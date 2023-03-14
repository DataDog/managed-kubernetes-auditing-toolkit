package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	mapset "github.com/deckarep/golang-set/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/url"
	"strings"
)

func getClusterIssuer(awsClient *aws.Config, targetCluster string) string {
	println("Retrieving cluster OIDC issuer")
	eksClient := eks.NewFromConfig(*awsClient)
	clusterInfo, _ := eksClient.DescribeCluster(context.Background(), &eks.DescribeClusterInput{
		Name: &targetCluster,
	})
	//TODO: what if no identity?
	issuer := strings.Replace(*clusterInfo.Cluster.Identity.Oidc.Issuer, "https://", "", 1)
	return issuer
}

func findRoles(awsClient *aws.Config, issuer string) []types.Role {
	println("Listing roles in the AWS account")
	iamClient := iam.NewFromConfig(*awsClient)
	paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	identity, _ := sts.NewFromConfig(*awsClient).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	assumableRoles := make([]types.Role, 0)
	for paginator.HasMorePages() {
		roles, _ := paginator.NextPage(context.Background())
		for _, role := range roles.Roles {
			if roleTrustsIssuer(role, *identity.Account, issuer) {
				assumableRoles = append(assumableRoles, role)
			}
		}
	}

	return assumableRoles
}

func roleTrustsIssuer(role types.Role, accountId string, issuer string) bool {
	var policy map[string]interface{}

	// url decode role.AssumeRolePolicyDocument
	rawPolicy, _ := url.PathUnescape(*role.AssumeRolePolicyDocument)
	err := json.Unmarshal([]byte(rawPolicy), &policy)
	if err != nil {
		panic(err)
	}
	for _, rawStatement := range policy["Statement"].([]interface{}) {
		statement := rawStatement.(map[string]interface{})
		if statement["Effect"] != "Allow" {
			continue
		}
		// TODO: smart eval instead of string compare
		if statement["Principal"].(map[string]interface{})["Federated"] == "arn:aws:iam::"+accountId+":oidc-provider/"+issuer {
			// at this point we don't evaluate the conditions
			return true
		}
	}
	return false
}

func main() {
	k8s := K8sClient()
	aws := AWSClient()
	//targetCluster := "datadog-pde-test-eks-cluster-us-east-1"
	targetCluster := "synthetics-eks"
	issuer := getClusterIssuer(aws, targetCluster)

	// All roles in AWS that at least one service account in the cluster is using
	clusterCandidateRolesArns := mapset.NewSet[string]()

	// All roles in AWS that have a trust relationship with the cluster's OIDC issuer
	candidateRoles := findRoles(aws, issuer)
	candidateRoleArns := mapset.NewSet[string]()
	candidatesRolesByARN := make(map[string]types.Role)
	for _, candidateRole := range candidateRoles {
		candidatesRolesByARN[*candidateRole.Arn] = candidateRole
		candidateRoleArns.Add(*candidateRole.Arn)
	}
	println("Found", candidateRoleArns.Cardinality(), "roles that can be assumed by the cluster's OIDC provider")

	// List service accounts in all namespaces
	println("Listing K8s service accounts")
	serviceAccounts, _ := k8s.CoreV1().ServiceAccounts("").List(context.Background(), metav1.ListOptions{})
	serviceAccountsWithRoleConfiguration := make([]v1.ServiceAccount, 0)
	for _, serviceAccount := range serviceAccounts.Items {
		if annotations := serviceAccount.Annotations; annotations != nil {
			if roleArn, ok := annotations["eks.amazonaws.com/role-arn"]; ok {
				serviceAccountsWithRoleConfiguration = append(serviceAccountsWithRoleConfiguration, serviceAccount)
				clusterCandidateRolesArns.Add(roleArn)
			}
		}
	}

	// Find roles that are in both sets
	// These are our roles (1) that can be assumed by the cluster and (2) at least one SA is using
	commonRoles := clusterCandidateRolesArns.Intersect(candidateRoleArns).ToSlice()

	// Now for each role, we look at its 'Condition' in the trust policy and determine which service accounts can use it
	//assumableRolesByServiceAccount := make(map[string][]string)
	for _, roleArn := range commonRoles {
		for _, serviceAccount := range serviceAccountsWithRoleConfiguration {
			if serviceAccountCanAssumeRole(serviceAccount, candidatesRolesByARN[roleArn], issuer) {
				//assumableRolesByServiceAccount[serviceAccount.Namespace+"/"+serviceAccount.Name] = append(assumableRolesByServiceAccount[serviceAccount.Namespace+"/"+serviceAccount.Name], roleArn)
				println(roleArn + " can be assumed by " + serviceAccount.Namespace + "/" + serviceAccount.Name)
			}
		}
	}
}

func serviceAccountCanAssumeRole(serviceAccount v1.ServiceAccount, role types.Role, issuer string) bool {
	//println("Checking if service account " + serviceAccount.Namespace + "/" + serviceAccount.Name + " can assume role " + *role.Arn)
	var policy map[string]interface{}

	// url decode role.AssumeRolePolicyDocument
	rawPolicy, _ := url.PathUnescape(*role.AssumeRolePolicyDocument)
	err := json.Unmarshal([]byte(rawPolicy), &policy)
	if err != nil {
		panic(err)
	}

	for _, rawStatement := range policy["Statement"].([]interface{}) {
		statement := rawStatement.(map[string]interface{})
		if statement["Effect"] != "Allow" {
			continue
		}

		rawCondition, hasCondition := statement["Condition"]
		if !hasCondition {
			return true
		}

		condition := rawCondition.(map[string]interface{})
		if stringEquals, ok := condition["StringEquals"]; ok {
			if stringEquals.(map[string]interface{})[issuer+":sub"] == "system:serviceaccount:"+serviceAccount.Namespace+":"+serviceAccount.Name {
				return true
			}
		}
	}
	return false
}
