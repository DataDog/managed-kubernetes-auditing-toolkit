package role_relationships

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	eks2 "github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/url"
	"path/filepath"
	"strconv"
)

type EKSClusterRolesResolver struct {
	AwsClient *aws.Config
	K8sClient *kubernetes.Clientset
}

func (m *EKSClusterRolesResolver) ResolveClusterRoles(clusterName string) (*eks2.EKSCluster, error) {
	log.Println("Retrieving cluster OIDC issuer")
	clusterInfo, err := eks.NewFromConfig(*m.AwsClient).DescribeCluster(context.Background(), &eks.DescribeClusterInput{
		Name: &clusterName,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve cluster OIDC issuer: %v", err)
	}
	if clusterInfo.Cluster.Identity == nil || clusterInfo.Cluster.Identity.Oidc == nil {
		// The cluster has no OIDC provider, so there are no roles to resolve
		return nil, nil
	}
	parsedClusterArn, _ := arn.Parse(*clusterInfo.Cluster.Arn)
	cluster := &eks2.EKSCluster{
		Name:                       clusterName,
		AccountID:                  parsedClusterArn.AccountID,
		IssuerURL:                  *clusterInfo.Cluster.Identity.Oidc.Issuer,
		ServiceAccountsByNamespace: map[string][]eks2.K8sServiceAccount{},
		PodsByNamespace:            map[string][]eks2.K8sPod{},
	}

	// Find roles that the cluster can assume
	assumableRoles, err := m.getRolesAssumableByCluster(cluster)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve roles assumable by the cluster: %v", err)
	}
	cluster.AssumableRoles = assumableRoles

	// Find all service accounts
	serviceAccountsByNamespace, err := m.getServiceAccountsByNamespace()
	cluster.ServiceAccountsByNamespace = serviceAccountsByNamespace

	// Resolve service accounts assumable roles
	log.Println("Analyzing the trust policy of " + strconv.Itoa(len(assumableRoles)) + " IAM roles that have the cluster's OIDC provider in their trust policy")
	for _, serviceAccounts := range cluster.ServiceAccountsByNamespace {
		for i, serviceAccount := range serviceAccounts {
			// Find roles that the service account can assume
			assumableRoles, err := m.getRolesAssumableByServiceAccount(cluster, &serviceAccount)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve roles assumable by the service account %s: %v", serviceAccount.Name, err)
			}
			serviceAccounts[i].AssumableRoles = assumableRoles
		}
	}

	// Find all pods and link them with the service accounts
	podsByNamespace, err := m.getPodsByNamespace(cluster)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve pods: %v", err)
	}
	cluster.PodsByNamespace = podsByNamespace

	return cluster, nil
}

func (m *EKSClusterRolesResolver) getRolesAssumableByCluster(cluster *eks2.EKSCluster) ([]eks2.IAMRole, error) {
	log.Println("Listing roles in the AWS account")
	paginator := iam.NewListRolesPaginator(iam.NewFromConfig(*m.AwsClient), &iam.ListRolesInput{})
	assumableRoles := []eks2.IAMRole{}
	for paginator.HasMorePages() {
		roles, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to list roles in the AWS account: %v", err)
		}
		for _, role := range roles.Roles {
			trustPolicy, err := url.PathUnescape(*role.AssumeRolePolicyDocument)
			role := eks2.IAMRole{
				Arn:         *role.Arn,
				TrustPolicy: trustPolicy,
			}
			if roleTrustsIssuer(role, cluster.AccountID, cluster.IssuerURL) {
				if err != nil {
					return nil, fmt.Errorf("unable to decode trust policy of role %s: %v", role.Arn, err)
				}
				assumableRoles = append(assumableRoles, role)
			}
		}
	}

	return assumableRoles, nil
}

func (m *EKSClusterRolesResolver) getServiceAccountsByNamespace() (map[string][]eks2.K8sServiceAccount, error) {
	log.Println("Listing K8s service accounts in all namespaces")
	serviceAccountsByNamespace := make(map[string][]eks2.K8sServiceAccount)
	serviceAccounts, err := m.K8sClient.CoreV1().ServiceAccounts("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s service accounts: %v", err)
	}
	for _, serviceAccount := range serviceAccounts.Items {
		namespace := serviceAccount.Namespace
		serviceAccountsByNamespace[namespace] = append(serviceAccountsByNamespace[namespace], eks2.K8sServiceAccount{
			Name:           serviceAccount.Name,
			Namespace:      serviceAccount.Namespace,
			Annotations:    serviceAccount.Annotations,
			AssumableRoles: []eks2.IAMRole{},
		})
	}
	return serviceAccountsByNamespace, nil
}

func (m *EKSClusterRolesResolver) getRolesAssumableByServiceAccount(cluster *eks2.EKSCluster, serviceAccount *eks2.K8sServiceAccount) ([]eks2.IAMRole, error) {
	// For now, we only consider service accounts with the EKS annotation
	// Technically, we might want to consider all service accounts, and consider that you could add the annotation manually to it
	// However, in general we focus on current, effective permissions only
	const EKSAnnotation = "eks.amazonaws.com/role-arn"
	annotations := serviceAccount.Annotations

	if annotations == nil {
		// The service account has no annotations at all
		return []eks2.IAMRole{}, nil
	}

	if _, hasRoleAnnotation := annotations[EKSAnnotation]; !hasRoleAnnotation {
		// The service account has some annotations, but not the EKS one
		return []eks2.IAMRole{}, nil
	}

	assumableRoles := []eks2.IAMRole{}
	// TODO: O(1) lookup instead of iterating
	for _, candidateRole := range cluster.AssumableRoles {
		// Note: We don't need to check 'candidateRole.Arn == roleArn'
		// If the EKS annotation is specified, it means a JWT is injected in the pod with the audience "sts.amazonaws.com"
		// From there, if the trust relationship on the role allows it, anyone with the JWT can assume the role regardless of the annotation value
		if roleCanBeAssumedByServiceAccount(candidateRole, serviceAccount, cluster) {
			assumableRoles = append(assumableRoles, candidateRole)
		}
	}

	return assumableRoles, nil
}

func (m *EKSClusterRolesResolver) resolvePodRoles() error {
	return nil
}

func (m *EKSClusterRolesResolver) getPodsByNamespace(cluster *eks2.EKSCluster) (map[string][]eks2.K8sPod, error) {
	pods, err := m.K8sClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s pods: %v", err)
	}
	podsByNamespace := make(map[string][]eks2.K8sPod)
	for _, pod := range pods.Items {
		namespace := pod.Namespace
		var serviceAccount *eks2.K8sServiceAccount = nil
		candidateServiceAccounts := cluster.ServiceAccountsByNamespace[namespace]
		for _, candidateServiceAccount := range candidateServiceAccounts {
			if candidateServiceAccount.Name == pod.Spec.ServiceAccountName {
				serviceAccount = &candidateServiceAccount
				break
			}
		}
		podsByNamespace[namespace] = append(podsByNamespace[namespace], eks2.K8sPod{
			Name:           pod.Name,
			Namespace:      namespace,
			ServiceAccount: serviceAccount,
		})
	}

	return podsByNamespace, nil
}

func roleTrustsIssuer(role eks2.IAMRole, accountId string, issuer string) bool {
	var policy map[string]interface{}

	// url decode role.AssumeRolePolicyDocument
	err := json.Unmarshal([]byte(role.TrustPolicy), &policy)
	if err != nil {
		panic(err)
	}
	for _, rawStatement := range policy["Statement"].([]interface{}) {
		statement := rawStatement.(map[string]interface{})
		if statement["Effect"] != "Allow" {
			continue
		}
		// TODO: smart eval instead of string compare
		issuerId := issuer[len("https://"):]
		if statement["Principal"].(map[string]interface{})["Federated"] == "arn:aws:iam::"+accountId+":oidc-provider/"+issuerId {
			// we don't evaluate the conditions on purpose
			return true
		}
	}
	return false
}

func roleCanBeAssumedByServiceAccount(role eks2.IAMRole, serviceAccount *eks2.K8sServiceAccount, cluster *eks2.EKSCluster) bool {
	var policy map[string]interface{}
	err := json.Unmarshal([]byte(role.TrustPolicy), &policy)
	if err != nil {
		panic(err)
	}

	issuerId := cluster.IssuerURL[len("https://"):]
	for _, rawStatement := range policy["Statement"].([]interface{}) {
		statement := rawStatement.(map[string]interface{})
		if statement["Effect"] != "Allow" || statement["Action"] != "sts:AssumeRoleWithWebIdentity" {
			continue
		}

		rawCondition, hasCondition := statement["Condition"]
		if !hasCondition {
			return true
		}

		condition := rawCondition.(map[string]interface{})

		// Case 1: StringLike
		if stringLike, ok := condition["StringLike"]; ok {
			subjectCondition := stringLike.(map[string]interface{})[issuerId+":sub"]
			if subjectCondition == nil {
				continue
			}
			effectiveSubject := "system:serviceaccount:" + serviceAccount.Namespace + ":" + serviceAccount.Name
			if match, err := filepath.Match(subjectCondition.(string), effectiveSubject); match && err == nil {
				return true
			}
		}

		// Case 2: StringEquals
		if stringEquals, ok := condition["StringEquals"]; ok {
			subjectCondition := stringEquals.(map[string]interface{})[issuerId+":sub"]
			if subjectCondition == nil {
				continue
			}
			effectiveSubject := "system:serviceaccount:" + serviceAccount.Namespace + ":" + serviceAccount.Name

			// The condition value can be a simple string, or a list of strings (which are then OR'ed together)
			if stringSubjectCondition, ok := subjectCondition.(string); ok && stringSubjectCondition == effectiveSubject {
				return true
			}
			if listSubjectCondition, ok := subjectCondition.([]interface{}); ok {
				for _, stringSubjectCondition := range listSubjectCondition {
					if stringSubjectCondition == effectiveSubject {
						return true
					}
				}
			}
		}
	}
	return false
}
