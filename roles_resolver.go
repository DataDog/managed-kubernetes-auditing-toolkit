package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"net/url"
)

/*
	TODO:
* Currently, we only look at roles that can be assumed through a service account
* Instead, we should:
	1. Find pods that have a service account with the EKS label (_any role_)
	2. Then evaluate if this pod identity can assume each role


We should NOT restrict ourselves to the annotations on the service accounts, otherwise we're missing cases such as:
* Pod X uses role roleA
* RoleB allows ALL pods in a NS to assume it
*/

type EKSClusterRolesResolver struct {
	awsClient *aws.Config
	k8sClient *kubernetes.Clientset
}

func (m *EKSClusterRolesResolver) ResolveClusterRoles(clusterName string) (*EKSCluster, error) {
	println("Retrieving cluster OIDC issuer")
	clusterInfo, err := eks.NewFromConfig(*m.awsClient).DescribeCluster(context.Background(), &eks.DescribeClusterInput{
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
	cluster := &EKSCluster{
		Name:                       clusterName,
		AccountID:                  parsedClusterArn.AccountID,
		IssuerURL:                  *clusterInfo.Cluster.Identity.Oidc.Issuer,
		ServiceAccountsByNamespace: map[string][]K8sServiceAccount{},
		PodsByNamespace:            map[string][]K8sPod{},
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

func (m *EKSClusterRolesResolver) getRolesAssumableByCluster(cluster *EKSCluster) ([]IAMRole, error) {
	println("Listing roles in the AWS account")
	paginator := iam.NewListRolesPaginator(iam.NewFromConfig(*m.awsClient), &iam.ListRolesInput{})
	assumableRoles := []IAMRole{}
	for paginator.HasMorePages() {
		roles, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to list roles in the AWS account: %v", err)
		}
		for _, role := range roles.Roles {
			trustPolicy, err := url.PathUnescape(*role.AssumeRolePolicyDocument)
			role := IAMRole{
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

func (m *EKSClusterRolesResolver) getServiceAccountsByNamespace() (map[string][]K8sServiceAccount, error) {
	println("Listing K8s service accounts")
	serviceAccountsByNamespace := make(map[string][]K8sServiceAccount)
	serviceAccounts, err := m.k8sClient.CoreV1().ServiceAccounts("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s service accounts: %v", err)
	}
	for _, serviceAccount := range serviceAccounts.Items {
		namespace := serviceAccount.Namespace
		serviceAccountsByNamespace[namespace] = append(serviceAccountsByNamespace[namespace], K8sServiceAccount{
			Name:           serviceAccount.Name,
			Namespace:      serviceAccount.Namespace,
			Annotations:    serviceAccount.Annotations,
			AssumableRoles: []IAMRole{},
		})
	}
	return serviceAccountsByNamespace, nil
}

func (m *EKSClusterRolesResolver) getRolesAssumableByServiceAccount(cluster *EKSCluster, serviceAccount *K8sServiceAccount) ([]IAMRole, error) {
	const EKSAnnotation = "eks.amazonaws.com/role-arn"
	annotations := serviceAccount.Annotations

	if annotations == nil {
		// The service account has no annotations at all
		return []IAMRole{}, nil
	}
	roleArn, hasRoleAnnotation := annotations[EKSAnnotation]
	if !hasRoleAnnotation {
		// The service account has annotations, but not the EKS one
		return []IAMRole{}, nil
	}

	// TODO: O(1) lookup instead of iterating
	for _, candidateRole := range cluster.AssumableRoles {
		if candidateRole.Arn == roleArn && roleCanBeAssumedByServiceAccount(candidateRole, serviceAccount, cluster) {
			return []IAMRole{candidateRole}, nil
		}
	}

	return []IAMRole{}, nil
}

func (m *EKSClusterRolesResolver) resolvePodRoles() error {
	return nil
}

func (m *EKSClusterRolesResolver) getPodsByNamespace(cluster *EKSCluster) (map[string][]K8sPod, error) {
	pods, err := m.k8sClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s pods: %v", err)
	}
	podsByNamespace := make(map[string][]K8sPod)
	for _, pod := range pods.Items {
		namespace := pod.Namespace
		var serviceAccount *K8sServiceAccount = nil
		candidateServiceAccounts := cluster.ServiceAccountsByNamespace[namespace]
		for _, candidateServiceAccount := range candidateServiceAccounts {
			if candidateServiceAccount.Name == pod.Spec.ServiceAccountName {
				serviceAccount = &candidateServiceAccount
				break
			}
		}
		podsByNamespace[namespace] = append(podsByNamespace[namespace], K8sPod{
			Name:           pod.Name,
			Namespace:      namespace,
			ServiceAccount: serviceAccount,
		})
	}

	return podsByNamespace, nil
}

func roleTrustsIssuer(role IAMRole, accountId string, issuer string) bool {
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
