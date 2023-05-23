package role_relationships

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/aws/iam_evaluation"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/url"
	"strings"
)

type K8sServiceAccount struct {
	Name           string
	Namespace      string
	Annotations    map[string]string
	AssumableRoles []IAMRole
}

type K8sPod struct {
	Name                            string
	Namespace                       string
	ServiceAccount                  *K8sServiceAccount
	HasProjectedServiceAccountToken bool
}

type IAMRole struct {
	Arn          string
	TrustPolicy  string
	IsPrivileged bool
}

type EKSCluster struct {
	AwsClient *aws.Config
	K8sClient *kubernetes.Clientset

	Name                       string
	AccountID                  string
	IssuerURL                  string
	ServiceAccountsByNamespace map[string][]*K8sServiceAccount
	PodsByNamespace            map[string][]*K8sPod
}

func NewEKSClusterAnalyzer(clusterName string) *EKSCluster {
	return &EKSCluster{Name: clusterName}
}

func (m *EKSCluster) ResolveClusterRoles() error {
	log.Println("Retrieving cluster OIDC issuer")
	clusterInfo, err := eks.NewFromConfig(*m.AwsClient).DescribeCluster(context.Background(), &eks.DescribeClusterInput{
		Name: &m.Name,
	})
	if err != nil {
		return fmt.Errorf("unable to retrieve cluster OIDC issuer: %v", err)
	}
	if clusterInfo.Cluster.Identity == nil || clusterInfo.Cluster.Identity.Oidc == nil {
		// The cluster has no OIDC provider, so there are no roles to resolve
		return nil
	}
	parsedClusterArn, _ := arn.Parse(*clusterInfo.Cluster.Arn)
	m.AccountID = parsedClusterArn.AccountID
	m.IssuerURL = strings.Replace(*clusterInfo.Cluster.Identity.Oidc.Issuer, "https://", "", 1)

	// Find all service accounts
	serviceAccountsByNamespace, err := m.getServiceAccountsByNamespace()
	if err != nil {
		return fmt.Errorf("unable to retrieve service accounts: %v", err)
	}
	m.ServiceAccountsByNamespace = serviceAccountsByNamespace

	// Find all pods and link them with the service accounts
	podsByNamespace, err := m.getPodsByNamespace()
	if err != nil {
		return fmt.Errorf("unable to retrieve pods: %v", err)
	}
	m.PodsByNamespace = podsByNamespace

	// For every namespace and every pod, find the roles that a pod can assume
	roles, err := m.getIAMRoles()
	log.Printf("Analyzing the trust policy of %d IAM roles", len(roles))
	if err != nil {
		return err
	}
	for _, role := range roles {
		for namespace, serviceAccounts := range m.ServiceAccountsByNamespace {
			for _, serviceAccount := range serviceAccounts {
				authzContext := iam_evaluation.AuthorizationContext{
					Action: "sts:AssumeRoleWithWebIdentity",
					Principal: &iam_evaluation.Principal{
						Type: iam_evaluation.PrincipalTypeFederated,
						ID:   fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", m.AccountID, m.IssuerURL),
					},
					ContextKeys: map[string]string{
						fmt.Sprintf("%s:sub", m.IssuerURL): fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount.Name),
						fmt.Sprintf("%s:aud", m.IssuerURL): "sts.amazonaws.com",
					},
				}
				trustPolicy, err := iam_evaluation.ParseRoleTrustPolicy(role.TrustPolicy)
				if err != nil {
					return err // TODO: warning instead
				}
				if *trustPolicy.Authorize(&authzContext) == iam_evaluation.AuthorizationResultAllow {
					serviceAccount.AssumableRoles = append(serviceAccount.AssumableRoles, role)
				}
			}
		}
	}

	return nil
}

func (m *EKSCluster) getIAMRoles() ([]IAMRole, error) {
	log.Println("Listing roles in the AWS account")
	paginator := iam.NewListRolesPaginator(iam.NewFromConfig(*m.AwsClient, func(options *iam.Options) {
		options.Region = "us-east-1"
	}), &iam.ListRolesInput{})
	assumableRoles := []IAMRole{}
	for paginator.HasMorePages() {
		roles, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to list roles in the AWS account: %v", err)
		}
		for _, role := range roles.Roles {
			trustPolicy, err := url.PathUnescape(*role.AssumeRolePolicyDocument)
			if err != nil {
				return nil, err
			}
			role := IAMRole{
				Arn:         *role.Arn,
				TrustPolicy: trustPolicy,
			}
			assumableRoles = append(assumableRoles, role)
		}
	}
	return assumableRoles, nil
}

func (m *EKSCluster) getServiceAccountsByNamespace() (map[string][]*K8sServiceAccount, error) {
	log.Println("Listing K8s service accounts in all namespaces")
	serviceAccountsByNamespace := make(map[string][]*K8sServiceAccount)
	serviceAccounts, err := m.K8sClient.CoreV1().ServiceAccounts("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s service accounts: %v", err)
	}
	for _, serviceAccount := range serviceAccounts.Items {
		namespace := serviceAccount.Namespace
		serviceAccountsByNamespace[namespace] = append(serviceAccountsByNamespace[namespace], &K8sServiceAccount{
			Name:           serviceAccount.Name,
			Namespace:      serviceAccount.Namespace,
			Annotations:    serviceAccount.Annotations,
			AssumableRoles: []IAMRole{},
		})
	}
	return serviceAccountsByNamespace, nil
}

func (m *EKSCluster) getPodsByNamespace() (map[string][]*K8sPod, error) {
	pods, err := m.K8sClient.CoreV1().Pods("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list K8s pods: %v", err)
	}
	podsByNamespace := make(map[string][]*K8sPod)
	for _, pod := range pods.Items {
		namespace := pod.Namespace
		var serviceAccount *K8sServiceAccount = nil
		candidateServiceAccounts := m.ServiceAccountsByNamespace[namespace]
		for _, candidateServiceAccount := range candidateServiceAccounts {
			if candidateServiceAccount.Name == pod.Spec.ServiceAccountName {
				serviceAccount = candidateServiceAccount
				break
			}
		}
		podsByNamespace[namespace] = append(podsByNamespace[namespace], &K8sPod{
			Name:                            pod.Name,
			Namespace:                       namespace,
			ServiceAccount:                  serviceAccount,
			HasProjectedServiceAccountToken: hasProjectedServiceAccountToken(&pod),
		})
	}

	return podsByNamespace, nil
}

func hasProjectedServiceAccountToken(pod *corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		projectedVolume := volume.Projected
		if projectedVolume == nil || len(projectedVolume.Sources) == 0 {
			continue
		}
		for _, source := range projectedVolume.Sources {
			saSource := source.ServiceAccountToken
			if saSource == nil {
				continue
			}
			if saSource.Audience == "sts.amazonaws.com" {
				return true
			}
		}
	}
	return false
}
