package role_relationships

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/aws/iam_evaluation"
	"github.com/hashicorp/go-version"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/url"
	"strconv"
	"strings"
)

type AssumeIAMRoleReason string

const (
	AssumeIAMRoleReasonIRSA        = "IAM Roles for Service Accounts"
	AssumeIAMRoleReasonPodIdentity = "Pod Identity"
)

// https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html#pod-id-cluster-versions
const PodIdentityMinSupportedK8sVersion = "1.24"

// AssumableIAMRole records that an IAM role can be assumed through a specific mechanism
type AssumableIAMRole struct {
	IAMRole *IAMRole
	Reason  AssumeIAMRoleReason
}

type K8sServiceAccount struct {
	Name           string
	Namespace      string
	Annotations    map[string]string
	AssumableRoles []*AssumableIAMRole
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

type PodIdentityAssociation struct {
	ID                 string
	Namespace          string
	ServiceAccountName string
	RoleArn            string
}

type EKSCluster struct {
	AwsClient *aws.Config
	K8sClient *kubernetes.Clientset

	Name                       string
	KubernetesVersion          string // e.g. "1.24"
	AccountID                  string
	IssuerURL                  string
	ServiceAccountsByNamespace map[string][]*K8sServiceAccount
	PodsByNamespace            map[string][]*K8sPod
	IAMRoles                   []*IAMRole
}

func (m *EKSCluster) AnalyzeRoleRelationships() error {
	// Start by retrieving the cluster information
	if err := m.retrieveClusterInformation(); err != nil {
		return fmt.Errorf("unable to retrieve EKS cluster information: %v", err)
	}

	// Retrieve all service accounts
	serviceAccountsByNamespace, err := m.retrieveServiceAccountsByNamespace()
	if err != nil {
		return fmt.Errorf("unable to retrieve service accounts: %v", err)
	}
	m.ServiceAccountsByNamespace = serviceAccountsByNamespace

	// Then, find all pods and link them with the service accounts
	podsByNamespace, err := m.getPodsByNamespace()
	if err != nil {
		return fmt.Errorf("unable to retrieve pods: %v", err)
	}
	m.PodsByNamespace = podsByNamespace

	// Then, retrieve all IAM roles in the account
	iamRoles, err := m.retrieveIAMRoles()
	log.Printf("Found %d IAM roles in the AWS account", len(iamRoles))
	if err != nil {
		return fmt.Errorf("unable to list IAM roles: %v", err)
	}
	m.IAMRoles = iamRoles

	// Finally, launch the analysis for both IRSA and Pod Identity
	if err := m.AnalyzeRoleRelationshipsForIRSA(); err != nil {
		return fmt.Errorf("unable to analyze IRSA configuration in your cluster and account: %v", err)
	}

	if err := m.AnalyzeRoleRelationshipsForPodIdentity(); err != nil {
		return fmt.Errorf("unable to analyze Pod Identity configuration in your cluster and account: %v", err)
	}

	return nil
}

func (m *EKSCluster) AnalyzeRoleRelationshipsForPodIdentity() error {
	log.Println("Analyzing Pod Identity configuration of your cluster")
	eksClient := eks.NewFromConfig(*m.AwsClient)

	if !m.supportsPodIdentity() {
		log.Println("Your cluster runs a Kubernetes version that does not support Pod Identity - skipping")
		log.Println("Your K8s version is " + m.KubernetesVersion + ", and Pod Identity is supported starting from " + PodIdentityMinSupportedK8sVersion)
		return nil
	}

	// Step 1: Retrieve all pod associations in the cluster, and keep a map by podAssociationNamespace
	paginator := eks.NewListPodIdentityAssociationsPaginator(eksClient, &eks.ListPodIdentityAssociationsInput{
		ClusterName: &m.Name,
	})
	namespaceToPodIdentityAssociations := map[string][]*PodIdentityAssociation{}
	for paginator.HasMorePages() {
		podIdentityAssociations, err := paginator.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("unable to retrieve pod identity associations: %v", err)
		}
		for _, podIdentityAssociation := range podIdentityAssociations.Associations {
			namespace := *podIdentityAssociation.Namespace
			if _, ok := namespaceToPodIdentityAssociations[namespace]; !ok {
				namespaceToPodIdentityAssociations[namespace] = []*PodIdentityAssociation{}
			}

			//TODO: This is duplicate because AWS across calls update this value... we need to define our own type
			association := podIdentityAssociation
			namespaceToPodIdentityAssociations[namespace] = append(namespaceToPodIdentityAssociations[namespace], &PodIdentityAssociation{
				ID:                 *association.AssociationId,
				Namespace:          *association.Namespace,
				ServiceAccountName: *association.ServiceAccount,
				RoleArn:            "", // No role ARN yet at this point, as we need a call to DescribePodIdentityAssociation
			})
		}
	}

	// Step 2: Map assumable roles to pods
	for podAssociationNamespace := range namespaceToPodIdentityAssociations {
		log.Println("Analyzing namespace " + podAssociationNamespace + " which has " + strconv.Itoa(len(namespaceToPodIdentityAssociations[podAssociationNamespace])) + " Pod Identity associations")
		for _, podAssociation := range namespaceToPodIdentityAssociations[podAssociationNamespace] {

			// Retrieve the role attached to the pod identity association
			podAssociationDetails, err := eksClient.DescribePodIdentityAssociation(context.Background(), &eks.DescribePodIdentityAssociationInput{
				AssociationId: &podAssociation.ID,
				ClusterName:   &m.Name,
			})
			if err != nil {
				return fmt.Errorf("unable to describe pod identity association %s: %v", podAssociation.ID, err)
			}
			assumableIamRole := AssumableIAMRole{
				IAMRole: &IAMRole{Arn: *podAssociationDetails.Association.RoleArn},
				Reason:  AssumeIAMRoleReasonPodIdentity,
			}

			pods, ok := m.PodsByNamespace[podAssociationNamespace]
			if !ok {
				// no pods in podAssociationNamespace, go to the next one
				continue
			}
			// All pods in this podAssociationNamespace with this service account can assume the role
			for i, _ := range pods {
				if pods[i].ServiceAccount.Name == podAssociation.ServiceAccountName {
					pods[i].ServiceAccount.AssumableRoles = append(pods[i].ServiceAccount.AssumableRoles, &assumableIamRole)
				}
			}
		}
	}

	return nil
}

func (m *EKSCluster) AnalyzeRoleRelationshipsForIRSA() error {
	log.Println("Analyzing IAM Roles For Service Accounts (IRSA) configuration")
	if m.IssuerURL == "" {
		log.Println("Your cluster has no OIDC provider, skipping IRSA analysis")
		return nil
	}

	for _, role := range m.IAMRoles {
		// Parse the role trust policy
		trustPolicy, err := iam_evaluation.ParseRoleTrustPolicy(role.TrustPolicy)
		if err != nil {
			log.Println("[WARNING] Could not parse the trust policy of " + role.Arn + ", ignoring. Error: " + err.Error())
			continue
		}

		assumableIamRole := AssumableIAMRole{
			IAMRole: &IAMRole{Arn: role.Arn},
			Reason:  AssumeIAMRoleReasonIRSA,
		}

		// Iterate over all service accounts in the cluster and figure out which ones can assume the role
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

				if *trustPolicy.Authorize(&authzContext) == iam_evaluation.AuthorizationResultAllow {
					serviceAccount.AssumableRoles = append(serviceAccount.AssumableRoles, &assumableIamRole)
				}
			}
		}
	}

	return nil
}

func (m *EKSCluster) retrieveClusterInformation() error {
	log.Println("Retrieving cluster information")
	clusterInfo, err := eks.NewFromConfig(*m.AwsClient).DescribeCluster(context.Background(), &eks.DescribeClusterInput{
		Name: &m.Name,
	})
	if err != nil {
		return fmt.Errorf("unable to retrieve cluster OIDC issuer: %v", err)
	}
	if clusterInfo.Cluster.Identity == nil || clusterInfo.Cluster.Identity.Oidc == nil {
		// The cluster has no OIDC provider
		m.IssuerURL = ""
		return nil
	}

	parsedClusterArn, _ := arn.Parse(*clusterInfo.Cluster.Arn)
	m.AccountID = parsedClusterArn.AccountID
	m.IssuerURL = strings.Replace(*clusterInfo.Cluster.Identity.Oidc.Issuer, "https://", "", 1)
	m.KubernetesVersion = *clusterInfo.Cluster.Version
	return nil
}

func (m *EKSCluster) retrieveIAMRoles() ([]*IAMRole, error) {
	log.Println("Listing roles in the AWS account")
	paginator := iam.NewListRolesPaginator(iam.NewFromConfig(*m.AwsClient, func(options *iam.Options) {
		options.Region = "us-east-1"
	}), &iam.ListRolesInput{})
	allIAMRoles := []*IAMRole{}
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
			allIAMRoles = append(allIAMRoles, &role)
		}
	}
	return allIAMRoles, nil
}

func (m *EKSCluster) retrieveServiceAccountsByNamespace() (map[string][]*K8sServiceAccount, error) {
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
			AssumableRoles: []*AssumableIAMRole{},
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

func (m *EKSCluster) supportsPodIdentity() bool {
	currentVersion, err := version.NewVersion(m.KubernetesVersion)
	minimumVersion, err2 := version.NewVersion(PodIdentityMinSupportedK8sVersion)
	if err != nil || err2 != nil {
		log.Println("WARNING: Unable to parse cluster K8s version, assuming it's >= 1.24 and supports Pod Identity")
		log.Println("Error: " + err.Error() + " " + err2.Error())
		return true
	}

	return currentVersion.GreaterThanOrEqual(minimumVersion)
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
