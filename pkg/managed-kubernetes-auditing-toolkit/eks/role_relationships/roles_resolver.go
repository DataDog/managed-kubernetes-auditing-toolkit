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
	Arn             string
	Name            string
	TrustPolicy     string
	EffectivePolicy *iam_evaluation.Policy
	IsPrivileged    bool
}

type EKSCluster struct {
	AwsClient *aws.Config
	IamClient *iam.Client
	K8sClient *kubernetes.Clientset

	Name                       string
	AccountID                  string
	IssuerURL                  string
	ServiceAccountsByNamespace map[string][]*K8sServiceAccount
	PodsByNamespace            map[string][]*K8sPod
}

func (m *EKSCluster) AnalyzeRoleRelationships() error {
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

	roles, err := m.getIAMRoles()
	log.Printf("Analyzing the trust policy of %d IAM roles", len(roles))
	if err != nil {
		return err
	}

	// Roles that have at least one pod that can assume them
	// We'll only analyze the privileges of these roles
	rolesToAnalyze := []*IAMRole{}
	roleArnsToAnalyze := map[string]bool{}

	for i, role := range roles {
		// Parse the role trust policy
		trustPolicy, err := iam_evaluation.ParsePolicyDocument(role.TrustPolicy)
		if err != nil {
			log.Println("[WARNING] Could not parse the trust policy of " + role.Arn + ", ignoring. Error: " + err.Error())
			continue
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
					serviceAccount.AssumableRoles = append(serviceAccount.AssumableRoles, role)

					// This role can be assumed by at least one service account
					// Make sure we analyze its privileges later on
					if _, ok := roleArnsToAnalyze[role.Arn]; !ok {
						rolesToAnalyze = append(rolesToAnalyze, &roles[i])
						roleArnsToAnalyze[role.Arn] = true
					}
				}
			}
		}
	}

	// Analyze the privileges of identified roles
	for _, role := range rolesToAnalyze {
		role.EffectivePolicy, err = m.getRoleEffectivePolicy(role.Name)
		if err != nil {
			log.Printf("[WARNING] Unable to analyze privileges of role %s - will skip it. Error: %v", role.Arn, err)
		}
		role.IsPrivileged = m.isRolePrivileged(role)
		if role.IsPrivileged {
			log.Println("WOW! Role " + role.Arn + " is privileged")
		}
	}

	return nil
}

func (m *EKSCluster) getIAMRoles() ([]IAMRole, error) {
	log.Println("Listing roles in the AWS account")
	m.IamClient = iam.NewFromConfig(*m.AwsClient, func(options *iam.Options) {
		options.Region = "us-east-1"
	})
	paginator := iam.NewListRolesPaginator(m.IamClient, &iam.ListRolesInput{})
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
				Name:        *role.RoleName,
				TrustPolicy: trustPolicy,
			}
			assumableRoles = append(assumableRoles, role)
		}
	}
	return assumableRoles, nil
}

func (m *EKSCluster) getRoleEffectivePolicy(roleName string) (*iam_evaluation.Policy, error) {
	resultingPolicy := iam_evaluation.NewPolicy()
	effectiveInlinePolicy, err := m.getRoleEffectiveInlinePolicy(roleName)
	if err != nil {
		return nil, err
	}

	effectiveAttachedPolicy, err := m.getRoleEffectiveAttachedPolicy(roleName)
	if err != nil {
		return nil, err
	}

	resultingPolicy = resultingPolicy.Merge(effectiveInlinePolicy)
	resultingPolicy = resultingPolicy.Merge(effectiveAttachedPolicy)

	log.Printf("For role %s, found %d statements in the effective policy", roleName, len(resultingPolicy.Statements))
	return resultingPolicy, nil
}

func (m *EKSCluster) getRoleEffectiveInlinePolicy(roleName string) (*iam_evaluation.Policy, error) {
	paginator := iam.NewListRolePoliciesPaginator(m.IamClient, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})

	resultingPolicy := iam_evaluation.NewPolicy()

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to list role policies: %v", err)
		}
		for i := range result.PolicyNames {
			policyName := result.PolicyNames[i]
			policyResult, err := m.IamClient.GetRolePolicy(context.Background(), &iam.GetRolePolicyInput{
				PolicyName: &policyName,
				RoleName:   &roleName,
			})
			if err != nil {
				return nil, fmt.Errorf("unable to get role inline policy %s: %v", policyName, err)
			}

			policyJson, err := url.PathUnescape(*policyResult.PolicyDocument)
			if err != nil {
				return nil, fmt.Errorf("unable to decode IAM policy of role inline policy %s: %v", policyName, err)
			}

			policy, err := iam_evaluation.ParsePolicyDocument(policyJson)
			if err != nil {
				return nil, fmt.Errorf("unable to parse role inline policy %s: %v", policyName, err)
			}
			resultingPolicy = resultingPolicy.Merge(policy)
		}
	}

	return resultingPolicy, nil
}

func (m *EKSCluster) getRoleEffectiveAttachedPolicy(roleName string) (*iam_evaluation.Policy, error) {
	paginator := iam.NewListAttachedRolePoliciesPaginator(m.IamClient, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	resultingPolicy := iam_evaluation.NewPolicy()

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("unable to list role policies: %v", err)
		}
		for i := range result.AttachedPolicies {
			policyAttachment := result.AttachedPolicies[i]
			policyDocument, err := m.getIamPolicyDocument(*policyAttachment.PolicyArn)
			policy, err := iam_evaluation.ParsePolicyDocument(policyDocument)
			if err != nil {
				return nil, fmt.Errorf("unable to parse role attached policy %s: %v", *policyAttachment.PolicyName, err)
			}
			resultingPolicy = resultingPolicy.Merge(policy)
		}
	}

	return resultingPolicy, nil
}

func (m *EKSCluster) getIamPolicyDocument(policyArn string) (string, error) {
	// Need to list policy versions first, then only get the latest version..
	policyVersionResult, err := m.IamClient.GetPolicy(context.Background(), &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return "", fmt.Errorf("unable to list versions of role attached policy %s: %v", policyArn, err)
	}

	latestVersion := policyVersionResult.Policy.DefaultVersionId
	policyResult, err := m.IamClient.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: latestVersion,
	})
	if err != nil {
		return "", fmt.Errorf("unable to get role attached policy %s: %v", policyArn, err)
	}

	policyJson, err := url.PathUnescape(*policyResult.PolicyVersion.Document)
	if err != nil {
		return "", fmt.Errorf("unable to decode IAM policy of role attached policy %s: %v", policyArn, err)
	}

	return policyJson, nil
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

func (m *EKSCluster) isRolePrivileged(role *IAMRole) bool {
	if role.EffectivePolicy == nil || len(role.EffectivePolicy.Statements) == 0 {
		return false
	}
	if *role.EffectivePolicy.Authorize(&iam_evaluation.AuthorizationContext{Action: "icannot:exist", Resource: "me:neither"}) == iam_evaluation.AuthorizationResultAllow {
		return true
	}
	privilegedActions := [][]string{
		{"secretsmanager:listsecrets", "secretsmanager:getsecretvalue"},
	}
	for _, actions := range privilegedActions {
		allMatch := true
		for _, action := range actions {
			if *role.EffectivePolicy.Authorize(&iam_evaluation.AuthorizationContext{Action: action, Resource: "nope"}) == iam_evaluation.AuthorizationResultDeny {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}

	return false
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
