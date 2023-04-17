package role_relationships

import (
	"testing"

	"github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks"
)

func TestRoleCanBeAssumedByServiceAccount(t *testing.T) {
	// List of scenarios to test roleCanBeAssumedByServiceAccount
	scenarios := []struct {
		Name              string
		IAMRole           eks.IAMRole
		K8sServiceAccount eks.K8sServiceAccount
		IssuerURL         string
		ExpectedResult    bool
	}{
		{
			Name: "A role cannot be assumed if its trust policy doesn't specify the OIDC issuer of the cluster",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\",\"oidc.eks.us-east-1.amazonaws.com/id/4567:sub\": \"system:serviceaccount:my-ns:my-sa\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:        "my-sa",
				Namespace:   "my-ns",
				Annotations: map[string]string{},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: false,
		},
		{
			Name: "A role with the proper trust policy cannot be assumed if it doesn't specify the AssumeRoleWithWebIdentity action",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRole\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\",\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"system:serviceaccount:my-ns:my-sa\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "my-ns",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: false,
		},
		{
			Name: "A properly configured role can be assumed by a properly configured service account",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\",\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"system:serviceaccount:my-ns:my-sa\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "my-ns",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: true,
		},
		{
			Name: "A properly configured role can be assumed by a properly configured service account when multiple conditions are specified",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\",\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": [\"system:serviceaccount:my-ns:my-sa\", \"system:serviceaccount:my-ns:my-sa2\"]}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "my-ns",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: true,
		},
		{
			Name: "A properly configured role can be assumed by a properly configured service account, even when using a wildcard in the pod name",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\"}, \"StringLike\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"system:serviceaccount:my-ns:*\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "my-ns",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: true,
		},
		{
			Name: "A properly configured role cannot be assumed by a properly configured service account when the wildcard is incorrectly in a StringEquals condition",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\", \"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"system:serviceaccount:my-ns:*\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "my-ns",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: false,
		},
		{
			Name: "A properly configured role can be assumed by a properly configured service account, even when using a wildcard in the namespace",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\"}, \"StringLike\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"system:serviceaccount:*:my-sa\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "whatever",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: true,
		},
		{
			Name: "A properly configured role can be assumed by a properly configured service account, even when using a wildcard",
			IAMRole: eks.IAMRole{
				Arn:         "arn:aws:iam::012345678901:role/my-role",
				TrustPolicy: "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Principal\": {\"Federated\": \"arn:aws:iam::012345678901:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/1234\"},\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:aud\": \"sts.amazonaws.com\"}, \"StringLike\": {\"oidc.eks.us-east-1.amazonaws.com/id/1234:sub\": \"*\"}}}]}",
			},
			K8sServiceAccount: eks.K8sServiceAccount{
				Name:      "my-sa",
				Namespace: "whatever",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::012345678901:role/my-role",
				},
			},
			IssuerURL:      "https://oidc.eks.us-east-1.amazonaws.com/id/1234",
			ExpectedResult: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := roleCanBeAssumedByServiceAccount(scenario.IAMRole, &scenario.K8sServiceAccount, &eks.EKSCluster{IssuerURL: scenario.IssuerURL})
			if result != scenario.ExpectedResult {
				t.Errorf("Scenario '%s': expected result to be %v, got %v", scenario.Name, scenario.ExpectedResult, result)
			}
		})
	}
}
