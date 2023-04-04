package eks

type EKSCluster struct {
	Name                       string
	AccountID                  string
	IssuerURL                  string
	ServiceAccountsByNamespace map[string][]K8sServiceAccount
	PodsByNamespace            map[string][]K8sPod
	AssumableRoles             []IAMRole
}

type K8sServiceAccount struct {
	Name           string
	Namespace      string
	Annotations    map[string]string
	AssumableRoles []IAMRole
}

type K8sPod struct {
	Name           string
	Namespace      string
	ServiceAccount *K8sServiceAccount
}

type IAMRole struct {
	Arn          string
	TrustPolicy  string
	IsPrivileged bool
}
