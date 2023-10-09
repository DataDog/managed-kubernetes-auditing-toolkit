package iam_evaluation

type AuthorizationDecision string

const (
	AuthorizationDecisionAllow AuthorizationDecision = "ALLOW"
	AuthorizationDecisionDeny  AuthorizationDecision = "DENY"
)

type AuthorizationContext struct {
	Action      string
	Principal   *Principal
	Resource    string
	ContextKeys map[string]string
}

type AuthorizationResult struct {
	Decision AuthorizationDecision
}

var (
	AuthorizationResultDeny       = AuthorizationResult{Decision: AuthorizationDecisionDeny}
	AuthorizationResultAllow      = AuthorizationResult{Decision: AuthorizationDecisionAllow}
	AuthorizationResultNoDecision = AuthorizationResult{Decision: ""}
)
