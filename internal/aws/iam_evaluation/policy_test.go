package iam_evaluation

import "testing"

func allowPolicyStatementThatNeverMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionAllow,
		AllowedPrincipals: []*Principal{},
		AllowedActions:    []string{},
		Conditions:        []*Condition{},
	}
}

func allowPolicyStatementThatAlwaysMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionAllow,
		AllowedPrincipals: []*Principal{{Type: PrincipalTypeUnknown, ID: "*"}},
		AllowedActions:    []string{"*"},
		Conditions:        []*Condition{},
	}
}

func explicitDenyThatAlwaysMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionDeny,
		AllowedPrincipals: []*Principal{{Type: PrincipalTypeUnknown, ID: "*"}},
		AllowedActions:    []string{"*"},
		Conditions:        []*Condition{},
	}
}

func TestPolicyEvaluationResourceBased(t *testing.T) {
	scenarios := []struct {
		Name   string
		Policy Policy
		Expect AuthorizationResult
	}{
		{
			Name:   "a policy with no statement should deny",
			Policy: Policy{Statements: []*PolicyStatement{}},
			Expect: AuthorizationResultDeny,
		},
		{
			Name:   "a policy with no matching statement should deny",
			Policy: Policy{Statements: []*PolicyStatement{allowPolicyStatementThatNeverMatches(), allowPolicyStatementThatNeverMatches()}},
			Expect: AuthorizationResultDeny,
		},
		{
			Name:   "a policy with 1 matching statement should allow",
			Policy: Policy{Statements: []*PolicyStatement{allowPolicyStatementThatAlwaysMatches()}},
			Expect: AuthorizationResultAllow,
		},
		{
			Name:   "a policy with 1 matching statement and 1 non matching statement should allow",
			Policy: Policy{Statements: []*PolicyStatement{allowPolicyStatementThatAlwaysMatches(), allowPolicyStatementThatNeverMatches()}},
			Expect: AuthorizationResultAllow,
		},
		{
			Name:   "a policy with 1 explicit deny statement should deny",
			Policy: Policy{Statements: []*PolicyStatement{explicitDenyThatAlwaysMatches()}},
			Expect: AuthorizationResultDeny,
		},
		{
			Name:   "a policy with 1 matching allow statement and 1 explicit deny matching statement should deny",
			Policy: Policy{Statements: []*PolicyStatement{allowPolicyStatementThatAlwaysMatches(), explicitDenyThatAlwaysMatches()}},
			Expect: AuthorizationResultDeny,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := *scenario.Policy.Authorize(&AuthorizationContext{Principal: &Principal{PrincipalTypeUnknown, "foo"}})
			if result != scenario.Expect {
				t.Errorf("Expected %v, got %v", scenario.Expect, result)
			}
		})
	}
}

func TestPolicyEvaluationIdentityBased(t *testing.T) {

	scenarios := []struct {
		Name                 string
		Policy               Policy
		AuthorizationContext AuthorizationContext
		Expect               AuthorizationResult
	}{
		{
			Name:                 "simple policy",
			Policy:               Policy{Statements: []*PolicyStatement{{Effect: AuthorizationDecisionAllow, AllowedActions: []string{"s3:ListObjects"}, AllowedResources: []string{"my-resource"}}}},
			AuthorizationContext: AuthorizationContext{Action: "s3:ListObjects", Resource: "my-resource"},
			Expect:               AuthorizationResultAllow,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := *scenario.Policy.Authorize(&scenario.AuthorizationContext)
			if result != scenario.Expect {
				t.Errorf("Expected %v, got %v", scenario.Expect, result)
			}
		})
	}
}

func TestPolicyMerge(t *testing.T) {
	policy1 := NewPolicy()
	policy1.Statements = []*PolicyStatement{allowPolicyStatementThatAlwaysMatches(), allowPolicyStatementThatNeverMatches()}

	policy2 := NewPolicy()
	policy2.Statements = []*PolicyStatement{allowPolicyStatementThatNeverMatches()}

	policy3 := policy1.Merge(policy2)
	if len(policy3.Statements) != 3 {
		t.Errorf("Expected 3 statements, got %d", len(policy3.Statements))
	}
}
