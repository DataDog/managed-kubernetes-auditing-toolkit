package iam_evaluation

import "testing"

func allowPolicyStatementThatNeverMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionAllow,
		AllowedPrincipals: []string{},
		AllowedActions:    []string{},
		Conditions:        []*Condition{},
	}
}

func allowPolicyStatementThatAlwaysMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionAllow,
		AllowedPrincipals: []string{"*"},
		AllowedActions:    []string{"*"},
		Conditions:        []*Condition{},
	}
}

func explicitDenyThatAlwaysMatches() *PolicyStatement {
	return &PolicyStatement{
		Effect:            AuthorizationDecisionDeny,
		AllowedPrincipals: []string{"*"},
		AllowedActions:    []string{"*"},
		Conditions:        []*Condition{},
	}
}

func TestPolicy(t *testing.T) {
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
			result := *scenario.Policy.Authorize(&AuthorizationContext{})
			if result != scenario.Expect {
				t.Errorf("Expected %v, got %v", scenario.Expect, result)
			}
		})
	}
}
