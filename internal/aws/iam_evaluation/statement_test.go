package iam_evaluation

import (
	"testing"
)

func TestPolicyStatement_Authorize(t *testing.T) {

	tests := []struct {
		Name      string
		Statement PolicyStatement
		Context   AuthorizationContext
		Expect    AuthorizationResult
	}{
		{
			Name: "Simple statement matching should allow",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
			},
			Context: AuthorizationContext{
				Action:      "ec2:CreateInstance",
				Principal:   &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "Simple statement not matching should not allow",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
			},
			Context: AuthorizationContext{
				Action:      "ec2:SomethingElse",
				Principal:   &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{},
			},
			Expect: AuthorizationResultNoDecision,
		},
		{
			Name: "Simple statement not matching principal should not allow",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAWS, ID: "foobar"}},
			},
			Context: AuthorizationContext{
				Action:      "ec2:CreateInstance",
				Principal:   &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{},
			},
			Expect: AuthorizationResultNoDecision,
		},
		{
			Name: "Explicit deny statement matching should deny",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionDeny,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
			},
			Context: AuthorizationContext{
				Action:      "ec2:CreateInstance",
				Principal:   &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{},
			},
			Expect: AuthorizationResultDeny,
		},
		{
			Name: "Explicit deny statement not matching should not deny",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionDeny,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
			},
			Context: AuthorizationContext{
				Action:      "ec2:SomethingElse",
				Principal:   &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{},
			},
			Expect: AuthorizationResultNoDecision,
		},
		{
			Name: "Statement with simple condition should allow",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:MyKey", Operator: "StringEquals", AllowedValues: []string{"foo"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:MyKey": "foo",
				},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "Statement with condition should allow - allowed values should be OR'ed together",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:MyKey", Operator: "StringEquals", AllowedValues: []string{"foo", "bar"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:MyKey": "bar",
				},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "Statement with multiple conditions should allow - individual conditions should be AND'ed together",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:MyKey", Operator: "StringEquals", AllowedValues: []string{"foo"}},
					{Key: "aws:MyOtherKey", Operator: "StringEquals", AllowedValues: []string{"bar"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:MyKey":      "foo",
					"aws:MyOtherKey": "bar",
				},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "Statement with multiple conditions should allow - individual conditions should be AND'ed together and each value within OR'ed",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:MyKey", Operator: "StringEquals", AllowedValues: []string{"foo", "fooz"}},
					{Key: "aws:MyOtherKey", Operator: "StringEquals", AllowedValues: []string{"bar", "baz"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:MyKey":      "fooz",
					"aws:MyOtherKey": "bar",
				},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "StringLike condition",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:InstanceType", Operator: "StringLike", AllowedValues: []string{"t2.*"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:InstanceType": "t2.medium",
				},
			},
			Expect: AuthorizationResultAllow,
		},
		{
			Name: "StringLike condition negative case",
			Statement: PolicyStatement{
				Effect:            AuthorizationDecisionAllow,
				AllowedActions:    []string{"ec2:CreateInstance"},
				AllowedPrincipals: []*Principal{{Type: PrincipalTypeAny}},
				Conditions: []*Condition{
					{Key: "aws:InstanceType", Operator: "StringLike", AllowedValues: []string{"t2.*"}},
				},
			},
			Context: AuthorizationContext{
				Action:    "ec2:CreateInstance",
				Principal: &Principal{Type: PrincipalTypeAWS, ID: "foo"},
				ContextKeys: map[string]string{
					"aws:InstanceType": "m3.2xlarge",
				},
			},
			Expect: AuthorizationResultNoDecision,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result := *tt.Statement.Authorize(&tt.Context)
			if result != tt.Expect {
				t.Errorf("Expected %v, got %v", tt.Expect, result)
			}
		})
	}
}
