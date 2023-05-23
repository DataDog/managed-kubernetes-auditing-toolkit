package iam_evaluation

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func getTestPolicyFile(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename), "test_policies", name+".json")
	// read file and return contents
	btes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(btes)
}

func TestPolicyParser(t *testing.T) {
	scenarios := []struct {
		Name       string
		PolicyFile string
		WantErr    bool
		WantPolicy Policy
	}{
		{
			PolicyFile: "allow_assume_by_ec2",
			WantPolicy: Policy{
				Statements: []*PolicyStatement{
					{
						Effect:         AuthorizationDecisionAllow,
						AllowedActions: []string{"sts:AssumeRole"},
						AllowedPrincipals: []*Principal{
							{Type: PrincipalTypeService, ID: "ec2.amazonaws.com"},
						},
						Conditions: []*Condition{},
					},
				},
			},
		},
		{
			PolicyFile: "allow_oidc_with_condition",
			WantPolicy: Policy{
				Statements: []*PolicyStatement{
					{
						Effect:         AuthorizationDecisionAllow,
						AllowedActions: []string{"sts:AssumeRoleWithWebIdentity"},
						AllowedPrincipals: []*Principal{
							{Type: PrincipalTypeFederated, ID: "arn:aws:iam::11112222333:oidc-provider/auth.example.com"},
						},
						Conditions: []*Condition{
							{Key: "auth.example.com:sub", Operator: "StringEquals", AllowedValues: []string{"Administrator"}},
							{Key: "auth.example.com:aud", Operator: "StringEquals", AllowedValues: []string{"MyappWebIdentity"}},
						},
					},
				},
			},
		},
		{
			PolicyFile: "eks_irsa",
			WantPolicy: Policy{
				Statements: []*PolicyStatement{
					{
						Effect:         AuthorizationDecisionAllow,
						AllowedActions: []string{"sts:AssumeRoleWithWebIdentity"},
						AllowedPrincipals: []*Principal{
							{Type: PrincipalTypeFederated, ID: "arn:aws:iam::111122223333:oidc-provider/oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"},
						},
						Conditions: []*Condition{
							{Key: "oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub", Operator: "StringEquals", AllowedValues: []string{"system:serviceaccount:default:my-service-account"}},
							{Key: "oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud", Operator: "StringEquals", AllowedValues: []string{"sts.amazonaws.com"}},
						},
					},
				},
			},
		},
		{
			PolicyFile: "eks_irsa_stringlike",
			WantPolicy: Policy{
				Statements: []*PolicyStatement{
					{
						Effect:         AuthorizationDecisionAllow,
						AllowedActions: []string{"sts:AssumeRoleWithWebIdentity"},
						AllowedPrincipals: []*Principal{
							{Type: PrincipalTypeFederated, ID: "arn:aws:iam::111122223333:oidc-provider/oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"},
						},
						Conditions: []*Condition{
							{Key: "oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub", Operator: "StringLike", AllowedValues: []string{"system:serviceaccount:my-ns1:*", "system:serviceaccount:my-ns2:*"}},
							{Key: "oidc.eks.region-code.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud", Operator: "StringEquals", AllowedValues: []string{"sts.amazonaws.com"}},
						},
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.PolicyFile, func(t *testing.T) {
			policy, err := ParseRoleTrustPolicy(getTestPolicyFile(scenario.PolicyFile))
			if (err != nil) != scenario.WantErr {
				t.Errorf("expected error: %v, got: %v", scenario.WantErr, err)
			}
			assert.Len(t, policy.Statements, len(scenario.WantPolicy.Statements))
			for i, wantStatement := range scenario.WantPolicy.Statements {
				gotStatement := policy.Statements[i]
				assert.Equal(t, wantStatement.Effect, gotStatement.Effect, "effect statement %d", i)
				assert.ElementsMatchf(t, wantStatement.AllowedActions, gotStatement.AllowedActions, "actions statement %d", i)
				assert.ElementsMatchf(t, wantStatement.Conditions, gotStatement.Conditions, "condition statement %d", i)
				assert.ElementsMatchf(t, wantStatement.AllowedPrincipals, gotStatement.AllowedPrincipals, "principal statement %d", i)
			}
		})
	}
}

func Test_ensureStringArray(t *testing.T) {
	tests := []struct {
		name    string
		action  interface{}
		want    []string
		wantErr bool
	}{
		{name: "parse string action", action: "foo", want: []string{"foo"}},
		{name: "parse string array action", action: []string{"foo", "bar"}, want: []string{"foo", "bar"}},
		{name: "parse string array actions as interface", action: []interface{}{"foo", "bar"}, want: []string{"foo", "bar"}},
		{name: "parse invalid action", action: 42, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ensureStringArray(tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("ensureStringArray() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ensureStringArray() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseSinglePrincipal(t *testing.T) {
	type args struct {
		rawPrincipalType string
		principalId      interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []*Principal
		wantErr bool
	}{
		{
			name: "parse string principal",
			args: args{
				rawPrincipalType: "aws",
				principalId:      "foo",
			},
			want: []*Principal{{Type: PrincipalTypeAWS, ID: "foo"}},
		},
		{
			name: "parse array principal",
			args: args{
				rawPrincipalType: "federated",
				principalId:      []string{"foo", "bar"},
			},
			want: []*Principal{
				{Type: PrincipalTypeFederated, ID: "foo"},
				{Type: PrincipalTypeFederated, ID: "bar"},
			},
		},
		{
			name: "parse invalid principal",
			args: args{
				rawPrincipalType: "IDoNotExist",
				principalId:      "foo",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSinglePrincipal(tt.args.rawPrincipalType, tt.args.principalId)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSinglePrincipal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSinglePrincipal() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseConditions(t *testing.T) {
	tests := []struct {
		name          string
		rawConditions map[string]map[string]interface{}
		want          []*Condition
		wantErr       bool
	}{
		{
			rawConditions: map[string]map[string]interface{}{"StringEquals": {"foo": "bar"}},
			want:          []*Condition{{Operator: "StringEquals", Key: "foo", AllowedValues: []string{"bar"}}},
		},
		{
			rawConditions: map[string]map[string]interface{}{"StringEquals": {"foo": []string{"bar", "baz"}}},
			want:          []*Condition{{Operator: "StringEquals", Key: "foo", AllowedValues: []string{"bar", "baz"}}},
		},
		{
			rawConditions: map[string]map[string]interface{}{"StringEquals": {"foo": "bar", "fooz": "baz"}},
			want: []*Condition{
				{Operator: "StringEquals", Key: "foo", AllowedValues: []string{"bar"}},
				{Operator: "StringEquals", Key: "fooz", AllowedValues: []string{"baz"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConditions(tt.rawConditions)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConditions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseConditions() got = %v, want %v", got, tt.want)
			}
		})
	}
}
