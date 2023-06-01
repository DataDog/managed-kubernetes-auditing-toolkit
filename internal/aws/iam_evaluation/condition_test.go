package iam_evaluation

import "testing"

func TestConditionStringEquals(t *testing.T) {
	scenarios := []struct {
		Name                 string
		Condition            *Condition
		AuthorizationContext *AuthorizationContext
		ShouldMatch          bool
	}{
		{
			"unknown operator should not match",
			&Condition{
				Key:           "foo",
				Operator:      "OperatorThatDoesNotExist",
				AllowedValues: []string{"bar"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{}},
			false,
		},
		{
			"simple string equals",
			&Condition{
				Key:           "foo",
				Operator:      "StringEquals",
				AllowedValues: []string{"bar"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"simple string equals with no match",
			&Condition{
				Key:           "foo",
				Operator:      "StringEquals",
				AllowedValues: []string{"baz"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			false,
		},
		{
			"simple string equals with multiple value should OR them together",
			&Condition{
				Key:           "foo",
				Operator:      "StringEquals",
				AllowedValues: []string{"baz", "bar"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"condition keys are not case sensitive, per https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
			&Condition{
				Key:           "AWS:SourceIp",
				Operator:      "StringEquals",
				AllowedValues: []string{"foo"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"aws:sourceip": "foo"}},
			true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := scenario.Condition.Matches(scenario.AuthorizationContext)
			if result && !scenario.ShouldMatch {
				t.Errorf("condition matched, expected it NOT to match")
			} else if !result && scenario.ShouldMatch {
				t.Errorf("condition did NOT match, expected it to match")
			}
		})
	}
}

func TestConditionStringLike(t *testing.T) {
	scenarios := []struct {
		Name                 string
		Condition            *Condition
		AuthorizationContext *AuthorizationContext
		ShouldMatch          bool
	}{
		{
			"simple string like with no wildcard should match",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"bar"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"simple string like with wildcard",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"b*"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"simple string like with wildcard not matching",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"b*"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "nope"}},
			false,
		},
		{
			"simple string like with multiple value should OR them together",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"a*", "b*"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"simple string like with wildcard should match",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"*"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"foo": "bar"}},
			true,
		},
		{
			"simple string like with wildcard should not match missing key",
			&Condition{
				Key:           "foo",
				Operator:      "StringLike",
				AllowedValues: []string{"*"},
			},
			&AuthorizationContext{ContextKeys: map[string]string{"nope": "nope"}},
			false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := scenario.Condition.Matches(scenario.AuthorizationContext)
			if result && !scenario.ShouldMatch {
				t.Errorf("condition matched, expected it NOT to match")
			} else if !result && scenario.ShouldMatch {
				t.Errorf("condition did NOT match, expected it to match")
			}
		})
	}
}
