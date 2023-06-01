package iam_evaluation

import (
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"path/filepath"
	"strings"
)

type Condition struct {
	Key           string
	Operator      string
	AllowedValues []string
}

var ConditionOperators = map[string]func(string, string) bool{
	"stringequals": func(input string, value string) bool {
		return input == value
	},
	"stringlike": func(input string, pattern string) bool {
		matches, err := filepath.Match(pattern, input)
		return matches && err == nil
	},
}

func (m *Condition) Matches(context *AuthorizationContext) bool {
	operatorFunc, found := ConditionOperators[strings.ToLower(m.Operator)]
	contextKeysMap := utils.NewCaseInsensitiveMap(&context.ContextKeys)
	if !found {
		// unknown operator, the condition cannot match
		return false
	}
	for _, allowedValue := range m.AllowedValues {
		contextKey, hasContextKey := contextKeysMap.Get(m.Key)
		if hasContextKey && operatorFunc(contextKey, allowedValue) {
			return true
		}
	}

	return false
}
