package iam_evaluation

import (
	"encoding/json"
	"fmt"
	"strings"
)

type rawStatement struct {
	Effect    string                            `json:"Effect"`
	Action    interface{}                       `json:"Action"`
	Principal interface{}                       `json:"Principal"`
	Condition map[string]map[string]interface{} `json:"Condition"`
}

type rawPolicy struct {
	Statement []rawStatement `json:"Statement"`
}

func ParseRoleTrustPolicy(policy string) (*Policy, error) {
	var rawPolicy rawPolicy
	resultPolicy := Policy{}
	err := json.Unmarshal([]byte(policy), &rawPolicy)
	if err != nil {
		return nil, fmt.Errorf("unable to parse role trust policy from JSON: %v", err)
	}
	for _, rawStatement := range rawPolicy.Statement {
		statement, err := parsePolicyStatement(&rawStatement)
		if err != nil {
			return nil, err
		}
		resultPolicy.Statements = append(resultPolicy.Statements, statement)
	}
	
	return &resultPolicy, nil
}

func parsePolicyStatement(rawStatement *rawStatement) (*PolicyStatement, error) {

	var statement PolicyStatement
	effect, err := parseStatementEffect(rawStatement.Effect)
	if err != nil {
		return nil, err
	}
	statement.Effect = effect

	actions, err := ensureStringArray(rawStatement.Action)
	if err != nil {
		return nil, err
	}
	statement.AllowedActions = actions

	principals, err := parsePrincipals(rawStatement.Principal)
	if err != nil {
		return nil, err
	}
	statement.AllowedPrincipals = principals

	conditions, err := parseConditions(rawStatement.Condition)
	if err != nil {
		return nil, err
	}
	statement.Conditions = conditions

	return &statement, nil

}

func parseConditions(rawConditions map[string]map[string]interface{}) ([]*Condition, error) {
	result := []*Condition{}
	for conditionOperator, conditionValues := range rawConditions {
		conditions, err := parseSingleCondition(conditionOperator, conditionValues)
		if err != nil {
			return nil, err
		}
		result = append(result, conditions...)
	}
	return result, nil
}

func parseSingleCondition(operator string, values map[string]interface{}) ([]*Condition, error) {
	conditions := []*Condition{}
	for conditionKey, conditionValues := range values {

		values, err := ensureStringArray(conditionValues)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, &Condition{
			Operator:      operator,
			Key:           conditionKey,
			AllowedValues: values,
		})

	}
	return conditions, nil
}

func parsePrincipals(principals interface{}) ([]*Principal, error) {

	// Case 1: principals is a string and contains "*"
	// Case 2: principals is a map, each entry of the form
	// ("AWS" | "Federated" | "Service" | "CanonicalUser") :
	//    [<principal_id_string>, <principal_id_string>, ...]

	switch principals := principals.(type) {
	case string:
		if principals == "*" {
			return []*Principal{{Type: PrincipalTypeUnknown, ID: "*"}}, nil
		} else {
			return nil, fmt.Errorf("invalid principal: %s", principals)
		}
	case map[string]interface{}:
		results := []*Principal{}
		for principalType, principalValue := range principals {
			result, err := parseSinglePrincipal(principalType, principalValue)
			if err != nil {
				return nil, err
			}
			results = append(results, result...)
		}
		return results, nil
	default:
		return nil, fmt.Errorf("invalid principal: %v", principals)
	}
}

func parseSinglePrincipal(rawPrincipalType string, principalId interface{}) ([]*Principal, error) {
	types := map[string]PrincipalType{
		"aws":           PrincipalTypeAWS,
		"federated":     PrincipalTypeFederated,
		"service":       PrincipalTypeService,
		"canonicaluser": PrincipalTypeCanonicalUser,
	}
	principalType, ok := types[strings.ToLower(rawPrincipalType)]
	if !ok {
		return nil, fmt.Errorf("invalid principal type: %s", rawPrincipalType)
	}
	values, err := ensureStringArray(principalId)
	if err != nil {
		return nil, fmt.Errorf("invalid principal value: %v", principalId)
	}

	principals := []*Principal{}
	for _, value := range values {
		principals = append(principals, &Principal{Type: principalType, ID: value})
	}
	return principals, nil
}

func ensureStringArray(stringOrArray interface{}) ([]string, error) {
	switch value := stringOrArray.(type) {
	case string:
		return []string{value}, nil
	case []string:
		return stringOrArray.([]string), nil
	case []interface{}:
		values := make([]string, len(value))
		for i, v := range value {
			stringValue, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("value cannot be converted to string array: %v", stringOrArray)
			}
			values[i] = stringValue
		}
		return values, nil
	default:
		return nil, fmt.Errorf("value cannot be converted to string array: %v", stringOrArray)
	}
}

func parseStatementEffect(rawEffect string) (AuthorizationDecision, error) {
	switch strings.ToLower(rawEffect) {
	case "allow":
		return AuthorizationDecisionAllow, nil
	case "deny":
		return AuthorizationDecisionDeny, nil
	default:
		return "", fmt.Errorf("invalid effect: %s", rawEffect)
	}
}
