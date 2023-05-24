package iam_evaluation

import (
	"path/filepath"
	"strings"
)

type PrincipalType string

const (
	PrincipalTypeUnknown       = PrincipalType("")
	PrincipalTypeAny           = "[any]"
	PrincipalTypeAWS           = PrincipalType("AWS")
	PrincipalTypeService       = PrincipalType("Service")
	PrincipalTypeFederated     = PrincipalType("Federated")
	PrincipalTypeCanonicalUser = PrincipalType("CanonicalUser")
)

type Principal struct {
	Type PrincipalType
	ID   string
}

type PolicyStatement struct {
	Effect            AuthorizationDecision
	AllowedPrincipals []*Principal
	AllowedActions    []string
	Conditions        []*Condition
}

func (m *PolicyStatement) Authorize(context *AuthorizationContext) *AuthorizationResult {
	statementMatches := m.statementMatches(context)
	if !statementMatches {
		// The statement does not match, no authorization decision
		return &AuthorizationResultNoDecision
	}

	if m.Effect == AuthorizationDecisionAllow {
		return &AuthorizationResultAllow // Explicit allow
	}
	return &AuthorizationResultDeny // Explicit deny
}

func (m *PolicyStatement) statementMatches(context *AuthorizationContext) bool {
	return m.actionMatches(context.Action) &&
		m.principalMatches(context.Principal) &&
		m.conditionsMatch(context)
}

func (m *PolicyStatement) conditionsMatch(context *AuthorizationContext) bool {
	if len(m.Conditions) == 0 {
		return true // no conditions
	}

	// Conditions are AND'ed together
	for _, condition := range m.Conditions {
		if !condition.Matches(context) {
			// At least one condition doesn't match, deny authorization
			return false
		}
	}

	// We verified that all conditions matched
	return true
}

func (m *PolicyStatement) actionMatches(action string) bool {
	action = strings.ToLower(action)
	for _, allowedAction := range m.AllowedActions {
		if match, err := filepath.Match(strings.ToLower(allowedAction), action); match && err == nil {
			return true
		}
	}
	return false
}

func (m *PolicyStatement) principalMatches(principal *Principal) bool {
	for _, allowedPrincipal := range m.AllowedPrincipals {
		if allowedPrincipal.Type == PrincipalTypeAny {
			return true
		}

		if allowedPrincipal.Type != principal.Type {
			continue
		}

		if match, err := filepath.Match(allowedPrincipal.ID, principal.ID); match && err == nil {
			return true
		}
	}
	return false
}
