package iam_evaluation

import (
	"path/filepath"
)

type PolicyStatement struct {
	Effect            AuthorizationDecision
	AllowedPrincipals []string
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
	//TODO ignore case?
	//TODO: reproduce better how wildcard works in AWS
	for _, allowedAction := range m.AllowedActions {
		if match, err := filepath.Match(allowedAction, action); match && err == nil {
			return true
		}
	}
	return false
}

func (m *PolicyStatement) principalMatches(principal string) bool {
	// TODO behavior
	// TODO: should we ignore Principal if empty? or say it should always be filled since we're in context of a RBP
	for _, allowedPrincipal := range m.AllowedPrincipals {
		if match, err := filepath.Match(allowedPrincipal, principal); match && err == nil {
			return true
		}
	}
	return false
}
