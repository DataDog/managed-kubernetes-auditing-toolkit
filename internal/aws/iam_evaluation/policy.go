package iam_evaluation

type Policy struct {
	Statements []*PolicyStatement
}

func NewPolicy() *Policy {
	return &Policy{
		Statements: []*PolicyStatement{},
	}
}

func (m *Policy) Authorize(context *AuthorizationContext) *AuthorizationResult {
	willAllow := false

	for _, statement := range m.Statements {
		decision := *statement.Authorize(context)
		if decision == AuthorizationResultDeny {
			return &AuthorizationResultDeny // explicit deny, overwriting any previous allow statement
		} else if decision == AuthorizationResultAllow {
			willAllow = true
		}
	}

	if willAllow {
		return &AuthorizationResultAllow
	}

	return &AuthorizationResultDeny // implicit deny
}

func (m *Policy) Merge(other *Policy) *Policy {
	// deep copy
	newPolicy := NewPolicy()
	newPolicy.Statements = make([]*PolicyStatement, len(m.Statements)+len(other.Statements))
	copy(newPolicy.Statements, m.Statements)
	copy(newPolicy.Statements, other.Statements)
	return newPolicy
}
