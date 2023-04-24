package iam_evaluation

type Policy struct {
	Statements []*PolicyStatement
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
	} else {
		return &AuthorizationResultDeny // implicit deny
	}
}
