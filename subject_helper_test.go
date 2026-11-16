package oauth

// testSubject is who a test sign-in acts as (D193).
var testSubject = Subject{UserID: "u-test", TokenID: "fp-test"}

// resolveWith turns a yes-or-no token check into a ResolveBearer that
// answers testSubject for an accepted token.
func resolveWith(verify func(string) bool) func(string) (Subject, bool) {
	return func(token string) (Subject, bool) {
		if verify(token) {
			return testSubject, true
		}
		return Subject{}, false
	}
}

// activeTest is a TokenActive that finds testSubject's token valid.
func activeTest(tokenID string) (Subject, bool) {
	if tokenID != testSubject.TokenID {
		return Subject{}, false
	}
	return testSubject, true
}
