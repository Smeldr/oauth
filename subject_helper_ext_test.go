package oauth_test

import (
	"time"

	"smeldr.dev/oauth"
)

// testSubject is who a test sign-in acts as (D193).
var testSubject = oauth.Subject{UserID: "u-test", TokenID: "fp-test"}

// resolveWith turns a yes-or-no token check into a ResolveBearer that
// answers testSubject for an accepted token.
func resolveWith(verify func(string) bool) func(string) (oauth.Subject, bool) {
	return func(token string) (oauth.Subject, bool) {
		if verify(token) {
			return testSubject, true
		}
		return oauth.Subject{}, false
	}
}

// activeTest is a TokenActive that finds testSubject's token valid.
func activeTest(tokenID string) (oauth.Subject, bool) {
	if tokenID != testSubject.TokenID {
		return oauth.Subject{}, false
	}
	return testSubject, true
}

// withSubject sets testSubject on a seeded refresh token, valid for a day.
func withSubject(rt oauth.RefreshToken) oauth.RefreshToken {
	rt.UserID, rt.TokenID = testSubject.UserID, testSubject.TokenID
	if rt.ExpiresAt.IsZero() {
		rt.ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	return rt
}
