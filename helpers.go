package nextools

import (
	"context"

	"connectrpc.com/connect"
)

type contextHelper struct {
	authenticator Authenticator
}

func (helper *contextHelper) GetToken(req connect.AnyRequest) string {
	accessToken := req.Header().Get("Authorization")
	if accessToken == "" {
		return ""
	}

	return accessToken
}

func (helper *contextHelper) GetUserClaims(ctx context.Context) *Claims {
	userClaims := ctx.Value(ContextKeyUser).(*Claims)
	return userClaims
}

func (helper *contextHelper) GetTenant(ctx context.Context) (string, string) {
	// Extract metadata from context

	countryIso2, ok := helper.getContextString(ctx, XCountryKey)
	if !ok {
		return "", ""
	}

	stateIso2, ok := helper.getContextString(ctx, XStateKey)
	if !ok {
		return countryIso2, ""
	}

	return countryIso2, stateIso2
}

func (helper *contextHelper) getContextString(ctx context.Context, key any) (string, bool) {
	val := ctx.Value(key)
	s, ok := val.(string)
	return s, ok
}

func NewContextHelper(authenticator Authenticator) ContextHelper {
	return &contextHelper{
		authenticator: authenticator,
	}
}
