package nextools

import (
	"context"

	"connectrpc.com/connect"
)

type contextHelper struct {
	authenticator Authenticator
}

func (helper *contextHelper) GetInfluencer(request connect.AnyRequest) string {
	influencer := request.Header().Get(XInfluencerKey)
	if influencer == "" {
		return ""
	}

	return influencer
}

func (helper *contextHelper) GetSupplier(request connect.AnyRequest) string {
	supplierID := request.Header().Get(XSupplierKey)
	if supplierID == "" {
		return ""
	}

	return supplierID
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

// ContextHelperBuilder builds a ContextHelper with optional dependencies.
type ContextHelperBuilder struct {
	authenticator Authenticator
}

// NewContextHelperBuilder creates a new builder instance.
func NewContextHelperBuilder() *ContextHelperBuilder {
	return &ContextHelperBuilder{}
}

// WithAuthenticator assigns the Authenticator dependency.
func (b *ContextHelperBuilder) WithAuthenticator(auth Authenticator) *ContextHelperBuilder {
	b.authenticator = auth
	return b
}

// Build returns the configured ContextHelper.
func (b *ContextHelperBuilder) Build() ContextHelper {
	return &contextHelper{
		authenticator: b.authenticator,
	}
}

// NewContextHelper is a convenience helper that uses the builder.
func NewContextHelper(authenticator Authenticator) ContextHelper {
	return NewContextHelperBuilder().
		WithAuthenticator(authenticator).
		Build()
}
