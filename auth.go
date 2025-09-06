package nextools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// ContextKeyUser is used to store the authenticated user's claims in context.
	ContextKeyUser = "UserClaimsKey"
	XCountryKey    = "X-Country-Iso2"
	XStateKey      = "X-State-Iso2"
	XSupplierKey   = "X-Supplier"
	XInfluencerKey = "X-Influencer"
)

type Claims struct {
	Exp            int64    `json:"exp"`
	Iat            int64    `json:"iat"`
	Jti            string   `json:"jti"`
	Iss            string   `json:"iss"`
	Aud            []string `json:"aud"`
	Id             string   `json:"sub"`
	Typ            string   `json:"typ"`
	Azp            string   `json:"azp"`
	Acr            string   `json:"acr"`
	AllowedOrigins []string `json:"allowed-origins"`

	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	Scope             string `json:"scope"`
	Sid               string `json:"sid,omitempty"`
	SessionState      string `json:"session_state,omitempty"`
	Country           string `json:"country,omitempty"`
	State             string `json:"state,omitempty"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	ClientHost        string `json:"clientHost,omitempty"`
	ClientAddress     string `json:"clientAddress,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
}

// ExpiresAt returns the expiration time as time.Time
func (c *Claims) ExpiresAt() time.Time {
	return time.Unix(c.Exp, 0)
}

// IssuedAt returns the issue time as time.Time
func (c *Claims) IssuedAt() time.Time {
	return time.Unix(c.Iat, 0)
}

// IsExpired checks if the token has expired
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt())
}

func (c *Claims) HasRole(role string) bool {
	return slices.Contains(c.RealmAccess.Roles, role)
}

func (c *Claims) IsClientToken() bool {
	// If preferred_username starts with "service-account-" it’s a client credentials token
	if len(c.PreferredUsername) >= 16 && c.PreferredUsername[:15] == "service-account" {
		return true
	}

	// If there is no email or name, and client_id is present, it’s probably a client token
	if c.ClientID != "" && c.Name == "" && c.Email == "" {
		return true
	}

	return false
}

func (c *Claims) GetRole() string {
	defaultRoles := []string{
		"default-roles-shooters",
		"default-roles-gh-realm",
		"offline_access",
		"uma_authorization",
	}

	for _, role := range c.RealmAccess.Roles {
		if !slices.Contains(defaultRoles, role) {
			return role
		}
	}

	return ""
}

func (c *Claims) String() string {
	jb, _ := json.MarshalIndent(c, "", " \t")
	return string(jb)
}

// keycloakAuthenticator handles OpenID Connect token validation.
type keycloakAuthenticator struct {
	verifier *oidc.IDTokenVerifier
}

func (authenticator *keycloakAuthenticator) ExtractHeaderToken(request connect.AnyRequest) (string, error) {
	// Look for the authorization header.
	authHeader := request.Header().Get("Authorization")
	if authHeader == "" {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// The authorization header should be in the form "Bearer <token>".
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header")
	}

	return parts[1], nil
}

func (authenticator *keycloakAuthenticator) GetVerifier() *oidc.IDTokenVerifier {
	return authenticator.verifier
}

// NewAuthenticator creates a new OIDC authenticator using the given issuer URL and client configuration.
func NewAuthenticator() (Authenticator, error) {
	clientId := os.Getenv("AUTH.CLIENT_ID")
	issuerUrl := os.Getenv("AUTH.URL")
	url := fmt.Sprintf("%s/realms/%s", issuerUrl, os.Getenv("AUTH.REALM"))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(1000) * time.Second,
		Transport: tr,
	}

	c := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(c, url)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{
		ClientID: clientId,
	}

	verifier := provider.Verifier(oidcConfig)

	return &keycloakAuthenticator{
		verifier: verifier,
	}, nil
}

// ExtractToken extracts the bearer token from the gRPC metadata (authorization header).
func (authenticator *keycloakAuthenticator) ExtractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Look for the authorization header.
	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// The authorization header should be in the form "Bearer <token>".
	parts := strings.SplitN(authHeader[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header")
	}

	return parts[1], nil
}

// ValidateTokenMiddleware validates the JWT token in the authorization header.
func (authenticator *keycloakAuthenticator) ValidateTokenMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract and validate the token from metadata (authorization header).
	token, err := authenticator.ExtractToken(ctx)
	if err != nil {
		return nil, err
	}

	// Parse and verify the token.
	idToken, err := authenticator.GetVerifier().Verify(ctx, token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("failed to verify token: %v", err))
	}

	// Get the claims from the token.
	claims := new(Claims)
	if err := idToken.Claims(claims); err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("failed to verify claims: %v", err))
	}

	// Pass the claims into the context for further use in the handler.
	ctx = context.WithValue(ctx, ContextKeyUser, claims)

	return handler(ctx, req)
}
