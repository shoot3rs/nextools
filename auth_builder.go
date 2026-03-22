package nextools

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type AuthenticatorBuilder struct {
	issuerURL  string
	realm      string
	clientID   string
	httpClient *http.Client
	tlsConfig  *tls.Config
	timeout    time.Duration
}

// AuthenticatorOption customizes the builder before Build().
type AuthenticatorOption func(*AuthenticatorBuilder)

// NewAuthenticatorBuilder seeds a builder with the current environment values.
func NewAuthenticatorBuilder() *AuthenticatorBuilder {
	return &AuthenticatorBuilder{
		issuerURL: os.Getenv("AUTH.URL"),
		realm:     os.Getenv("AUTH.REALM"),
		clientID:  os.Getenv("AUTH.CLIENT_ID"),
		timeout:   time.Duration(1000) * time.Second,
	}
}

// WithAuthenticatorIssuer overrides the issuer URL.
func WithAuthenticatorIssuer(url string) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if url != "" {
			b.issuerURL = url
		}
	}
}

// WithAuthenticatorRealm overrides the realm name.
func WithAuthenticatorRealm(realm string) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if realm != "" {
			b.realm = realm
		}
	}
}

// WithAuthenticatorClientID overrides the client ID.
func WithAuthenticatorClientID(clientID string) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if clientID != "" {
			b.clientID = clientID
		}
	}
}

// WithAuthenticatorHTTPClient reuses an existing HTTP client.
func WithAuthenticatorHTTPClient(client *http.Client) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if client != nil {
			b.httpClient = client
		}
	}
}

// WithAuthenticatorTLSConfig swaps the TLS config used for HTTP requests.
func WithAuthenticatorTLSConfig(cfg *tls.Config) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if cfg != nil {
			b.tlsConfig = cfg
		}
	}
}

// WithAuthenticatorTimeout overrides the HTTP client timeout.
func WithAuthenticatorTimeout(timeout time.Duration) AuthenticatorOption {
	return func(b *AuthenticatorBuilder) {
		if timeout > 0 {
			b.timeout = timeout
		}
	}
}

// Build instantiates the Authenticator using the configured values.
func (b *AuthenticatorBuilder) Build() (Authenticator, error) {
	httpClient := b.httpClient
	if httpClient == nil {
		transport := &http.Transport{
			TLSClientConfig: b.tlsConfig,
		}
		httpClient = &http.Client{
			Timeout:   b.timeout,
			Transport: transport,
		}
	}

	discoveryURL := fmt.Sprintf("%s/realms/%s", b.issuerURL, b.realm)
	ctx := context.Background()
	c := oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(c, discoveryURL)
	if err != nil {
		return nil, err
	}

	oidcConfig := &oidc.Config{ClientID: b.clientID}
	verifier := provider.Verifier(oidcConfig)

	return &keycloakAuthenticator{verifier: verifier}, nil
}

// NewAuthenticator builds a keycloak authenticator via builder options.
func NewAuthenticator(opts ...AuthenticatorOption) (Authenticator, error) {
	builder := NewAuthenticatorBuilder()
	for _, opt := range opts {
		opt(builder)
	}
	return builder.Build()
}
