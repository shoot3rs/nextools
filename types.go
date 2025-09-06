package nextools

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
	"github.com/shoot3rs/sseor"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"gorm.io/gorm"
)

type ContextHelper interface {
	GetTenant(ctx context.Context) (string, string)
	GetUserClaims(context.Context) *Claims
	GetToken(in connect.AnyRequest) string
}

type Config interface {
	Gorm() *gorm.Config
	HttpClient() *http.Client
	ServerAddr() string
	SseAddress() string
	Http2() *http2.Server
	IsDevelopment() bool
	IsProduction() bool
	IsTesting() bool
	JetStream() jetstream.StreamConfig
	LoadEnv()
	Logger() *zap.Logger
	Environment() string
	Redis() *redis.Options
	Sseor() *sseor.Config
}

type Connection interface {
	Connect()
	GetConfig() *gorm.Config
	GetEngine() interface{}
}

type Middleware interface {
	CorsMiddleware(http.Handler) http.Handler
	HealthChecker(string) *grpchealth.StaticChecker
	LoggingUnaryInterceptor() connect.UnaryInterceptorFunc
	TenantHeaderInterceptor(routes ...string) connect.UnaryInterceptorFunc
	UnaryTenantMismatchInterceptor() connect.UnaryInterceptorFunc
	UnaryTokenInterceptor(routes ...string) connect.UnaryInterceptorFunc
}

type SSEMiddleware interface {
	AttachSSEHeaders(next http.HandlerFunc) http.HandlerFunc
	AuthMiddleware(next http.HandlerFunc) http.HandlerFunc
	NamespaceMiddleware(next http.HandlerFunc) http.HandlerFunc
}

type Authenticator interface {
	ExtractHeaderToken(connect.AnyRequest) (string, error)
	ExtractToken(ctx context.Context) (string, error)
	GetVerifier() *oidc.IDTokenVerifier
	ValidateTokenMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error)
}
