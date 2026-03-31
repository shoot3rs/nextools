package nextools

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"connectrpc.com/validate"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type ErrorReporter interface {
	Capture(context.Context, ErrorReport)
	Close() error
}

type Nextools interface {
	Logger(cfg Config) LoggerClient
	Middleware(authenticator Authenticator, logger LoggerClient, ctxHelper ContextHelper) Middleware
	Authenticator() Authenticator
	DBConnection() DBConnection
	ContextHelper() ContextHelper
	GlobalConfig() GlobalConfig
}

type ContextHelper interface {
	GetTenant(ctx context.Context) (string, string)
	GetUserClaims(context.Context) *Claims
	GetToken(in connect.AnyRequest) string
	GetSupplier(connect.AnyRequest) string
	GetInfluencer(connect.AnyRequest) string
}

type GlobalConfig interface {
	Gorm() *gorm.Config
	HttpClient() *http.Client
	ServerAddr() string
	SseAddress() string
	Http2() *http2.Server
	IsDevelopment() bool
	IsProduction() bool
	IsTesting() bool
	JetStream() jetstream.StreamConfig
	Environment() string
	Redis() *redis.Options
	Validator() validate.Option
}

type DBConnection interface {
	Connect()
	CreateIndexes()
	CreateViews()
	CreateSequence() error
	EnablePostGIS() error
	GetConfig() *gorm.Config
	GetEngine() interface{}
}

type Middleware interface {
	CorsMiddleware(http.Handler) http.Handler
	HealthChecker(string) *grpchealth.StaticChecker
	UnaryLoggingInterceptor() connect.UnaryInterceptorFunc
	TenantHeaderInterceptor(routes ...string) connect.UnaryInterceptorFunc
	UnaryTenantMismatchInterceptor() connect.UnaryInterceptorFunc
	UnaryTokenInterceptor(routes ...string) connect.UnaryInterceptorFunc
}

type Authenticator interface {
	ExtractHeaderToken(connect.AnyRequest) (string, error)
	ExtractToken(ctx context.Context) (string, error)
	GetVerifier() *oidc.IDTokenVerifier
	ValidateTokenMiddleware(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error)
}

// LoggerClient lists the exported helpers backed by nextools.Logger.
type LoggerClient interface {
	With(fields ...Field) *Logger
	Close() error
	SetLevel(Level)
	Trace(msg string, fields ...Field)
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	OK(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	Log(level Level, msg string, fields ...Field)
	WithEntry(Entry)
	Banner(extras ...Field)
	ConnectInterceptor() connect.UnaryInterceptorFunc
	GORMLogger(minLevel gormlogger.LogLevel) gormlogger.Interface
	NATSOptions() []nats.Option
	NATSPublish(nc *nats.Conn, subject string, data []byte) error
	NATSSubscribe(nc *nats.Conn, subject string, handler nats.MsgHandler) (*nats.Subscription, error)
	PGTracer() *PGQueryTracer
}
