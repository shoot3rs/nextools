package nextools

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"connectrpc.com/validate"
	"github.com/charmmtech/sseor"
	"github.com/joho/godotenv"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ConfigOption func(*appConfig)

// WithEnvLookup allows overriding how environment variables are read.
func WithEnvLookup(fn func(string) string) ConfigOption {
	return func(cfg *appConfig) {
		if fn != nil {
			cfg.envLookup = fn
		}
	}
}

// WithEnvValue preloads a specific key/value pair before falling back to the environment.
func WithEnvValue(key, value string) ConfigOption {
	return func(cfg *appConfig) {
		if cfg.overrides == nil {
			cfg.overrides = make(map[string]string)
		}
		cfg.overrides[key] = value
	}
}

// WithEnvValues preloads multiple values upfront.
func WithEnvValues(values map[string]string) ConfigOption {
	return func(cfg *appConfig) {
		if cfg.overrides == nil {
			cfg.overrides = make(map[string]string, len(values))
		}
		for k, v := range values {
			cfg.overrides[k] = v
		}
	}
}

// WithHttpClient swaps the underlying HTTP client for request helpers.
func WithHttpClient(client *http.Client) ConfigOption {
	return func(cfg *appConfig) {
		if client != nil {
			cfg.httpClient = client
		}
	}
}

// WithHttp2Server injects a pre-built HTTP/2 server configuration.
func WithHttp2Server(server *http2.Server) ConfigOption {
	return func(cfg *appConfig) {
		if server != nil {
			cfg.http2Server = server
		}
	}
}

// WithValidator sets the validation option that config returns.
func WithValidator(option validate.Option) ConfigOption {
	return func(cfg *appConfig) {
		cfg.validator = option
	}
}

// WithRedisOptions reuses a pre-built redis.Options.
func WithRedisOptions(options *redis.Options) ConfigOption {
	return func(cfg *appConfig) {
		if options != nil {
			cfg.redisOptions = cloneRedisOptions(options)
		}
	}
}

// WithJetStreamConfig sets a custom stream definition.
func WithJetStreamConfig(stream jetstream.StreamConfig) ConfigOption {
	return func(cfg *appConfig) {
		cfg.jetStreamConfig = &jetstream.StreamConfig{}
		*cfg.jetStreamConfig = stream
	}
}

// WithSseorConfig injects a custom SSE configuration.
func WithSseorConfig(s *sseor.Config) ConfigOption {
	return func(cfg *appConfig) {
		if s != nil {
			tmp := *s
			cfg.sseorConfig = &tmp
		}
	}
}

// WithGormConfig reuses an existing GORM config.
func WithGormConfig(config *gorm.Config) ConfigOption {
	return func(cfg *appConfig) {
		if config != nil {
			cfg.gormConfig = config
		}
	}
}

type appConfig struct {
	envLookup       func(string) string
	overrides       map[string]string
	httpClient      *http.Client
	http2Server     *http2.Server
	redisOptions    *redis.Options
	gormConfig      *gorm.Config
	validator       validate.Option
	jetStreamConfig *jetstream.StreamConfig
	sseorConfig     *sseor.Config
}

func cloneRedisOptions(value *redis.Options) *redis.Options {
	if value == nil {
		return nil
	}
	c := *value
	return &c
}

func (cfg *appConfig) envValue(key string) string {
	if cfg.overrides != nil {
		if v, ok := cfg.overrides[key]; ok {
			return v
		}
	}

	if cfg.envLookup != nil {
		return strings.TrimSpace(cfg.envLookup(key))
	}
	return strings.TrimSpace(os.Getenv(key))
}

func (cfg *appConfig) splitEnvList(key string) []string {
	raw := cfg.envValue(key)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (cfg *appConfig) intFromEnv(key string, fallback int) int {
	if raw := cfg.envValue(key); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return fallback
}

func (cfg *appConfig) boolFromEnv(key string, fallback bool) bool {
	if raw := strings.ToLower(cfg.envValue(key)); raw != "" {
		switch raw {
		case "1", "true", "yes", "True":
			return true
		case "0", "false", "no", "False":
			return false
		}
	}
	return fallback
}

func (cfg *appConfig) HttpClient() *http.Client {
	if cfg.httpClient != nil {
		return cfg.httpClient
	}
	return http.DefaultClient
}

func (cfg *appConfig) SseAddress() string {
	host := cfg.envValue("APP.SSE_HOST")
	if host == "" {
		host = cfg.envValue("APP.HOST")
	}
	port := cfg.envValue("APP.SSE_PORT")
	if port == "" {
		port = "8081"
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func (cfg *appConfig) Env() Env {
	return EnvFromString(cfg.envValue("APP.ENV"))
}

func (cfg *appConfig) Environment() string {
	return string(cfg.Env())
}

func (cfg *appConfig) Redis() *redis.Options {
	if cfg.redisOptions != nil {
		return cfg.redisOptions
	}

	addr := cfg.envValue("REDIS.ADDR")
	if addr == "" {
		addr = cfg.envValue("REDIS_URL")
	}

	options := &redis.Options{
		Addr:         addr,
		Username:     cfg.envValue("REDIS.USER"),
		Password:     cfg.envValue("REDIS.PASS"),
		DB:           cfg.intFromEnv("REDIS.DB", 0),
		PoolSize:     cfg.intFromEnv("REDIS.POOL_SIZE", 10),
		MinIdleConns: cfg.intFromEnv("REDIS.MIN_IDLE", 2),
		MaxRetries:   cfg.intFromEnv("REDIS.MAX_RETRIES", 3),
	}

	return options
}

func (cfg *appConfig) Sseor() *sseor.Config {
	if cfg.sseorConfig != nil {
		return cfg.sseorConfig
	}

	conf := sseor.DefaultConfig()

	if redisURL := cfg.envValue("REDIS.URL"); redisURL != "" {
		conf.RedisURL = redisURL
	} else if alt := cfg.envValue("REDIS_URL"); alt != "" {
		conf.RedisURL = alt
	}

	conf.RedisPoolSize = cfg.intFromEnv("REDIS.POOL_SIZE", conf.RedisPoolSize)
	conf.RedisMinIdleConns = cfg.intFromEnv("REDIS.MIN_IDLE", conf.RedisMinIdleConns)
	conf.RedisMaxRetries = cfg.intFromEnv("REDIS.MAX_RETRIES", conf.RedisMaxRetries)

	if origins := cfg.splitEnvList("SSE.CORS_ORIGINS"); len(origins) > 0 {
		conf.CORSOrigins = origins
	}

	conf.AuthRequired = cfg.boolFromEnv("SSE.AUTH_REQUIRED", conf.AuthRequired)
	conf.RequireNamespace = cfg.boolFromEnv("SSE.REQUIRE_NAMESPACE", conf.RequireNamespace)
	conf.HealthCheckPath = cfg.envValue("SSE.HEALTH_PATH")
	if conf.HealthCheckPath == "" {
		conf.HealthCheckPath = "/health"
	}
	conf.MetricsPath = cfg.envValue("SSE.METRICS_PATH")
	if conf.MetricsPath == "" {
		conf.MetricsPath = "/metrics"
	}
	if issuer := cfg.envValue("AUTH.URL"); issuer != "" {
		if realm := cfg.envValue("AUTH.REALM"); realm != "" {
			conf.OIDCIssuerURL = fmt.Sprintf("%s/realms/%s", strings.TrimRight(issuer, "/"), realm)
		}
	}
	if client := cfg.envValue("AUTH.CLIENT_ID"); client != "" {
		conf.OIDCClientID = client
	}

	cfg.sseorConfig = conf
	return conf
}

func (cfg *appConfig) Validator() validate.Option {
	return cfg.validator
}

func (cfg *appConfig) JetStream() jetstream.StreamConfig {
	if cfg.jetStreamConfig != nil {
		return *cfg.jetStreamConfig
	}

	stream := jetstream.StreamConfig{
		Name:     cfg.envValue("NEXOR.STREAM_NAME"),
		Subjects: cfg.splitEnvList("NEXOR.STREAM_SUBJECTS"),
		Storage:  jetstream.FileStorage,
	}

	return stream
}

func (cfg *appConfig) Http2() *http2.Server {
	if cfg.http2Server != nil {
		return cfg.http2Server
	}
	return &http2.Server{}
}

func (cfg *appConfig) IsTesting() bool {
	return cfg.Env() == EnvTesting
}

func (cfg *appConfig) IsDevelopment() bool {
	return cfg.Env() == EnvDevelopment
}

func (cfg *appConfig) IsProduction() bool {
	return cfg.Env() == EnvProduction
}

func (cfg *appConfig) ServerAddr() string {
	host := cfg.envValue("APP.HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := cfg.envValue("APP.PORT")
	if port == "" {
		port = "8080"
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func (cfg *appConfig) Gorm() *gorm.Config {
	if cfg.gormConfig != nil {
		return cfg.gormConfig
	}

	logMode := logger.Info
	if cfg.IsProduction() {
		logMode = logger.Silent
	}

	cfg.gormConfig = &gorm.Config{
		SkipDefaultTransaction:                   false,
		NamingStrategy:                           nil,
		FullSaveAssociations:                     false,
		Logger:                                   logger.Default.LogMode(logMode),
		NowFunc:                                  nil,
		DryRun:                                   false,
		PrepareStmt:                              false,
		DisableAutomaticPing:                     false,
		DisableForeignKeyConstraintWhenMigrating: false,
		IgnoreRelationshipsWhenMigrating:         false,
		DisableNestedTransaction:                 false,
		AllowGlobalUpdate:                        false,
		QueryFields:                              false,
		CreateBatchSize:                          0,
		TranslateError:                           true,
		ClauseBuilders:                           nil,
		ConnPool:                                 nil,
		Dialector:                                nil,
		Plugins:                                  nil,
	}

	return cfg.gormConfig
}

func (cfg *appConfig) LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Unable to load .env")
		return
	}
	log.Println(".env loaded successfully!")
}

func NewConfig(opts ...ConfigOption) GlobalConfig {
	cfg := &appConfig{
		envLookup: os.Getenv,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
