package nextools

type nextools struct {
	cfg                  GlobalConfig
	loggerFactory        func() *LoggerBuilder
	authenticatorFactory func() *AuthenticatorBuilder
	middlewareFactory    func() *MiddlewareBuilder
}

type NextoolsOption func(*nextools)

// WithGlobalConfig seeds nextools with a pre-built GlobalConfig.
func WithGlobalConfig(cfg GlobalConfig) NextoolsOption {
	return func(n *nextools) {
		if cfg != nil {
			n.cfg = cfg
		}
	}
}

// WithLoggerBuilderFactory supplies a custom factory used whenever Logger() is invoked.
func WithLoggerBuilderFactory(factory func() *LoggerBuilder) NextoolsOption {
	return func(n *nextools) {
		if factory != nil {
			n.loggerFactory = factory
		}
	}
}

// WithAuthenticatorBuilderFactory supplies a custom factory used by Authenticator().
func WithAuthenticatorBuilderFactory(factory func() *AuthenticatorBuilder) NextoolsOption {
	return func(n *nextools) {
		if factory != nil {
			n.authenticatorFactory = factory
		}
	}
}

// WithMiddlewareBuilderFactory supplies a custom factory used by Middleware()/SSEMiddleware().
func WithMiddlewareBuilderFactory(factory func() *MiddlewareBuilder) NextoolsOption {
	return func(n *nextools) {
		if factory != nil {
			n.middlewareFactory = factory
		}
	}
}

func New(opts ...NextoolsOption) Nextools {
	n := &nextools{
		cfg:                  NewConfig(),
		loggerFactory:        func() *LoggerBuilder { return NewLoggerBuilder() },
		authenticatorFactory: func() *AuthenticatorBuilder { return NewAuthenticatorBuilder() },
		middlewareFactory:    func() *MiddlewareBuilder { return NewMiddlewareBuilder() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(n)
		}
	}
	return n
}

func (n nextools) Logger(cfg Config) LoggerClient {
	builder := n.loggerFactory()
	builder.WithService(cfg.Service)
	builder.WithVersion(cfg.Version)
	builder.WithEnv(cfg.Env)
	builder.WithLevel(cfg.Level)
	builder.WithOutput(cfg.Output)
	builder.WithNoColor(cfg.NoColor)
	builder.WithCallerSkip(cfg.CallerSkip)
	return builder.Build()
}

func (n nextools) Middleware(authenticator Authenticator, logger LoggerClient, ctxHelper ContextHelper) Middleware {
	builder := n.middlewareFactory().
		WithAuthenticator(authenticator).
		WithLogger(logger).
		WithContextHelper(ctxHelper)
	return builder.Build()
}

func (n nextools) SSEMiddleware(authenticator Authenticator, logger LoggerClient, ctxHelper ContextHelper) SSEMiddleware {
	builder := n.middlewareFactory().
		WithAuthenticator(authenticator).
		WithLogger(logger).
		WithContextHelper(ctxHelper)
	return builder.BuildSSE()
}

func (n nextools) Authenticator() Authenticator {
	builder := n.authenticatorFactory()
	authenticator, err := builder.Build()
	if err != nil {
		return nil
	}
	return authenticator
}

func (n nextools) DBConnection() DBConnection {
	//TODO implement me
	panic("implement me")
}

func (n nextools) ContextHelper() ContextHelper {
	return NewContextHelper(n.Authenticator())
}

func (n nextools) GlobalConfig() GlobalConfig {
	return n.cfg
}
