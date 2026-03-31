package nextools

// MiddlewareBuilder anchors middleware, ensuring dependencies are wired declaratively.
type MiddlewareBuilder struct {
	authenticator Authenticator
	logger        LoggerClient
	helper        ContextHelper
	reporter      ErrorReporter
}

// NewMiddlewareBuilder boots a builder instance.
func NewMiddlewareBuilder() *MiddlewareBuilder {
	return &MiddlewareBuilder{}
}

// WithAuthenticator sets the authenticator dependency.
func (b *MiddlewareBuilder) WithAuthenticator(auth Authenticator) *MiddlewareBuilder {
	b.authenticator = auth
	return b
}

// WithLogger sets the logging dependency.
func (b *MiddlewareBuilder) WithLogger(logger LoggerClient) *MiddlewareBuilder {
	b.logger = logger
	if concrete, ok := logger.(*Logger); ok && b.reporter == nil {
		b.reporter = concrete.cfg.Reporter
	}
	return b
}

// WithContextHelper wires the helper that extracts contextual metadata.
func (b *MiddlewareBuilder) WithContextHelper(helper ContextHelper) *MiddlewareBuilder {
	b.helper = helper
	return b
}

// WithErrorReporter wires an error reporter for request-scoped failures.
func (b *MiddlewareBuilder) WithErrorReporter(reporter ErrorReporter) *MiddlewareBuilder {
	b.reporter = reporter
	return b
}

// Build returns a Middleware configured with the collected dependencies.
func (b *MiddlewareBuilder) Build() Middleware {
	return &middleware{
		loggR:         b.logger,
		authenticator: b.authenticator,
		contextHelper: b.helper,
		reporter:      b.reporter,
	}
}

// BuildSSE returns an SSEMiddleware configured with the current dependencies.
//func (b *MiddlewareBuilder) BuildSSE() SSEMiddleware {
//	return &sseMiddleware{
//		loggR:         b.logger,
//		contextHelper: b.helper,
//		authenticator: b.authenticator,
//	}
//}
