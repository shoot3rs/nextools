package nextools

import (
	"io"
	"os"
)

type LoggerBuilder struct {
	cfg Config
}

// NewLoggerBuilder returns a builder seeded with sensible defaults.
func NewLoggerBuilder() *LoggerBuilder {
	return &LoggerBuilder{
		cfg: Config{
			Service: os.Getenv("APP.NAME"),
			Version: os.Getenv("APP.VERSION"),
			Env:     DetectAppEnv(nil),
			Level:   LevelInfo,
			Output:  os.Stdout,
			Reporter: NewErrorReporterFromEnv(
				os.Getenv("APP.NAME"),
				os.Getenv("APP.VERSION"),
				string(DetectAppEnv(nil)),
			),
		},
	}
}

// WithService overrides the service name.
func (b *LoggerBuilder) WithService(service string) *LoggerBuilder {
	if service != "" {
		b.cfg.Service = service
	}
	return b
}

// WithVersion overrides the version label emitted in logs.
func (b *LoggerBuilder) WithVersion(version string) *LoggerBuilder {
	if version != "" {
		b.cfg.Version = version
	}
	return b
}

// WithEnv sets the target environment (development, production, etc.).
func (b *LoggerBuilder) WithEnv(env Env) *LoggerBuilder {
	if env != "" {
		b.cfg.Env = env
	}
	return b
}

// WithLevel adjusts the minimum log level.
func (b *LoggerBuilder) WithLevel(level Level) *LoggerBuilder {
	b.cfg.Level = level
	return b
}

// WithOutput changes where log entries are written.
func (b *LoggerBuilder) WithOutput(output io.Writer) *LoggerBuilder {
	if output != nil {
		b.cfg.Output = output
	}
	return b
}

// WithNoColor toggles ANSI output.
func (b *LoggerBuilder) WithNoColor(noColor bool) *LoggerBuilder {
	b.cfg.NoColor = noColor
	return b
}

// WithErrorReporter overrides the error reporter used for error tracking.
func (b *LoggerBuilder) WithErrorReporter(reporter ErrorReporter) *LoggerBuilder {
	b.cfg.Reporter = reporter
	return b
}

// WithCallerSkip adds extra stack frames to skip when resolving file:line.
func (b *LoggerBuilder) WithCallerSkip(skip int) *LoggerBuilder {
	if skip > 0 {
		b.cfg.CallerSkip = skip
	}
	return b
}

// WithConfig seeds the builder with an existing Config.
func (b *LoggerBuilder) WithConfig(cfg Config) *LoggerBuilder {
	b.cfg = cfg
	return b
}

// Build creates the LoggerClient using the configured values.
func (b *LoggerBuilder) Build() LoggerClient {
	return NewLogger(b.cfg)
}
