package nextools

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

type SentryReporter struct {
	hub *sentry.Hub
}

func NewSentryReporterFromEnv(service, version, env string) ErrorReporter {
	dsn := strings.TrimSpace(os.Getenv("SENTRY.DSN"))
	if dsn == "" {
		return NewNoopErrorReporter()
	}

	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      env,
		Release:          version,
		ServerName:       service,
		Debug:            isTruthy(os.Getenv("SENTRY.DEBUG")),
		AttachStacktrace: true,
		SendDefaultPII:   isTruthy(os.Getenv("SENTRY.SEND_DEFAULT_PII")),
	})
	if err != nil {
		return NewNoopErrorReporter()
	}

	return &SentryReporter{
		hub: sentry.NewHub(client, sentry.NewScope()),
	}
}

func (r *SentryReporter) Capture(ctx context.Context, report ErrorReport) {
	if r == nil || r.hub == nil {
		return
	}

	hub := r.hub.Clone()
	if hub == nil {
		return
	}

	if ctxHub := sentry.GetHubFromContext(ctx); ctxHub != nil {
		hub = ctxHub.Clone()
		if hub.Client() == nil {
			hub.BindClient(r.hub.Client())
		}
	}

	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(toSentryLevel(report.Level))
		for key, value := range report.Tags {
			scope.SetTag(key, value)
		}
		for key, value := range report.Extra {
			scope.SetExtra(key, value)
		}

		if report.Message != "" {
			scope.SetContext("error_report", map[string]any{
				"message": report.Message,
				"handled": report.Handled,
			})
		}

		if report.Err != nil {
			hub.CaptureException(report.Err)
			return
		}
		if report.Message != "" {
			hub.CaptureMessage(report.Message)
		}
	})
}

func (r *SentryReporter) Close() error {
	if r == nil || r.hub == nil {
		return nil
	}
	r.hub.Flush(2 * time.Second)
	return nil
}

func toSentryLevel(level Level) sentry.Level {
	switch level {
	case LevelTrace, LevelDebug:
		return sentry.LevelDebug
	case LevelInfo, LevelOK:
		return sentry.LevelInfo
	case LevelWarn:
		return sentry.LevelWarning
	case LevelError:
		return sentry.LevelError
	case LevelFatal:
		return sentry.LevelFatal
	default:
		return sentry.LevelError
	}
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
