package nextools

import (
	"context"
	"os"
	"strings"
)

const reportSkipFieldKey = "_report_skip"

type ErrorReport struct {
	Message   string
	Err       error
	Level     Level
	Handled   bool
	Tags      map[string]string
	Extra     map[string]any
	StackSkip int
}

type noopErrorReporter struct{}

func NewNoopErrorReporter() ErrorReporter {
	return noopErrorReporter{}
}

func (noopErrorReporter) Capture(context.Context, ErrorReport) {}

func (noopErrorReporter) Close() error { return nil }

func NewErrorReporterFromEnv(service, version, env string) ErrorReporter {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ERROR.REPORTING_PROVIDER"))) {
	case "", "posthog":
		return NewPostHogReporterFromEnv(service, version, env)
	case "sentry":
		return NewSentryReporterFromEnv(service, version, env)
	case "none", "noop", "disabled":
		return NewNoopErrorReporter()
	default:
		return NewNoopErrorReporter()
	}
}

func ReportSkip() Field {
	return F(reportSkipFieldKey, true)
}

func shouldSkipReport(fields []Field) bool {
	for _, field := range fields {
		if field.Key != reportSkipFieldKey {
			continue
		}
		skip, ok := field.Value.(bool)
		if ok && skip {
			return true
		}
	}
	return false
}

func fieldsToExtra(fields []Field) map[string]any {
	if len(fields) == 0 {
		return nil
	}

	extra := make(map[string]any, len(fields))
	for _, field := range fields {
		if field.Key == reportSkipFieldKey {
			continue
		}
		if err, ok := field.Value.(error); ok && err != nil {
			extra[field.Key] = err.Error()
			continue
		}
		extra[field.Key] = field.Value
	}
	return extra
}

func extractError(fields []Field) error {
	for _, field := range fields {
		if err, ok := field.Value.(error); ok && err != nil {
			return err
		}
		if strings.EqualFold(field.Key, "error") {
			if err, ok := field.Value.(error); ok && err != nil {
				return err
			}
		}
	}
	return nil
}
