package nextools

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/posthog/posthog-go"
)

type PostHogReporter struct {
	mu         sync.Mutex
	client     posthog.Client
	distinctID string
	enabled    bool
}

func NewPostHogReporterFromEnv(service, version, env string) ErrorReporter {
	token := firstNonEmpty(
		os.Getenv("POSTHOG.PROJECT_TOKEN"),
		os.Getenv("POSTHOG.PROJECT_API_KEY"),
		os.Getenv("POSTHOG.API_KEY"),
	)
	if token == "" {
		return NewNoopErrorReporter()
	}

	endpoint := strings.TrimSpace(os.Getenv("POSTHOG.ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("POSTHOG.HOST"))
	}
	if endpoint == "" {
		endpoint = "https://us.i.posthog.com"
	}

	client, err := posthog.NewWithConfig(token, posthog.Config{
		Endpoint: endpoint,
	})
	if err != nil {
		return NewNoopErrorReporter()
	}

	hostname, hostErr := os.Hostname()
	if hostErr != nil || hostname == "" {
		hostname = "unknown-host"
	}

	distinctID := firstNonEmpty(
		os.Getenv("POSTHOG.DISTINCT_ID"),
		fmt.Sprintf("%s:%s:%s:%s", service, env, version, hostname),
	)

	return &PostHogReporter{
		client:     client,
		distinctID: distinctID,
		enabled:    true,
	}
}

func (r *PostHogReporter) Close() error {
	if r == nil || !r.enabled || r.client == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client == nil {
		return nil
	}

	err := r.client.Close()
	r.client = nil
	r.enabled = false
	return err
}

func (r *PostHogReporter) Capture(_ context.Context, report ErrorReport) {
	if r == nil || !r.enabled || r.client == nil {
		return
	}

	exceptionType := classifyExceptionType(report.Err, report.Message)
	exceptionValue := classifyExceptionValue(report.Err, report.Message)
	handled := report.Handled

	exception := posthog.Exception{
		DistinctId: r.distinctID,
		Timestamp:  time.Now(),
		ExceptionList: []posthog.ExceptionItem{
			{
				Type:  exceptionType,
				Value: exceptionValue,
				Mechanism: &posthog.ExceptionMechanism{
					Handled: &handled,
				},
				Stacktrace: posthog.DefaultStackTraceExtractor{}.GetStackTrace(report.StackSkip),
			},
		},
	}

	_ = r.client.Enqueue(exception)
}

func classifyExceptionType(err error, msg string) string {
	if err == nil {
		if msg == "" {
			return "Error"
		}
		return msg
	}

	t := reflect.TypeOf(err)
	if t == nil {
		return "error"
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Name() != "" {
		return t.Name()
	}
	return t.String()
}

func classifyExceptionValue(err error, msg string) string {
	if err != nil {
		return err.Error()
	}
	if msg != "" {
		return msg
	}
	return "error"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
