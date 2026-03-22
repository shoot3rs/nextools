package nextools

import (
	"os"
	"strings"
)

// Env represents the deployment environment.
type Env string

const (
	EnvDevelopment Env = "development"
	EnvTesting     Env = "testing"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

// EnvFromString normalizes a raw string into a known Env value.
func EnvFromString(raw string) Env {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(EnvTesting):
		return EnvTesting
	case string(EnvProduction):
		return EnvProduction
	case string(EnvStaging):
		return EnvStaging
	default:
		return EnvDevelopment
	}
}

// DetectAppEnv reads APP.ENV via the provided lookup (or os.Getenv by default).
// Acceptable values are "development", "testing", "staging", "production".
func DetectAppEnv(envLookup func(string) string) Env {
	if envLookup == nil {
		envLookup = os.Getenv
	}
	return EnvFromString(envLookup("APP.ENV"))
}
