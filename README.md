# nextools Builder Guide

`nextools` exposes reusable helpers for the Charmm tech stack. Beyond the `.Config`/`.Database` option functions, the remainder of the package now follows the same builder mindset so your services only have to wire up what they really care about.

## Key builders

| Builder | Purpose |
| --- | --- |
| `nextools.NewLoggerBuilder()` | Configure service name, version, env, level, output, and caller skip before calling `.Build()`. |
| `nextools.NewAuthenticatorBuilder()` | Override issuer URL, realm, client ID, HTTP client, TLS config, or request timeout before `.Build()` returns the familiar `Authenticator`. |
| `nextools.NewMiddlewareBuilder()` | Plug in `Authenticator`, `LoggerClient`, and `ContextHelper` once and produce either `Middleware` or `SSEMiddleware`. |

The builder helpers complement the existing option sets (e.g., `nextools.WithEnvValue`, `nextools.WithModels`, `nextools.WithConfig`).

## Sample wiring

```go
cfg := nextools.NewConfig(
    nextools.WithEnvValue("APP.NAME", "billing"),
    nextools.WithEnvValue("APP.VERSION", "v1.2.0"),
)

logger := nextools.NewLoggerBuilder().
    WithService("billing").
    WithVersion("v1.2.0").
    WithLevel(nextools.LevelInfo).
    Build()

authenticator, err := nextools.NewAuthenticator(
    nextools.WithAuthenticatorIssuer("https://auth.example.com"),
    nextools.WithAuthenticatorRealm("char_mm"),
)
if err != nil {
    log.Fatal(err)
}

ctxHelper := nextools.NewContextHelper(authenticator)
middleware := nextools.NewMiddlewareBuilder().
    WithAuthenticator(authenticator).
    WithLogger(logger).
    WithContextHelper(ctxHelper).
    Build()

sse := nextools.NewMiddlewareBuilder().
    WithAuthenticator(authenticator).
    WithLogger(logger).
    WithContextHelper(ctxHelper).
    BuildSSE()
```

## Tips

* Builders retain sensible defaults (e.g., the logger looks up `APP.NAME`/`APP.VERSION`, the authenticator uses `AUTH.*` env vars, and middleware just wires the dependencies you supply).
* Each builder is chainable so you can read values from flags, environment, or runtime discovery and decide what to override.
* If you already have a `Config` struct, the logger builder exposes `WithConfig(config)` to seed the builder.

This README is the single source when getting started with the `nextools` helpers.
