# nextools Builder Guide

`nextools` exposes reusable helpers for the Charmm tech stack. Beyond the `.Config`/`.Database` option functions, the remainder of the package now follows the same builder mindset so your services only have to wire up what they really care about. The package currently offers builders for configuration, logging, authentication, middleware, context helpers, database wiring, and error reporting so you can keep every cross-cutting concern in one place.

## Key builders

| Builder | Purpose |
| --- | --- |
| `nextools.NewLoggerBuilder()` | Configure service name, version, env, level, output, and caller skip before calling `.Build()`. |
| `nextools.NewAuthenticatorBuilder()` | Override issuer URL, realm, client ID, HTTP client, TLS config, or request timeout before `.Build()` returns the familiar `Authenticator`. |
| `nextools.NewMiddlewareBuilder()` | Plug in `Authenticator`, `LoggerClient`, `ContextHelper`, and optionally an `ErrorReporter` once and produce request middleware. |

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
```

## Tips

* Builders retain sensible defaults (e.g., the logger looks up `APP.NAME`/`APP.VERSION`, the authenticator uses `AUTH.*` env vars, and middleware just wires the dependencies you supply).
* Each builder is chainable so you can read values from flags, environment, or runtime discovery and decide what to override.
* If you already have a `Config` struct, the logger builder exposes `WithConfig(config)` to seed the builder.
* Error reporting uses dotted env vars such as `ERROR.REPORTING_PROVIDER`, `SENTRY.DSN`, and `POSTHOG.PROJECT_TOKEN`.

This README is the single source when getting started with the `nextools` helpers.

## Config builder

`nextools.NewConfig()` merges explicit overrides with the process env before exposing strongly typed helpers for HTTP/2, JetStream, Redis, validators, and the GORM config that the database builder consumes. Use the `With…` helpers to inject custom clients or override env values.

```go
cfg := nextools.NewConfig(
    nextools.WithEnvValue("APP.NAME", "catalog"),
    nextools.WithEnvValue("APP.VERSION", "release-42"),
    nextools.WithHttpClient(customClient),
    nextools.WithHttp2Server(customHTTP2),
    nextools.WithRedisOptions(redisOptions),
    nextools.WithJetStreamConfig(streamConfig),
    nextools.WithValidator(customValidator),
    nextools.WithGormConfig(gormConfig),
)
```

The builder also exposes `WithEnvLookup` for test fakes, `WithEnvValues` for bulk overrides, and `WithEnvValue` for per-key overrides, so you can reuse the same config helper across services without duplicating environment parsing logic.

## Logger builder

`nextools.NewLoggerBuilder()` exposes fluent setters for the service name, version, environment, level, output writer, ANSI switching, caller skip, and error reporter. The builder seeds from `APP.NAME`, `APP.VERSION`, and `APP.ENV` automatically.

```go
import "os"

logger := nextools.NewLoggerBuilder().
    WithService("billing").
    WithVersion("v2.3.0").
    WithEnv(nextools.EnvProduction).
    WithLevel(nextools.LevelInfo).
    WithOutput(os.Stdout).
    WithNoColor(true).
    Build()
```

The logger always emits the production log structure and can forward error-level events to an `ErrorReporter`. Call `defer logger.Close()` in service entrypoints so buffered reporters such as Sentry/PostHog can flush on shutdown.

```go
reporter := nextools.NewErrorReporterFromEnv("billing", "v2.3.0", "production")

logger := nextools.NewLoggerBuilder().
    WithService("billing").
    WithVersion("v2.3.0").
    WithEnv(nextools.EnvProduction).
    WithErrorReporter(reporter).
    Build()

defer logger.Close()
```

## Error reporting

`nextools` supports pluggable error reporting behind a shared interface:

```go
type ErrorReporter interface {
    Capture(context.Context, ErrorReport)
    Close() error
}
```

Built-in providers:

* `posthog`
* `sentry`
* `none` / `noop`

The default logger builder resolves the reporter from environment through `nextools.NewErrorReporterFromEnv(...)`.

### Provider selection

Use the dotted env vars below:

* `ERROR.REPORTING_PROVIDER=posthog`
* `ERROR.REPORTING_PROVIDER=sentry`
* `ERROR.REPORTING_PROVIDER=none`

Sentry config:

* `SENTRY.DSN`
* `SENTRY.DEBUG`
* `SENTRY.SEND_DEFAULT_PII`

PostHog config:

* `POSTHOG.PROJECT_TOKEN`
* `POSTHOG.PROJECT_API_KEY`
* `POSTHOG.API_KEY`
* `POSTHOG.ENDPOINT`
* `POSTHOG.HOST`
* `POSTHOG.DISTINCT_ID`

### Capture model

`nextools` intentionally splits error capture into two paths:

* Logger-backed capture for non-request errors such as startup failures, worker failures, DB/NATS/Temporal issues, and explicit `logger.Error(...)` calls.
* Middleware-backed capture for request-scoped failures so RPC metadata can be attached.

This is why the reporter is not implemented as middleware alone. Middleware only sees request flow, while many service failures happen outside request handling.

### Swapping providers

If you want to swap PostHog for Sentry, or add another backend later, keep the service wiring the same and provide a different `ErrorReporter`.

```go
logger := nextools.NewLoggerBuilder().
    WithService("billing").
    WithVersion("v2.3.0").
    WithErrorReporter(nextools.NewSentryReporterFromEnv("billing", "v2.3.0", "production")).
    Build()
```

## Authenticator builder

`nextools.NewAuthenticator()` uses `AUTH.URL`, `AUTH.REALM`, and `AUTH.CLIENT_ID` from the environment but can be customized via options for issuer, realm, client ID, timeout, TLS config, or HTTP client.

```go
import "time"

authenticator, err := nextools.NewAuthenticator(
    nextools.WithAuthenticatorIssuer("https://auth.example.com"),
    nextools.WithAuthenticatorRealm("char_mm"),
    nextools.WithAuthenticatorClientID("nextools"),
    nextools.WithAuthenticatorTimeout(3*time.Second),
)
if err != nil {
    log.Fatal(err)
}
```

The returned `Authenticator` exposes middleware helpers (`ValidateTokenMiddleware`, `ExtractToken`, etc.) and an `oidc.IDTokenVerifier` so downstream services can uniformly secure gRPC handlers.

## Middleware builder

Build middleware once and reuse it across HTTP/gRPC handlers. Provide the configured `Authenticator`, `LoggerClient`, and `ContextHelper` to `nextools.NewMiddlewareBuilder()`. If the logger is a `nextools.Logger`, the middleware builder automatically reuses the logger's configured `ErrorReporter`. You can also override it explicitly.

```go
middleware := nextools.NewMiddlewareBuilder().
    WithAuthenticator(authenticator).
    WithLogger(logger).
    WithContextHelper(ctxHelper).
    Build()

authInterceptor := middleware.UnaryTokenInterceptor()
tenantInterceptor := middleware.TenantHeaderInterceptor()
loggingInterceptor := middleware.UnaryLoggingInterceptor()
corsHandler := middleware.CorsMiddleware(serverMux)
```

The builder also returns `UnaryTenantMismatchInterceptor`, `UnaryLoggingInterceptor`, and you can swap the `ContextHelper` if you want different tenant extraction logic.

For request failures, `UnaryLoggingInterceptor()` reports the exception through the configured `ErrorReporter` first, then logs it, marking the log path to avoid duplicate external reporting.

## Context helper

`ContextHelper` exposes helpers for pulling tenant IDs, supplier/influencer headers, tokens, and the parsed `Claims` struct from contexts or gRPC requests.

```go
claims := ctxHelper.GetUserClaims(ctx)
if claims.HasRole("admin") {
    // ...
}
tenantCountry, tenantState := ctxHelper.GetTenant(ctx)
```

Use `nextools.NewContextHelper(authenticator)` when you only need the defaults, or leverage `NewContextHelperBuilder()` if you want to force a different authenticator.

## Database builder

`nextools.NewDatabase(cfg.Gorm(), opts...)` wires GORM with retries, migrations, indexes, views, seeders, sequences, and PostGIS helpers. Options include:

* `WithModels(...)` – the models that are automatically `AutoMigrate`d and evaluated by seeding/view helpers.
* `WithDialect`, `WithSqlitePath`, `WithPostgresDSN` – override how the engine connects.
* `WithLogger` – log lifecycle events to your `LoggerClient`.
* `WithMaxRetries`, `WithBackoffStrategy` – tune connect retries.
* `WithSequenceName`, `WithIndexHook`, `EnablePostGIS` – infrastructure helpers.
* `WithSeeders`/`WithSeedCheckModels` and `WithViewBuilder` – seeding/view wiring.

Call `db.Connect()` once the options are configured; the engine retries connections, auto migrates your models, runs index hooks, and then executes view builders before seeding so production data is preserved.

### Seeding

The `gorm` builder in `nextools` can now run a `gorm_seeder` stack automatically after migrations finish. Supply the seeder factory and the models it targets, and the engine will only seed when those tables are still empty (so production databases that already contain data stay untouched).

```go
import gorm_seeder "github.com/kachit/gorm-seeder"

usersSeeder := seeders.NewUsersSeeder(gorm_seeder.SeederConfiguration{Rows: 10})

seederFactory := func(engine *gorm.DB) *gorm_seeder.SeedersStack {
    stack := gorm_seeder.NewSeedersStack(engine)
    stack.AddSeeder(&usersSeeder)
    return stack
}

db := nextools.NewDatabase(
    cfg.Gorm(),
    nextools.WithLogger(logger),
    nextools.WithModels(&models.User{}),
    nextools.WithSeeders(seederFactory, &models.User{}),
)
```

If you prefer to keep the seeder model list separate from `WithSeeders`, use `nextools.WithSeedCheckModels` to declare which tables should remain empty before the seed stack runs. The seeder factory itself can build any stack of `gorm_seeder.SeederInterface` implementations.

### Views

Register view builders with `nextools.WithViewBuilder` to keep the SQL that backs views close to the rest of your schema wiring. Each builder runs after migrations (but before seeding) and receives the fully initialized engine so it can honor sqlite vs postgres-specific options:

```go
import "gorm.io/gorm"

func inventorySummary(engine *gorm.DB) error {
    viewOption := gorm.ViewOption{}
    if dbType := engine.Dialector.Name(); dbType != "sqlite" {
        viewOption.Replace = true
    }
    viewOption.Query = engine.
        Model(&models.InventoryEvent{}).
        Select("... your aggregate ...")

    return engine.Migrator().CreateView("inventory_summary", viewOption)
}

db := nextools.NewDatabase(
    cfg.Gorm(),
    nextools.WithLogger(logger),
    nextools.WithModels(&models.InventoryEvent{}),
    nextools.WithViewBuilder(inventorySummary),
)
```

Multiple builders can be registered and will all execute when `CreateViews` runs automatically. You can also call `db.CreateViews()` manually if you need to manage view creation outside of `Connect()`.
