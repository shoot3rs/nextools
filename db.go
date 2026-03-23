// Package nextools provides reusable database helpers for the Charmm tech stack.
// It wraps GORM with support for SQLite and PostgreSQL, automatic migrations,
// view creation, seeding, and retry logic with configurable backoff strategies.
package nextools

import (
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	gorm_seeder "github.com/kachit/gorm-seeder"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// gormDB is the internal implementation of DBConnection that manages database
// connections, migrations, seeding, and view creation. It supports both SQLite
// and PostgreSQL dialects with configurable retry logic and lifecycle hooks.
type gormDB struct {
	dbType          string
	engine          *gorm.DB
	config          *gorm.Config
	models          []interface{}
	overrideDialect string
	sqlitePath      string
	postgresDSN     string
	maxRetries      int
	backoff         RetryBackoff
	sequenceName    string
	indexHooks      []IndexHook
	viewBuilders    []ViewBuilder
	seederFactory   SeederFactory
	seedCheckModels []interface{}
	logger          LoggerClient
}

const (
	// defaultSequenceName is the name used for the PostgreSQL sequence when none is specified.
	defaultSequenceName = "code_seq"
	// defaultMaxRetries is the number of connection attempts before giving up.
	defaultMaxRetries = 5
)

type (
	// DatabaseOption alters the gormDB before use.
	DatabaseOption func(*gormDB)

	// IndexHook can create DB-specific constraints after migrations run.
	IndexHook func(*gorm.DB) error

	// RetryBackoff determines the duration between retry attempts.
	RetryBackoff func(attempt int) time.Duration

	// SeederFactory builds the gorm_seeder stack once the engine is ready.
	SeederFactory func(*gorm.DB) *gorm_seeder.SeedersStack

	// ViewBuilder constructs schema views once the engine is ready.
	ViewBuilder func(*gorm.DB) error
)

// WithModels registers models that will be automatically migrated.
func WithModels(models ...interface{}) DatabaseOption {
	return func(db *gormDB) {
		db.models = append(db.models, models...)
	}
}

// WithDialect forces a specific dialect (sqlite/postgres) instead of reading DB.TYPE.
func WithDialect(dialect string) DatabaseOption {
	return func(db *gormDB) {
		db.overrideDialect = dialect
	}
}

// WithSqlitePath overrides the sqlite file that will be opened.
func WithSqlitePath(path string) DatabaseOption {
	return func(db *gormDB) {
		if path != "" {
			db.sqlitePath = path
			db.overrideDialect = "sqlite"
		}
	}
}

// WithPostgresDSN overrides how the postgres connection string is built.
func WithPostgresDSN(dsn string) DatabaseOption {
	return func(db *gormDB) {
		db.postgresDSN = dsn
	}
}

// WithLogger writes Connect lifecycle logs through the supplied logger instance.
func WithLogger(logger LoggerClient) DatabaseOption {
	return func(db *gormDB) {
		db.logger = logger
	}
}

// WithMaxRetries changes how many attempts Connect performs before giving up.
func WithMaxRetries(retries int) DatabaseOption {
	return func(db *gormDB) {
		if retries > 0 {
			db.maxRetries = retries
		}
	}
}

// WithBackoffStrategy customizes the retry backoff calculator.
func WithBackoffStrategy(backoff RetryBackoff) DatabaseOption {
	return func(db *gormDB) {
		if backoff != nil {
			db.backoff = backoff
		}
	}
}

// WithSequenceName changes the name of the sequence that will be created for Postgres.
func WithSequenceName(name string) DatabaseOption {
	return func(db *gormDB) {
		if name != "" {
			db.sequenceName = name
		}
	}
}

// WithIndexHook registers a callback that will run after migrations finish.
func WithIndexHook(hook IndexHook) DatabaseOption {
	return func(db *gormDB) {
		if hook != nil {
			db.indexHooks = append(db.indexHooks, hook)
		}
	}
}

// WithViewBuilder registers a callback that can create materialized or standard views after migrations.
func WithViewBuilder(builder ViewBuilder) DatabaseOption {
	return func(db *gormDB) {
		if builder != nil {
			db.viewBuilders = append(db.viewBuilders, builder)
		}
	}
}

// WithSeeders wires a factory that builds the seeder stack and optionally tracks which models should be empty before seeding.
func WithSeeders(factory SeederFactory, models ...interface{}) DatabaseOption {
	return func(db *gormDB) {
		if factory != nil {
			db.seederFactory = factory
		}
		if len(models) > 0 {
			db.seedCheckModels = append(db.seedCheckModels, models...)
		}
	}
}

// WithSeedCheckModels tells the database which models should be empty before running the seeder stack.
func WithSeedCheckModels(models ...interface{}) DatabaseOption {
	return func(db *gormDB) {
		if len(models) > 0 {
			db.seedCheckModels = append(db.seedCheckModels, models...)
		}
	}
}

// defaultBackoff calculates retry delay using a quadratic backoff strategy.
// The delay increases with each attempt: 1s, 4s, 9s, 16s, etc.
func defaultBackoff(attempt int) time.Duration {
	attempt++ // make backoff 1-indexed
	return time.Duration(math.Pow(float64(attempt), 2)) * time.Second
}

// EnablePostGIS creates the PostGIS extension in PostgreSQL databases.
// It is a no-op for other database dialects.
func (db *gormDB) EnablePostGIS() error {
	if db.engine.Dialector.Name() != "postgres" {
		return nil
	}

	return db.engine.Exec(`CREATE EXTENSION IF NOT EXISTS postgis;`).Error
}

// CreateIndexes executes all registered index hooks to create database-specific
// constraints and indexes after migrations complete.
func (db *gormDB) CreateIndexes() {
	for _, hook := range db.indexHooks {
		if err := hook(db.engine); err != nil {
			db.logf(LevelWarn, "[🧨] failed to run index hook: %v [🧨]", err)
		}
	}

	db.logger.OK("👌 Indexes created successfully! 👌")
}

// GetEngine returns the underlying GORM database engine as an interface{}.
// Cast to *gorm.DB to access GORM-specific methods.
func (db *gormDB) GetEngine() interface{} {
	return db.engine
}

// GetConfig returns the GORM configuration used by this database connection.
func (db *gormDB) GetConfig() *gorm.Config {
	return db.config
}

// Connect establishes the database connection with retry logic, runs migrations,
// creates views, and applies seeds. It configures connection pooling and exits
// the process if the database cannot be reached after max retries.
func (db *gormDB) Connect() {
	db.dbType = strings.ToLower(strings.TrimSpace(db.overrideDialect))
	if db.dbType == "" {
		db.dbType = strings.ToLower(strings.TrimSpace(os.Getenv("DB.TYPE")))
	}

	if db.dbType == "" {
		db.logf(LevelFatal, "[🧨] unable to determine DB.TYPE [🧨]")
		os.Exit(1)
	}

	db.logf(LevelInfo, "⚡ Loading db config for: %s ⚡", db.dbType)

	if db.maxRetries <= 0 {
		db.maxRetries = defaultMaxRetries
	}
	if db.backoff == nil {
		db.backoff = defaultBackoff
	}

	var (
		err      error
		attempts int
	)

	for {
		db.engine, err = db.defaultDialector()
		if err == nil {
			break
		}

		attempts++
		if attempts >= db.maxRetries {
			db.logf(LevelFatal, "[🧨] unable to connect to %s database: %v [🧨]", db.dbType, err)
			os.Exit(1)
		}

		wait := db.backoff(attempts)
		db.logf(LevelWarn, "[🧨] database is not ready, retrying in %s: %v [🧨]", wait, err)
		time.Sleep(wait)
	}

	sqlDB, _ := db.engine.DB()
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour * 8765)

	if err := sqlDB.Ping(); err != nil {
		db.logf(LevelWarn, "[🧨] error pinging database! [🧨]")
	}

	if err := db.handleMigrations(); err != nil {
		db.logf(LevelFatal, "database migrations failed: %v", err)
		log.Fatal(err)
	}

	db.CreateViews()

	db.applySeeds()
}

// loadSqliteDB creates a GORM connection to a SQLite database file.
// The file path defaults to <DB.NAME>.db if not overridden via WithSqlitePath.
func (db *gormDB) loadSqliteDB() (*gorm.DB, error) {
	path := db.sqlitePath
	if path == "" {
		path = fmt.Sprintf("%s.db", os.Getenv("DB.NAME"))
	}

	conn, err := gorm.Open(sqlite.Open(path), db.GetConfig())

	if err != nil {
		db.logf(LevelError, "[🧨] failed to connect db: %v [🧨]", err)
		return nil, err
	}
	db.logf(LevelInfo, "👌Connection to sqlite established successfully! 👌")

	return conn, nil
}

// loadPostgresDB creates a GORM connection to a PostgreSQL database.
// The DSN is built from DB.* environment variables unless overridden via WithPostgresDSN.
func (db *gormDB) loadPostgresDB() (*gorm.DB, error) {
	dsn := db.postgresDSN
	if dsn == "" {
		dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s",
			os.Getenv("DB.HOST"),
			os.Getenv("DB.USER"),
			os.Getenv("DB.PASS"),
			os.Getenv("DB.NAME"),
			os.Getenv("DB.PORT"),
		)
	}

	return gorm.Open(postgres.Open(dsn), db.GetConfig())
}

// defaultDialector selects and initializes the appropriate GORM dialector
// based on the configured database type (sqlite or postgres).
func (db *gormDB) defaultDialector() (*gorm.DB, error) {
	switch db.dbType {
	case "sqlite":
		return db.loadSqliteDB()
	case "postgres":
		return db.loadPostgresDB()
	default:
		return nil, fmt.Errorf("unsupported database dialect %q", db.dbType)
	}
}

// CreateSequence creates a PostgreSQL sequence with the configured name.
// The sequence name defaults to "code_seq" if not specified via WithSequenceName.
func (db *gormDB) CreateSequence() error {
	seqName := db.sequenceName
	if seqName == "" {
		seqName = defaultSequenceName
	}

	query := fmt.Sprintf("CREATE SEQUENCE IF NOT EXISTS %s", seqName)
	if err := db.engine.Exec(query).Error; err != nil {
		db.logf(LevelWarn, "[🧨] failed to create sequence %s: %v [🧨]", seqName, err)
		return err
	}

	db.logf(LevelInfo, "👌 Sequence %s created successfully! 👌", seqName)
	return nil
}

// handleMigrations runs GORM AutoMigrate on all registered models to synchronize
// the database schema with the application's model definitions.
func (db *gormDB) handleMigrations() error {
	dialector := db.engine.Dialector.Name()
	db.logf(LevelInfo, "[👷] Dialector: %s [👷]", dialector)

	if err := db.engine.AutoMigrate(db.models...); err != nil {
		db.logf(LevelError, "[🧨] failed to auto migrate: %v [🧨]", err)
		return fmt.Errorf("auto migrate failed: %w", err)
	}

	db.logf(LevelInfo, "👌database migrations was successful! 👌")
	return nil
}

// CreateViews executes all registered view builders.
func (db *gormDB) CreateViews() {
	if len(db.viewBuilders) == 0 {
		return
	}

	created := false
	for _, builder := range db.viewBuilders {
		if builder == nil {
			continue
		}
		if err := builder(db.engine); err != nil {
			db.logf(LevelWarn, "[🧨] failed to create view: %v [🧨]", err)
			continue
		}
		created = true
	}

	if created {
		db.logf(LevelInfo, "👌 database views created successfully! 👌")
	}
}

// applySeeds runs the configured seeder stack if all target tables are empty.
// This ensures production databases with existing data are never accidentally seeded.
func (db *gormDB) applySeeds() {
	if db.seederFactory == nil {
		return
	}

	targets := db.seedCheckModels
	if len(targets) == 0 {
		targets = db.models
	}
	if len(targets) == 0 {
		db.logf(LevelWarn, "[🧨] no seed models configured; skipping seeding [🧨]")
		return
	}

	if !db.tablesEmpty(targets) {
		db.logf(LevelInfo, "ℹ️ seed tables contain data; skipping seeding")
		return
	}

	stack := db.seederFactory(db.engine)
	if stack == nil {
		db.logf(LevelWarn, "[🧨] seeder factory returned nil stack; skipping seeding [🧨]")
		return
	}

	if err := stack.Seed(); err != nil {
		db.logf(LevelError, "[🧨] seeding failed: %v [🧨]", err)
		return
	}

	db.logf(LevelInfo, "👌 database seeded successfully! 👌")
}

// tablesEmpty checks whether all tables for the given models have zero rows.
// It returns false if any table contains data or if a count query fails.
func (db *gormDB) tablesEmpty(models []interface{}) bool {
	for _, model := range models {
		if model == nil {
			continue
		}
		var count int64
		if err := db.engine.Model(model).Count(&count).Error; err != nil {
			db.logf(LevelWarn, "[🧨] failed to count rows for seeding check: %v [🧨]", err)
			return false
		}
		if count > 0 {
			db.logf(LevelInfo, "ℹ️ table for model %T already has %d rows", model, count)
			return false
		}
	}
	return true
}

// logf writes a formatted log message at the specified level using the configured
// logger, or falls back to standard log.Println if no logger is set.
func (db *gormDB) logf(level Level, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if db.logger != nil {
		db.logger.Log(level, message)
		return
	}
	log.Println(message)
}

// NewDatabase creates a new DBConnection with the given GORM config and options.
// Call Connect() on the returned instance to establish the database connection,
// run migrations, create views, and apply seeds.
func NewDatabase(cfg *gorm.Config, opts ...DatabaseOption) DBConnection {
	db := &gormDB{
		config:       cfg,
		models:       []interface{}{},
		maxRetries:   defaultMaxRetries,
		backoff:      defaultBackoff,
		sequenceName: defaultSequenceName,
	}

	for _, opt := range opts {
		opt(db)
	}

	return db
}
