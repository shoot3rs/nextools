package nextools

import (
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

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
	logger          LoggerClient
}

const (
	defaultSequenceName = "code_seq"
	defaultMaxRetries   = 5
)

type (
	// DatabaseOption alters the gormDB before use.
	DatabaseOption func(*gormDB)

	// IndexHook can create DB-specific constraints after migrations run.
	IndexHook func(*gorm.DB) error

	// RetryBackoff determines the duration between retry attempts.
	RetryBackoff func(attempt int) time.Duration
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

func defaultBackoff(attempt int) time.Duration {
	attempt++ // make backoff 1-indexed
	return time.Duration(math.Pow(float64(attempt), 2)) * time.Second
}

func (db *gormDB) EnablePostGIS() error {
	if db.engine.Dialector.Name() != "postgres" {
		return nil
	}

	return db.engine.Exec(`CREATE EXTENSION IF NOT EXISTS postgis;`).Error
}

func (db *gormDB) CreateIndexes() {
	for _, hook := range db.indexHooks {
		if err := hook(db.engine); err != nil {
			db.logf(LevelWarn, "[🧨] failed to run index hook: %v [🧨]", err)
		}
	}

	db.logger.OK("👌 Indexes created successfully! 👌")
}

func (db *gormDB) GetEngine() interface{} {
	return db.engine
}

func (db *gormDB) GetConfig() *gorm.Config {
	return db.config
}

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

	if db.dbType != "sqlite" {
		if err := db.CreateSequence(); err != nil {
			db.logf(LevelWarn, "[🧨] unable to create sequence: %v [🧨]", err)
		}
	}

	if err := db.EnablePostGIS(); err != nil {
		db.logf(LevelFatal, "failed to enable PostGIS: %v", err)
		log.Fatal(err)
	}

	if err := db.handleMigrations(); err != nil {
		db.logf(LevelFatal, "database migrations failed: %v", err)
		log.Fatal(err)
	}

	db.CreateIndexes()
}

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

func (db *gormDB) logf(level Level, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if db.logger != nil {
		db.logger.Log(level, message)
		return
	}
	log.Println(message)
}

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
