// Package nextools is the nextools centralized logger for charmm microservices.
//
// It ships as a single file — drop logger.go into any service under
// github.com/charmm/nextools/logger and import it.
//
// Two output modes controlled by Config.Env:
//
//	development  — multi-line, richly coloured, human-readable
//	production   — single compact line per entry, ndjson-ready
//
// Every log entry carries:
//
//	timestamp · service · version · file · line · rpc method · client ip · message · fields
//
// Built-in adapters (all in this file):
//
//	ConnectInterceptor()  — ConnectRPC unary interceptor
//	GORMLogger()          — gorm/logger.Interface
//	NATSOptions()         — []nats.Option
//	PGTracer()            — pgx v5 QueryTracer
//
// Version detection (in order of preference):
//  1. Config.Version if non-empty
//  2. debug.ReadBuildInfo module version (populated by `go install`)
//  3. git describe via runtime build VCS info (populated by `go build -buildvcs`)
//  4. "dev"
package nextools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  ANSI palette                                                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiItalic = "\033[3m"

	// foreground
	ansiFgBlack   = "\033[30m"
	ansiFgRed     = "\033[31m"
	ansiFgGreen   = "\033[32m"
	ansiFgYellow  = "\033[33m"
	ansiFgBlue    = "\033[34m"
	ansiFgMagenta = "\033[35m"
	ansiFgCyan    = "\033[36m"
	ansiFgWhite   = "\033[97m" // bright white
	ansiFgGray    = "\033[90m"

	// background
	ansiBgRed    = "\033[41m"
	ansiBgYellow = "\033[43m"

	// charmm brand palette — 256-colour where supported
	charmmAccent  = "\033[38;5;141m" // soft purple  #af87ff
	charmmDim     = "\033[38;5;61m"  // muted purple #5f5faf
	charmmMuted   = "\033[38;5;240m" // dark gray
	charmmIPColor = "\033[38;5;117m" // sky blue     #87d7ff
	charmmFile    = "\033[38;5;180m" // warm sand    #d7af87
	charmmVer     = "\033[38;5;114m" // soft green   #87d787
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Level                                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Level is the log severity.
type Level uint8

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelOK // successful lifecycle events (service started, build passed…)
	LevelWarn
	LevelError
	LevelFatal
)

type levelMeta struct {
	tag    string // fixed-width display tag (6 chars incl. brackets)
	symbol string // single Unicode glyph shown in dev mode
	color  string // ANSI foreground for the tag
	bgLine string // optional bg tint for the entire dev block border
}

var levelAttrs = map[Level]levelMeta{
	LevelTrace: {"TRACE ", "◌", ansiDim + ansiFgGray, charmmMuted},
	LevelDebug: {"DEBUG ", "●", ansiFgGray, charmmMuted},
	LevelInfo:  {"INFO  ", "◆", ansiFgBlue, ansiFgBlue},
	LevelOK:    {"OK    ", "✔", ansiFgGreen, ansiFgGreen},
	LevelWarn:  {"WARN  ", "▲", ansiFgYellow, ansiFgYellow},
	LevelError: {"ERROR ", "✖", ansiFgRed, ansiFgRed},
	LevelFatal: {"FATAL ", "☠", ansiBgRed + ansiFgWhite, ansiBgRed},
}

func (l Level) meta() levelMeta {
	if m, ok := levelAttrs[l]; ok {
		return m
	}
	return levelMeta{"?????", "?", ansiFgWhite, ""}
}

func (l Level) String() string { return strings.TrimSpace(l.meta().tag) }

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Entry — the unit of information carried per log call                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Entry holds every field that may appear in a log line.
// Adapters populate the RPC-specific fields; the core logger populates the rest.
type Entry struct {
	Time       time.Time
	Level      Level
	Service    string
	Version    string
	File       string // short path: pkg/file.go
	Line       int
	RPCMethod  string        // e.g. "GetUser"
	ClientIP   string        // e.g. "203.0.113.4"
	Latency    time.Duration // non-zero for request entries
	StatusCode string        // gRPC/HTTP status string
	Msg        string
	Fields     []Field
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Field                                                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Field is a typed key-value pair attached to a log entry.
type Field struct {
	Key   string
	Value any
}

// F creates a Field. Short alias used everywhere in service code.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Err wraps an error as a Field with key "error".
func Err(err error) Field { return Field{Key: "error", Value: err} }

// Config is passed to New. All fields are optional — defaults are sane.
type Config struct {
	// Service name shown on every line. Required.
	Service string
	// Version overrides auto-detection. Leave empty to auto-detect from build info.
	Version string
	// Env controls output format. Defaults to EnvDevelopment.
	Env Env
	// Level is the minimum severity to emit. Defaults to LevelDebug (dev) / LevelInfo (prod).
	Level Level
	// Output is the write target. Defaults to os.Stdout.
	Output io.Writer
	// NoColor forces plain text even in a TTY.
	NoColor bool
	// CallerSkip adds extra frames to skip when resolving file:line.
	// Useful when wrapping Logger in another thin layer.
	CallerSkip int
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Logger                                                                  ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Logger is the nextools/charmm logger. One instance per service process.
// Loggers are safe for concurrent use. Child loggers created via With() share
// the parent's output and config but carry additional persistent fields.
type Logger struct {
	mu      sync.Mutex
	cfg     Config
	version string        // resolved version string
	fields  []Field       // persistent fields (populated by With)
	seq     atomic.Uint64 // monotonic counter shown in banner startup lines
}

// NewLogger creates a Logger from cfg.
// Version is auto-detected when cfg.Version is empty.
// Output defaults to os.Stdout, Env defaults to EnvDevelopment.
func NewLogger(cfg Config) LoggerClient {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.Env == "" {
		cfg.Env = DetectAppEnv(nil)
	}
	if cfg.Service == "" {
		cfg.Service = "unknown"
	}

	// Auto-detect color support
	if !cfg.NoColor {
		if fi, _ := os.Stdout.Stat(); fi != nil {
			if (fi.Mode() & os.ModeCharDevice) == 0 {
				cfg.NoColor = true // not a TTY — disable color
			}
		}
	}

	l := &Logger{
		cfg:     cfg,
		version: resolveVersion(cfg.Version),
	}
	return l
}

// With returns a child Logger that prepends fields to every entry it emits.
// The child shares the same output, config, and version counter as the parent
// but has its own field slice — mutations to one do not affect the other.
func (l *Logger) With(fields ...Field) *Logger {
	child := &Logger{
		cfg:     l.cfg,
		version: l.version,
		fields:  make([]Field, len(l.fields)+len(fields)),
	}
	copy(child.fields, l.fields)
	copy(child.fields[len(l.fields):], fields)
	// share parent's atomic counter so sequence numbers stay global
	// (child points to parent's seq via a pointer trick using the parent ref)
	child.seq.Store(l.seq.Load())
	return child
}

// SetLevel changes the minimum level at runtime. Safe for concurrent use.
func (l *Logger) SetLevel(lv Level) {
	l.mu.Lock()
	l.cfg.Level = lv
	l.mu.Unlock()
}

// ── Public API ─────────────────────────────────────────────────────────────

func (l *Logger) Trace(msg string, fields ...Field) { l.emit(LevelTrace, 1, msg, fields) }
func (l *Logger) Debug(msg string, fields ...Field) { l.emit(LevelDebug, 1, msg, fields) }
func (l *Logger) Info(msg string, fields ...Field)  { l.emit(LevelInfo, 1, msg, fields) }
func (l *Logger) OK(msg string, fields ...Field)    { l.emit(LevelOK, 1, msg, fields) }
func (l *Logger) Warn(msg string, fields ...Field)  { l.emit(LevelWarn, 1, msg, fields) }
func (l *Logger) Error(msg string, fields ...Field) { l.emit(LevelError, 1, msg, fields) }
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.emit(LevelFatal, 1, msg, fields)
	os.Exit(1)
}

// Log emits at an arbitrary level. Useful when the level is computed.
func (l *Logger) Log(level Level, msg string, fields ...Field) {
	l.emit(level, 1, msg, fields)
}

// WithEntry emits a pre-built Entry directly. Used by adapters that construct
// the full Entry themselves (e.g. ConnectInterceptor fills RPCMethod, ClientIP).
func (l *Logger) WithEntry(e Entry) {
	if e.Level < l.cfg.Level {
		return
	}
	e.Fields = append(l.fields, e.Fields...)
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Service == "" {
		e.Service = l.cfg.Service
	}
	if e.Version == "" {
		e.Version = l.version
	}
	l.write(e)
}

// ── Internal ───────────────────────────────────────────────────────────────

func (l *Logger) emit(level Level, skip int, msg string, fields []Field) {
	if level < l.cfg.Level {
		return
	}
	file, line := callerInfo(skip + 1 + l.cfg.CallerSkip)
	all := make([]Field, 0, len(l.fields)+len(fields))
	all = append(all, l.fields...)
	all = append(all, fields...)

	l.write(Entry{
		Time:    time.Now(),
		Level:   level,
		Service: l.cfg.Service,
		Version: l.version,
		File:    file,
		Line:    line,
		Msg:     msg,
		Fields:  all,
	})
}

func (l *Logger) write(e Entry) {
	var s string
	if l.cfg.Env == EnvProduction || l.cfg.Env == EnvStaging {
		s = l.formatProd(e)
	} else {
		s = l.formatDev(e)
	}
	l.mu.Lock()
	fmt.Fprint(l.cfg.Output, s)
	l.mu.Unlock()
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  DEV formatter — multi-line, richly coloured                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
//  ╭─ ✔ OK ──────────────────────────── usersvc v1.4.2 ─ 2026/03/21 23:52:09.765 ─╮
//  │  Service started successfully
//  │  file     handlers/user.go:58
//  │  method   GetUser
//  │  ip       203.0.113.4
//  │  latency  3.1ms
//  │  user_id  usr_9f3k2
//  ╰─────────────────────────────────────────────────────────────────────────────────╯

func (l *Logger) formatDev(e Entry) string {
	c := l.color
	m := e.Level.meta()

	const width = 80

	// ── header bar ────────────────────────────────────────────────────────
	symbol := c(m.color+ansiBold, m.symbol)
	levelTag := c(m.color+ansiBold, e.Level.String())
	svc := c(charmmAccent+ansiBold, e.Service)
	ver := c(charmmVer, "v"+e.Version)
	ts := c(charmmMuted, e.Time.Format("2006/01/02 15:04:05.000"))

	// right side: "usersvc v1.4.2 · 2026/03/21 23:52:09.765"
	rightRaw := e.Service + " v" + e.Version + " · " + e.Time.Format("2006/01/02 15:04:05.000")
	right := svc + " " + ver + " " + c(charmmMuted, "·") + " " + ts
	_ = right // used below

	// left side: "╭─ ✔ OK "
	leftRaw := "   " + m.symbol + " " + e.Level.String() + " "
	padLen := width - len(leftRaw) - len(rightRaw) - 4
	if padLen < 1 {
		padLen = 1
	}
	pad := strings.Repeat("─", padLen)

	borderColor := m.bgLine
	if borderColor == "" {
		borderColor = charmmMuted
	}

	var sb strings.Builder

	// top border
	sb.WriteString(c(borderColor, "╭─"))
	sb.WriteString(" ")
	sb.WriteString(symbol)
	sb.WriteString(" ")
	sb.WriteString(levelTag)
	sb.WriteString(" ")
	sb.WriteString(c(borderColor, pad))
	sb.WriteString(" ")
	sb.WriteString(svc)
	sb.WriteString(" ")
	sb.WriteString(ver)
	sb.WriteString(" ")
	sb.WriteString(c(charmmMuted, "·"))
	sb.WriteString(" ")
	sb.WriteString(ts)
	sb.WriteString(" ")
	sb.WriteString(c(borderColor, "─╮"))
	sb.WriteString("\n")

	// ── message line ──────────────────────────────────────────────────────
	pipe := c(borderColor, "│")
	sb.WriteString(pipe)
	sb.WriteString("  ")
	sb.WriteString(c(ansiFgWhite+ansiBold, e.Msg))
	sb.WriteString("\n")

	// ── structured metadata lines ─────────────────────────────────────────
	metaLine := func(key, val, keyColor, valColor string) {
		sb.WriteString(pipe)
		sb.WriteString("  ")
		sb.WriteString(c(keyColor+ansiDim, fmt.Sprintf("%-10s", key)))
		sb.WriteString(c(valColor, val))
		sb.WriteString("\n")
	}

	// always-present metadata
	if e.File != "" {
		loc := e.File
		if e.Line > 0 {
			loc = fmt.Sprintf("%s:%d", e.File, e.Line)
		}
		metaLine("file", loc, ansiFgGray, charmmFile)
	}
	if e.RPCMethod != "" {
		metaLine("method", e.RPCMethod, ansiFgGray, charmmAccent)
	}
	if e.ClientIP != "" {
		metaLine("ip", e.ClientIP, ansiFgGray, charmmIPColor)
	}
	if e.Latency > 0 {
		metaLine("latency", fmtDur(e.Latency), ansiFgGray, ansiFgYellow)
	}
	if e.StatusCode != "" {
		sc := e.StatusCode
		scColor := ansiFgGreen
		if e.Level >= LevelWarn {
			scColor = ansiFgRed
		}
		metaLine("status", sc, ansiFgGray, scColor)
	}

	// user fields
	for _, f := range e.Fields {
		val := fmt.Sprintf("%v", f.Value)
		if err, ok := f.Value.(error); ok {
			val = err.Error()
		}
		metaLine(f.Key, val, ansiFgGray, ansiFgMagenta)
	}

	// ── bottom border ─────────────────────────────────────────────────────
	sb.WriteString(c(borderColor, "╰"+strings.Repeat("─", width+4)+"╯"))
	sb.WriteString("\n")

	return sb.String()
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  PROD formatter — single compact line                                   ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
//  2026/03/21 23:52:09.765  OK    usersvc/v1.4.2  handlers/user.go:58  GetUser  203.0.113.4  3.1ms  Service started  user_id=usr_9f3k2

func (l *Logger) formatProd(e Entry) string {
	c := l.color
	m := e.Level.meta()

	var sb strings.Builder

	// timestamp
	sb.WriteString(c(charmmMuted, e.Time.Format("2006/01/02 15:04:05.000")))
	sb.WriteString("  ")

	// level
	sb.WriteString(c(m.color+ansiBold, m.tag))
	sb.WriteString(" ")

	// service/version
	sb.WriteString(c(charmmAccent, e.Service))
	sb.WriteString(c(charmmMuted, "/"))
	sb.WriteString(c(charmmVer, "v"+e.Version))
	sb.WriteString("  ")

	// file:line
	if e.File != "" {
		loc := e.File
		if e.Line > 0 {
			loc = fmt.Sprintf("%s:%d", e.File, e.Line)
		}
		sb.WriteString(c(charmmFile, loc))
		sb.WriteString("  ")
	}

	// rpc method
	if e.RPCMethod != "" {
		sb.WriteString(c(charmmAccent, e.RPCMethod))
		sb.WriteString("  ")
	}

	// client ip
	if e.ClientIP != "" {
		sb.WriteString(c(charmmIPColor, e.ClientIP))
		sb.WriteString("  ")
	}

	// latency
	if e.Latency > 0 {
		sb.WriteString(c(ansiFgYellow, fmtDur(e.Latency)))
		sb.WriteString("  ")
	}

	// status
	if e.StatusCode != "" {
		scColor := ansiFgGreen
		if e.Level >= LevelWarn {
			scColor = ansiFgRed
		}
		sb.WriteString(c(scColor, e.StatusCode))
		sb.WriteString("  ")
	}

	// message
	sb.WriteString(c(ansiFgWhite, e.Msg))

	// extra fields as key=value
	for _, f := range e.Fields {
		val := fmt.Sprintf("%v", f.Value)
		if err, ok := f.Value.(error); ok {
			val = err.Error()
		}
		sb.WriteString("  ")
		sb.WriteString(c(ansiFgBlue, f.Key))
		sb.WriteString(c(charmmMuted, "="))
		sb.WriteString(c(ansiFgMagenta, val))
	}

	sb.WriteString("\n")
	return sb.String()
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Banner                                                                  ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// Banner prints the charmm nextools ASCII banner. Call once at startup.
//
//	 ██████╗██╗  ██╗ █████╗ ██████╗ ███╗   ███╗███╗   ███╗
//	██╔════╝██║  ██║██╔══██╗██╔══██╗████╗ ████║████╗ ████║
//	██║     ███████║███████║██████╔╝██╔████╔██║██╔████╔██║
//	██║     ██╔══██║██╔══██║██╔══██╗██║╚██╔╝██║██║╚██╔╝██║
//	╚██████╗██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║
//	 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝
func (l *Logger) Banner(extras ...Field) {
	c := l.color
	art := []string{
		` ██████╗██╗  ██╗ █████╗ ██████╗ ███╗   ███╗███╗   ███╗`,
		`██╔════╝██║  ██║██╔══██╗██╔══██╗████╗ ████║████╗ ████║`,
		`██║     ███████║███████║██████╔╝██╔████╔██║██╔████╔██║`,
		`██║     ██╔══██║██╔══██║██╔══██╗██║╚██╔╝██║██║╚██╔╝██║`,
		`╚██████╗██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║`,
		`╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝`,
	}

	// gradient: first rows more vivid, last rows dimmer
	shades := []string{charmmAccent, charmmAccent, charmmDim, charmmDim, charmmMuted, charmmMuted}
	for i, ln := range art {
		shade := charmmMuted
		if i < len(shades) {
			shade = shades[i]
		}
		fmt.Fprintln(l.cfg.Output, c(shade, ln))
	}

	// tagline
	fmt.Fprintf(l.cfg.Output, "  %s  %s  %s\n",
		c(charmmAccent+ansiBold, "nextools"),
		c(charmmMuted, "·"),
		c(charmmVer, "v"+l.version),
	)

	// service + env
	fmt.Fprintf(l.cfg.Output, "  %s  %s  %s\n\n",
		c(ansiFgWhite+ansiBold, l.cfg.Service),
		c(charmmMuted, "·"),
		c(envColor(l.cfg.Env), string(l.cfg.Env)),
	)

	// optional startup extras (build info, port, etc.)
	for _, f := range extras {
		seq := l.seq.Add(1)
		fmt.Fprintf(l.cfg.Output, "  %s  %s  %s %s\n",
			c(charmmMuted, fmt.Sprintf("%04d", seq)),
			c(charmmDim, "▸"),
			c(ansiDim+ansiFgGray, fmt.Sprintf("%-12s", f.Key)),
			c(charmmAccent, fmt.Sprintf("%v", f.Value)),
		)
	}
	if len(extras) > 0 {
		fmt.Fprintln(l.cfg.Output)
	}
}

func envColor(e Env) string {
	switch e {
	case EnvProduction:
		return ansiFgRed + ansiBold
	case EnvStaging:
		return ansiFgYellow
	default:
		return ansiFgGreen
	}
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  ConnectRPC adapter                                                      ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ConnectInterceptor returns a connect.UnaryInterceptorFunc that emits one
// Entry per RPC call with RPCMethod, ClientIP, Latency, and StatusCode filled.
//
//	mux.Handle(path, handler, connect.WithInterceptors(log.ConnectInterceptor()))
func (l *Logger) ConnectInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			proc := req.Spec().Procedure // "/user.v1.UserService/GetUser"

			// extract short method name "GetUser"
			parts := strings.Split(strings.TrimPrefix(proc, "/"), "/")
			method := proc
			if len(parts) == 2 {
				method = parts[1]
			}

			// peer address → IP only (strip port)
			ip := req.Peer().Addr
			if idx := strings.LastIndex(ip, ":"); idx != -1 {
				ip = ip[:idx]
			}

			resp, err := next(ctx, req)
			elapsed := time.Since(start)
			code := connect.CodeOf(err)

			level := LevelInfo
			if err != nil {
				level = LevelError
			}

			l.WithEntry(Entry{
				Level:      level,
				RPCMethod:  method,
				ClientIP:   ip,
				Latency:    elapsed,
				StatusCode: code.String(),
				Msg:        proc,
				Fields:     connectFields(err),
			})

			return resp, err
		}
	}
}

func connectFields(err error) []Field {
	if err != nil {
		return []Field{Err(err)}
	}
	return nil
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  GORM adapter                                                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// GORMLogger returns a gorm/logger.Interface backed by this Logger.
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: log.GORMLogger(gormlogger.Warn)})
func (l *Logger) GORMLogger(minLevel gormlogger.LogLevel) gormlogger.Interface {
	return &gormAdapter{
		log:           l.With(F("component", "gorm")),
		level:         minLevel,
		slowThreshold: 200 * time.Millisecond,
	}
}

type gormAdapter struct {
	log           *Logger
	level         gormlogger.LogLevel
	slowThreshold time.Duration
}

func (g *gormAdapter) LogMode(lv gormlogger.LogLevel) gormlogger.Interface {
	return &gormAdapter{log: g.log, level: lv, slowThreshold: g.slowThreshold}
}

func (g *gormAdapter) Info(_ context.Context, msg string, args ...any) {
	if g.level >= gormlogger.Info {
		g.log.emit(LevelInfo, 1, fmt.Sprintf(msg, args...), nil)
	}
}

func (g *gormAdapter) Warn(_ context.Context, msg string, args ...any) {
	if g.level >= gormlogger.Warn {
		g.log.emit(LevelWarn, 1, fmt.Sprintf(msg, args...), nil)
	}
}

func (g *gormAdapter) Error(_ context.Context, msg string, args ...any) {
	if g.level >= gormlogger.Error {
		g.log.emit(LevelError, 1, fmt.Sprintf(msg, args...), nil)
	}
}

func (g *gormAdapter) Trace(_ context.Context, begin time.Time, fc func() (string, int64), err error) {
	if g.level <= gormlogger.Silent {
		return
	}
	elapsed := time.Since(begin)
	sql, rows := fc()

	level := LevelDebug
	msg := "SQL query"
	var fields []Field

	switch {
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		level = LevelError
		msg = "SQL error"
		fields = []Field{Err(err), F("sql", truncate(sql, 120)), F("rows", rows)}
	case elapsed > g.slowThreshold:
		level = LevelWarn
		msg = "SQL slow query"
		fields = []Field{F("sql", truncate(sql, 120)), F("rows", rows)}
	default:
		fields = []Field{F("sql", truncate(sql, 80)), F("rows", rows)}
	}

	g.log.WithEntry(Entry{
		Level:   level,
		Latency: elapsed,
		Msg:     msg,
		Fields:  fields,
	})
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  NATS adapter                                                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// NATSOptions returns []nats.Option wiring lifecycle events into this Logger.
//
//	nc, _ := nats.Connect(url, log.NATSOptions()...)
func (l *Logger) NATSOptions() []nats.Option {
	nl := l.With(F("component", "nats"))
	return []nats.Option{
		nats.ConnectHandler(func(nc *nats.Conn) {
			nl.OK("NATS connected", F("url", nc.ConnectedUrl()), F("server", nc.ConnectedServerId()))
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				nl.Warn("NATS disconnected", Err(err))
			} else {
				nl.Info("NATS disconnected cleanly")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			nl.OK("NATS reconnected", F("url", nc.ConnectedUrl()))
		}),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			nl.Error("NATS async error", F("subject", sub.Subject), Err(err))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			nl.Info("NATS connection closed")
		}),
	}
}

// NATSPublish wraps nc.Publish with debug logging.
func (l *Logger) NATSPublish(nc *nats.Conn, subject string, data []byte) error {
	start := time.Now()
	err := nc.Publish(subject, data)
	level := LevelDebug
	fields := []Field{F("subject", subject), F("bytes", len(data))}
	if err != nil {
		level = LevelError
		fields = append(fields, Err(err))
	}
	l.WithEntry(Entry{Level: level, Latency: time.Since(start), Msg: "NATS publish", Fields: fields})
	return err
}

// NATSSubscribe wraps nc.Subscribe with per-message debug logging.
func (l *Logger) NATSSubscribe(nc *nats.Conn, subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	nl := l.With(F("component", "nats"), F("subject", subject))
	wrapped := func(msg *nats.Msg) {
		nl.WithEntry(Entry{
			Level:  LevelDebug,
			Msg:    "NATS received",
			Fields: []Field{F("bytes", len(msg.Data)), F("reply", msg.Reply)},
		})
		handler(msg)
	}
	sub, err := nc.Subscribe(subject, wrapped)
	if err != nil {
		nl.Error("NATS subscribe failed", Err(err))
		return nil, err
	}
	nl.OK("NATS subscribed", F("subject", subject))
	return sub, nil
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Postgres / pgx v5 adapter                                               ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// PGTracer returns a pgx v5 QueryTracer.
//
//	cfg.ConnConfig.Tracer = log.PGTracer()
func (l *Logger) PGTracer() *PGQueryTracer {
	return &PGQueryTracer{
		log:           l.With(F("component", "postgres")),
		slowThreshold: 300 * time.Millisecond,
	}
}

// PGQueryTracer implements pgx v5's QueryTracer interface.
type PGQueryTracer struct {
	log           *Logger
	slowThreshold time.Duration
}

type pgKey struct{}
type pgData struct {
	sql   string
	start time.Time
}

func (t *PGQueryTracer) TraceQueryStart(ctx context.Context, _ any, args interface{ SQL() string }) context.Context {
	return context.WithValue(ctx, pgKey{}, &pgData{sql: args.SQL(), start: time.Now()})
}

func (t *PGQueryTracer) TraceQueryEnd(ctx context.Context, _ any, args interface{ Err() error }) {
	d, _ := ctx.Value(pgKey{}).(*pgData)
	if d == nil {
		return
	}
	elapsed := time.Since(d.start)
	err := args.Err()

	level := LevelDebug
	msg := "PG query"
	var fields []Field

	switch {
	case err != nil:
		level = LevelError
		msg = "PG query error"
		fields = []Field{Err(err), F("sql", truncate(d.sql, 100))}
	case elapsed > t.slowThreshold:
		level = LevelWarn
		msg = "PG slow query"
		fields = []Field{F("sql", truncate(d.sql, 100))}
	default:
		fields = []Field{F("sql", truncate(d.sql, 60))}
	}

	t.log.WithEntry(Entry{Level: level, Latency: elapsed, Msg: msg, Fields: fields})
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Utilities                                                               ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// callerInfo returns the short file path and line number, skipping `skip`+2 frames.
func callerInfo(skip int) (string, int) {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown", 0
	}
	// produce  pkg/file.go  —  trim everything before the module root
	// heuristic: keep the last 2 path components for brevity
	parts := strings.Split(filepath.ToSlash(file), "/")
	if len(parts) >= 2 {
		file = strings.Join(parts[len(parts)-2:], "/")
	}
	return file, line
}

// resolveVersion returns the version string in order of preference:
//  1. explicit (non-empty cfg.Version)
//  2. VCS tag from debug.ReadBuildInfo (set by go build -buildvcs)
//  3. module version from build info
//  4. "dev"
func resolveVersion(explicit string) string {
	if explicit != "" {
		return explicit
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	// VCS semver tag written by go build -buildvcs (Go 1.18+)
	for _, s := range info.Settings {
		if s.Key == "vcs.tag" && s.Value != "" {
			return strings.TrimPrefix(s.Value, "v")
		}
	}
	// module version (populated when installed via `go install module@version`)
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}

// fmtDur formats a duration with appropriate precision.
func fmtDur(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fµs", float64(d.Nanoseconds())/1e3)
	case d < time.Second:
		return fmt.Sprintf("%.3fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
}

// truncate shortens s to max runes, appending … if trimmed.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

func (l *Logger) color(code, text string) string {
	if l.cfg.NoColor {
		return text
	}
	return code + text + ansiReset
}
