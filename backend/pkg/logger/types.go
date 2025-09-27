package logger

import (
	"context"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

// Logger defines the standard logging contract for the application.
// It supports structued logging with fields and context propagation.
type Logger interface {
	// Debug logs a debug-level message with optional structured fields.
	Debug(msg string, fields ...Field)

	// Info logs an info-level message with optional structured fields.
	Info(msg string, fields ...Field)

	// Warn logs a warning-level message with optional structured fields.
	Warn(msg string, fields ...Field)

	// Error logs an error-level message with an associated error and optional
	// fields.
	Error(msg string, err error, fields ...Field)

	// Fatal logs a fatal-level message with an associated error and optional
	// fields, then terminates the application.
	Fatal(msg string, err error, fields ...Field)

	// With returns a new Logger instance with the provided structured fields
	// attached to all future log entries.
	With(fields ...Field) Logger

	// WithContext returns a new Logger instance with context values
	// propagated to the log entries.
	WithContext(ctx context.Context) Logger
}

// Field represents a key-value pair for structured logging.
// Used to attach contextual information to log entries.
type Field struct {
	Key   string
	Value any
}

// Config holds configuration parameters for logger initialization.
// It supports multiple log formats, levels, and output destinations.
type Config struct {
	// Log level: debug, info, warn, error, fatal
	Level string

	// Log format: json, text
	Format string

	// Output destination: stdout, stderr, or file path
	Output string

	// Whether to include the caller information (file:line)
	EnableCaller bool

	// Whether to include the stacktraces for error levels
	EnableStackTrace bool
}

// zapLogger is an adapter that wraps zap.Logger to implement the Logger
// interface. It provides high-performance structured logging.
type zapLogger struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

// logrusLogger is an adapter that wraps logrus.Logger to implement the Logger
// interface. It provides feature-rich logging with easy-to-use APIs.
type logrusLogger struct {
	logger *logrus.Logger
}
