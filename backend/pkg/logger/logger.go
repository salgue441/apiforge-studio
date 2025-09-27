package logger

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates a new logger using Zap as the default backend. It provides
// high-performance structured logging suitable for production environments.
// Returns a `Logger` instance or an `error` if configuration fails.
func New(config Config) (Logger, error) {
	return NewZapLogger(config)
}

// NewZapLogger creates a new Zap-based logger with the provided configuration.
//
// The function configures log level, format, output destination, and optional
// features like caller information and stacktrace.
func NewZapLogger(config Config) (Logger, error) {
	level, err := zapcore.ParseLevel(config.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	var encoderConfig zapcore.EncoderConfig
	if config.Format == "text" {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	var encoder zapcore.Encoder
	if config.Format == "text" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var output zapcore.WriteSyncer
	switch config.Output {
	case "stderr":
		output = zapcore.Lock(os.Stderr)
	case "stdout":
		output = zapcore.Lock(os.Stdout)
	default:
		file, err := os.OpenFile(
			config.Output,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666,
		)

		if err != nil {
			return nil, err
		}

		output = zapcore.Lock(file)
	}

	core := zapcore.NewCore(encoder, output, level)

	var options []zap.Option
	if config.EnableCaller {
		options = append(options, zap.AddCaller())
	}

	if config.EnableStackTrace {
		options = append(options, zap.AddStacktrace(zapcore.ErrorLevel))
	}

	logger := zap.New(core, options...)
	return &zapLogger{
		logger: logger,
		sugar:  logger.Sugar(),
	}, nil
}

// NewLogrusLogger creates a new Logrus-based logger with the provided
// configuration.
//
// Logrus is often preferred for development due to its user-friendly API and
// formatting. It supports the same configuration options as the Zap logger for
// consistency.
func NewLogrusLogger(config Config) Logger {
	logger := logrus.New()
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}

	logger.SetLevel(level)
	if config.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
			FullTimestamp:   true,
		})
	}

	switch config.Output {
	case "stderr":
		logger.SetOutput(os.Stderr)
	case "stdout", "":
		logger.SetOutput(os.Stdout)
	default:
		file, err := os.OpenFile(
			config.Output,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			0666,
		)

		if err == nil {
			logger.SetOutput(file)
		}
	}

	if config.EnableCaller {
		logger.SetReportCaller(true)
	}

	return &logrusLogger{logger: logger}
}

// Zap Logger Implementation Methods

// Debug logs a debug-level message with structured fields using Zap.
func (l *zapLogger) Debug(msg string, fields ...Field) {
	l.logger.Debug(msg, l.fieldsToZap(fields)...)
}

// Info logs an info-level message with structured fields using Zap.
func (l *zapLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, l.fieldsToZap(fields)...)
}

// Warn logs a warning-level message with structured fields using Zap.
func (l *zapLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, l.fieldsToZap(fields)...)
}

// Error logs an error-level message with an associated error and structured
// fields using Zap. The error is automatically added as a structured field if
// provided.
func (l *zapLogger) Error(msg string, err error, fields ...Field) {
	zapFields := l.fieldsToZap(fields)
	if err != nil {
		zapFields = append(zapFields, zap.Error(err))
	}

	l.logger.Error(msg, zapFields...)
}

// Fatal logs a fatal-level message with an associated error and structured
// fields using Zap, then calls os.Exit(1). The error is automatically added as
// a structured field if provided.
func (l *zapLogger) Fatal(msg string, err error, fields ...Field) {
	zapFields := l.fieldsToZap(fields)
	if err != nil {
		zapFields = append(zapFields, zap.Error(err))
	}

	l.logger.Fatal(msg, zapFields...)
}

// With returns a new Zap logger instance with the provided structured fields
// attached to all future log entries.
func (l *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{
		logger: l.logger.With(l.fieldsToZap(fields)...),
		sugar:  l.sugar.With(convertToInterface(l.fieldsToZap(fields))...),
	}
}

// WithContext returns a new Zap logger instance with context values
// (like request_id, user_id, trace_id) propagated to log entries.
func (l *zapLogger) WithContext(ctx context.Context) Logger {
	var fields []Field
	if reqID, ok := ctx.Value("request_id").(string); ok {
		fields = append(fields, Field{Key: "request_id", Value: reqID})
	}

	if userID, ok := ctx.Value("user_id").(string); ok {
		fields = append(fields, Field{Key: "user_id", Value: userID})
	}

	if traceID, ok := ctx.Value("trace_id").(string); ok {
		fields = append(fields, Field{Key: "trace_id", Value: traceID})
	}

	return l.With(fields...)
}

// fieldsToZap converts internal Field types to Zap's zap.Field types.
func (l *zapLogger) fieldsToZap(fields []Field) []zap.Field {
	zapFields := make([]zap.Field, len(fields))
	for i, field := range fields {
		zapFields[i] = zap.Any(field.Key, field.Value)
	}

	return zapFields
}

// convertToInterface converts a slice of zap.Field to a slice of interface{}.
func convertToInterface(fields []zap.Field) []any {
	interfaces := make([]any, len(fields))
	for i, field := range fields {
		interfaces[i] = field
	}

	return interfaces
}

// Logrus Logger Implementation Methods

// Debug logs a debug-level message with structured fields using Logrus.
func (l *logrusLogger) Debug(msg string, fields ...Field) {
	l.logger.WithFields(l.fieldsToLogrus(fields)).Debug(msg)
}

// Info logs an info-level message with structured fields using Logrus.
func (l *logrusLogger) Info(msg string, fields ...Field) {
	l.logger.WithFields(l.fieldsToLogrus(fields)).Info(msg)
}

// Warn logs a warning-level message with structured fields using Logrus.
func (l *logrusLogger) Warn(msg string, fields ...Field) {
	l.logger.WithFields(l.fieldsToLogrus(fields)).Warn(msg)
}

// Error logs an error-level message with an associated error and structured
// fields using Logrus. The error is automatically added as a structured field
// if provided.
func (l *logrusLogger) Error(msg string, err error, fields ...Field) {
	logrusFields := l.fieldsToLogrus(fields)
	if err != nil {
		logrusFields["error"] = err.Error()
	}

	l.logger.WithFields(logrusFields).Error(msg)
}

// Fatal logs a fatal-level message with an associated error and structured
// fields using Logrus, then calls os.Exit(1). The error is automatically added
// as a structured field if provided.
func (l *logrusLogger) Fatal(msg string, err error, fields ...Field) {
	logrusFields := l.fieldsToLogrus(fields)
	if err != nil {
		logrusFields["error"] = err.Error()
	}

	l.logger.WithFields(logrusFields).Fatal(msg)
}

// With returns a new Logrus logger instance with the provided structured fields
// attached to all future log entries.
func (l *logrusLogger) With(fields ...Field) Logger {
	return &logrusLogger{
		logger: l.logger.WithFields(l.fieldsToLogrus(fields)).Logger,
	}
}

// WithContext returns a new Logrus logger instance with context values
// (like request_id, user_id, trace_id) propagated to log entries.
func (l *logrusLogger) WithContext(ctx context.Context) Logger {
	var fields []Field
	if reqID, ok := ctx.Value("request_id").(string); ok {
		fields = append(fields, Field{Key: "request_id", Value: reqID})
	}

	if userID, ok := ctx.Value("user_id").(string); ok {
		fields = append(fields, Field{Key: "user_id", Value: userID})
	}

	if traceID, ok := ctx.Value("trace_id").(string); ok {
		fields = append(fields, Field{Key: "trace_id", Value: traceID})
	}

	return l.With(fields...)
}

// fieldsToLogrus converts internal Field types to Logrus's Fields type.
func (l *logrusLogger) fieldsToLogrus(fields []Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key] = field.Value
	}

	return logrusFields
}

// Convenience functions for creating structured fields

// String creates a string field for structured logging.
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field for structured logging.
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Int64 creates an int64 field for structured logging.
func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

// Float64 creates a float64 field for structured logging.
func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a boolean field for structured logging.
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Any creates a field with any type for structured logging.
// Use specific typed functions when possible for better performance.
func Any(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// Duration creates a duration field for structured logging.
func Duration(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// Global logger management

// globalLogger is the singleton logger instance used by package-level
// convenience functions.
var globalLogger Logger

// SetGlobalLogger configures the global logger instance used by package-level
// functions.
// This should be called during application initialization.
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the configured global logger instance.
// If no global logger is set, it falls back to a default JSON logger writing
// to stdout.
func GetGlobalLogger() Logger {
	if globalLogger == nil {
		logger, _ := New(Config{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		})

		return logger
	}

	return globalLogger
}

// Package-level convenience functions that use the global logger

// Debug logs a debug-level message using the global logger.
func Debug(msg string, fields ...Field) {
	GetGlobalLogger().Debug(msg, fields...)
}

// Info logs an info-level message using the global logger.
func Info(msg string, fields ...Field) {
	GetGlobalLogger().Info(msg, fields...)
}

// Warn logs a warning-level message using the global logger.
func Warn(msg string, fields ...Field) {
	GetGlobalLogger().Warn(msg, fields...)
}

// Error logs an error-level message using the global logger.
func Error(msg string, err error, fields ...Field) {
	GetGlobalLogger().Error(msg, err, fields...)
}

// Fatal logs a fatal-level message using the global logger, then exits.
func Fatal(msg string, err error, fields ...Field) {
	GetGlobalLogger().Fatal(msg, err, fields...)
}

// With returns a new logger with structured fields using the global logger.
func With(fields ...Field) Logger {
	return GetGlobalLogger().With(fields...)
}

// WithContext returns a new logger with context values using the global logger.
func WithContext(ctx context.Context) Logger {
	return GetGlobalLogger().WithContext(ctx)
}
