// Package logger provides a unified, production-ready logging interface with
// support for multiple logging backends.
//
// # Overview
//
// The logger package offers a consistent logging abstraction that supports
// both Zap and Logrus backends. It enables applications to maintain uniform
// logging patterns while allowing flexibility in choosing the underlying
// logging implementation based on performance requirements or team preferences.
//
// # Features
//
//   - Unified Logger interface supporting structured logging
//   - Multiple backend support (Zap for production, Logrus for development)
//   - Context-aware logging with automatic field propagation
//   - Configurable log levels, formats, and outputs
//   - Global logger instance for convenient package-level usage
//   - Type-safe structured field creation
//   - Caller information and stacktrace support
//
// # Quick Start
//
// Basic usage with default configuration:
//
//	// Initialize logger
//	logger, err := logger.New(logger.Config{
//	    Level:  "info",
//	    Format: "json",
//	    Output: "stdout",
//	})
//	if err != nil {
//	    log.Fatal("Failed to create logger:", err)
//	}
//
//	// Set as global logger
//	logger.SetGlobalLogger(logger)
//
//	// Use package-level functions
//	logger.Info("Application started",
//	    logger.String("version", "1.0.0"),
//	    logger.Int("port", 8080),
//	)
//
// # Configuration
//
// The Config struct supports the following options:
//
//	Level:      Log level (debug, info, warn, error, fatal)
//	Format:     Output format (json, text)
//	Output:     Output destination (stdout, stderr, or file path)
//	EnableCaller:      Whether to include caller information
//	EnableStacktrace:  Whether to include stacktraces for errors
//
// # Backend Selection
//
// The package provides two main constructor functions:
//
//   - NewZapLogger(): High-performance logger recommended for production
//   - NewLogrusLogger(): Feature-rich logger good for development
//   - New(): Default constructor that uses Zap for production readiness
//
// # Structured Logging
//
// The package supports structured logging through Field types:
//
//	logger.Info("User login successful",
//	    logger.String("user_id", "12345"),
//	    logger.String("email", "user@example.com"),
//	    logger.Int("login_count", 42),
//	    logger.Bool("two_factor", true),
//	)
//
// # Context Integration
//
// Loggers can be enriched with context values:
//
//	ctx := context.WithValue(context.Background(), "request_id", "req-123")
//	logger.WithContext(ctx).Info("Processing request")
//	// Log output includes: {"request_id": "req-123", "msg": "Processing request"}
//
// # Global Logger Pattern
//
// For convenience, the package provides a global logger instance:
//
//	// Initialize during app startup
//	logger.SetGlobalLogger(myLogger)
//
//	// Use anywhere in your application
//	logger.Debug("Debug message")
//	logger.Error("Operation failed", err, logger.String("component", "api"))
//
// # Best Practices
//
//  1. Use Zap for production applications requiring high performance
//  2. Use Logrus for development or when needing rich formatting options
//  3. Always set a global logger during application initialization
//  4. Use structured fields instead of string formatting for better log processing
//  5. Propagate context through function calls to maintain request-scoped fields
//
// Example
//
//	func HandleRequest(ctx context.Context, userID string) {
//	    log := logger.WithContext(ctx).With(logger.String("handler", "HandleRequest"))
//
//	    log.Info("Processing request", logger.String("user_id", userID))
//
//	    // Business logic here
//
//	    if err := processUser(userID); err != nil {
//	        log.Error("Failed to process user", err)
//	        return
//	    }
//
//	    log.Info("Request completed successfully")
//	}
//
// # Compatibility
//
// The package is compatible with standard logging patterns and can be easily
// integrated with existing applications. It provides a drop-in replacement
// for both Zap and Logrus with a unified interface.
package logger
