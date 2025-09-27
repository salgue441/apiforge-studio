// Package validator provides a comprehensive, production-ready validation solution
// for Go applications with structured error handling, custom validation rules,
// and internationalization support.
//
// # Overview
//
// The validator package wraps the popular go-playground/validator with enhanced
// functionality including custom validation rules, structured error reporting,
// and a global validator instance for convenient usage. It is designed to handle
// complex validation scenarios while providing clean, actionable error messages.
//
// # Features
//
//   - Structured error handling with detailed field-level validation errors
//   - Custom validation rules for common scenarios (API names, passwords, slugs, etc.)
//   - Internationalization support with English translations included
//   - Global validator instance for convenient package-level usage
//   - Context-aware validation for complex business rules
//   - JSON tag name integration for consistent API error responses
//   - Extensible architecture for adding custom validation rules
//
// # Quick Start
//
// Basic usage with the global validator:
//
//	import "your-module/validator"
//
//	// Initialize the global validator (typically in main.go)
//	func main() {
//	    if err := validator.InitGlobalValidator(); err != nil {
//	        log.Fatal("Failed to initialize validator:", err)
//	    }
//	}
//
//	// Use in your application
//	type User struct {
//	    Email    string `json:"email" validate:"required,email"`
//	    Password string `json:"password" validate:"required,strongpassword"`
//	    Username string `json:"username" validate:"required,slug"`
//	}
//
//	func CreateUser(user User) error {
//	    if errors := validator.Validate(user); len(errors) > 0 {
//	        return fmt.Errorf("validation failed: %v", errors)
//	    }
//	    // Proceed with user creation
//	}
//
// # Custom Validation Rules
//
// The package includes numerous custom validation rules for common use cases:
//
//   - apiname      - API endpoint names (letters, numbers, underscores, hyphens)
//   - projectname  - Project names (more permissive, allows spaces)
//   - httpmethod   - HTTP methods (GET, POST, PUT, DELETE, etc.)
//   - jsonfield    - JSON field names (JavaScript identifier rules)
//   - tablename    - Database table names (SQL identifier rules)
//   - gopackage    - Go package names (lowercase letters and numbers)
//   - dockerimage  - Docker image names (Docker naming conventions)
//   - envname      - Environment variable names (uppercase with underscores)
//   - strongpassword - Strong passwords (8+ chars, upper/lower/digit/special)
//   - password     - Basic passwords (6-128 characters)
//   - apipath      - API paths (must start with /, supports path parameters)
//   - slug         - URL slugs (lowercase, hyphens, numbers)
//   - semver       - Semantic versions (major.minor.patch format)
//   - notempty     - Non-empty strings (trimmed length > 0)
//
// # Error Handling
//
// The package provides structured error handling through ValidationErrors type:
//
//	errors := validator.Validate(user)
//	if len(errors) > 0 {
//	    // Check for specific field errors
//	    if errors.HasField("email") {
//	        emailErrors := errors.GetFieldErrors("email")
//	        // Handle email-specific errors
//	    }
//
//	    // Return JSON response (errors implement json.Marshaler)
//	    return c.JSON(400, errors)
//	}
//
// # Advanced Usage
//
// Creating a custom validator instance with specific configuration:
//
//	// Create a new validator instance
//	customValidator, err := validator.New()
//	if err != nil {
//	    return err
//	}
//
//	// Validate with context for complex business rules
//	ctx := context.WithValue(context.Background(), "db", database)
//	errors := customValidator.ValidateWithContext(ctx, user)
//
//	// Validate individual variables
//	err := customValidator.ValidateVar(email, "required,email")
//
// # Validation Examples
//
// Using custom validation rules in struct tags:
//
//	type API struct {
//	    Name    string `json:"name" validate:"required,apiname"`
//	    Version string `json:"version" validate:"required,semver"`
//	    Path    string `json:"path" validate:"required,apipath"`
//	    Method  string `json:"method" validate:"required,httpmethod"`
//	}
//
//	type Project struct {
//	    Name        string `json:"name" validate:"required,projectname"`
//	    PackageName string `json:"package_name" validate:"required,gopackage"`
//	    DockerImage string `json:"docker_image" validate:"required,dockerimage"`
//	}
//
//	type User struct {
//	    Username string `json:"username" validate:"required,slug"`
//	    Email    string `json:"email" validate:"required,email"`
//	    Password string `json:"password" validate:"required,strongpassword"`
//	}
//
// # Configuration Options
//
// The validator automatically configures itself with sensible defaults:
//
//   - Uses JSON tag names for error field names
//   - English translations for all validation messages
//   - Custom error messages for all custom validation rules
//   - Proper error message formatting and internationalization
//
// # Best Practices
//
//  1. Initialize the global validator during application startup
//  2. Use structured errors for API responses
//  3. Choose appropriate validation rules for your domain
//  4. Use context-aware validation for business logic rules
//  5. Create custom validation rules for domain-specific requirements
//  6. Handle validation errors consistently across your application
//
// # Extending the Validator
//
// To add custom validation rules, create new validation functions following
// the existing patterns and register them in the registerCustomValidations method.
//
// Example custom validation function:
//
//	func validateCustomRule(fl validator.FieldLevel) bool {
//	    value := fl.Field().String()
//	    // Custom validation logic
//	    return isValid
//	}
//
// Then register it in the validations map in registerCustomValidations().
//
// # Integration with Web Frameworks
//
// The validator works seamlessly with popular web frameworks:
//
// Echo framework example:
//
//	func CreateUser(c echo.Context) error {
//	    var user User
//	    if err := c.Bind(&user); err != nil {
//	        return err
//	    }
//
//	    if errors := validator.Validate(user); len(errors) > 0 {
//	        return c.JSON(400, errors)
//	    }
//	    // Process valid user
//	}
//
// Gin framework example:
//
//	func CreateUser(c *gin.Context) {
//	    var user User
//	    if err := c.ShouldBindJSON(&user); err != nil {
//	        c.JSON(400, gin.H{"error": err.Error()})
//	        return
//	    }
//
//	    if errors := validator.Validate(user); len(errors) > 0 {
//	        c.JSON(400, errors)
//	        return
//	    }
//	    // Process valid user
//	}
//
// # Performance Considerations
//
// The validator is designed for performance:
//   - Regex patterns are pre-compiled and reused
//   - Validator instances are safe for concurrent use
//   - Structured errors minimize allocations
//   - Global validator avoids repeated initialization
//
// # Testing
//
// The package includes convenience functions for testing:
//
//	// In your tests
//	func TestUserValidation(t *testing.T) {
//	    user := User{Username: "test-user", Email: "test@example.com"}
//	    validator.MustValidate(user) // Panics if validation fails
//
//	    valid, errors := validator.ValidateStruct(user)
//	    assert.True(t, valid)
//	    assert.Empty(t, errors)
//	}
//
// # Error Messages
//
// All validation errors include translated, human-readable messages.
// Custom validation rules have specific error messages that explain the requirements.
//
// Example error response:
//
//	[
//	    {
//	        "field": "email",
//	        "tag": "email",
//	        "value": "invalid-email",
//	        "message": "email must be a valid email address"
//	    },
//	    {
//	        "field": "password",
//	        "tag": "strongpassword",
//	        "value": "weak",
//	        "message": "password must contain at least 8 characters with uppercase, lowercase, number, and special character"
//	    }
//	]
//
// # Dependencies
//
// The package relies on:
//   - github.com/go-playground/validator/v10 - Core validation engine
//   - github.com/go-playground/universal-translator - Internationalization
//   - github.com/go-playground/locales/en - English translations
//
// # Versioning
//
// This package follows semantic versioning. Breaking changes will result in
// major version increments.
//
// # License
//
// This package is provided under the same license as your project or the
// MIT license as specified in the module configuration.
package validator
