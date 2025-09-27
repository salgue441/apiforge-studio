package validator

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

// Regular expressions for various validation patterns used throughout the
// application. These regex patterns enforce consistent naming conventions and
// format requirements.
var (
	apiNameRegex     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
	projectNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\s_-]*[a-zA-Z0-9]$`)
	jsonFieldRegex   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	tableNameRegex   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	goPackageRegex   = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	dockerImageRegex = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	envNameRegex     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	slugRegex        = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	semVerRegex      = regexp.MustCompile(`^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\da-z\-]+(?:\.[\da-z\-]+)*)?(?:\+[\da-z\-]+(?:\.[\da-z\-]+)*)?$`)
)

// httpMethods contains the standard HTTP methods allowed by the validation.
// This map is used to validate that HTTP method strings conform to RFC
// standards.
var httpMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"OPTIONS": true,
	"HEAD":    true,
}

// validateAPIName validates API endpoint names for consistency and readability.
// This validation ensures API names follow established naming conventions and
// are suitable for use in URL paths and code generation.
//
// Validation Rules:
//   - Must not be empty
//   - Must start with a letter (a-z, A-Z)
//   - Can contain letters, numbers, underscores (_), and hyphens (-)
//   - No spaces or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid API name, false otherwise
//
// Example:
//
//	type Endpoint struct {
//	 Name string `validate:"apiname"` // Valid: "user_api", "payment-service"
//	}
func validateAPIName(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if len(value) == 0 {
		return false
	}

	return apiNameRegex.MatchString(value)
}

// validateProjectName validates project names with flexible naming conventions.
// This validation is more permissive than API names to accommodate various
// project naming styles while maintaining basic readability standards.
//
// Validation Rules:
//   - Length between 2 and 100 characters
//   - Must start and end with alphanumeric characters
//   - Can contain letters, numbers, spaces, underscores, and hyphens
//   - No leading/trailing spaces or special characters
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid project name, false otherwise
//
// Example:
//
//	type Project struct {
//	    Name string `validate:"projectname"` // Valid: "My API Project"
//	}
func validateProjectName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) < 2 || len(name) > 100 {
		return false
	}

	return projectNameRegex.MatchString(name)
}

// validateHTTPMethod validates HTTP methods against the standard set of
// methods. This ensures that HTTP method strings are valid and conform to RFC
// standards, preventing common typos and invalid method names in API
// definitions.
//
// Validation Rules:
//   - Must be one of: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
//   - Case-insensitive (converted to uppercase for validation)
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid HTTP method, false otherwise
//
// Example:
//
//	type Route struct {
//	    Method string `validate:"httpmethod"` // Valid: "get", "POST", "Put"
//	}
func validateHTTPMethod(fl validator.FieldLevel) bool {
	method := strings.ToUpper(fl.Field().String())
	return httpMethods[method]
}

// validateJSONField validates JSON field names for JavaScript/JSON
// compatibility. This validation ensures field names are valid JavaScript
// identifiers and can be safely used in JSON objects and JavaScript code.
//
// Validation Rules:
//   - Must not be empty
//   - Must start with a letter or underscore
//   - Can contain letters, numbers, and underscores
//   - No hyphens, spaces, or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid JSON field name, false otherwise
//
// Example:
//
//	type Config struct {
//	    FieldName string `validate:"jsonfield"` // Valid: "userName", "_id", "item2"
//	}
func validateJSONField(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if len(value) == 0 {
		return false
	}

	return jsonFieldRegex.MatchString(value)
}

// validateTableName validates database table names for SQL compatibility.
// This validation ensures table names follow common SQL identifier conventions
// and are compatible with most database systems.
//
// Validation Rules:
//   - Length between 1 and 63 characters (common database limits)
//   - Must start with a letter
//   - Can contain letters, numbers, and underscores
//   - No spaces, hyphens, or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid table name, false otherwise
//
// Example:
//
//	type Model struct {
//	    TableName string `validate:"tablename"` // Valid: "users", "order_items"
//	}
func validateTableName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) < 1 || len(name) > 63 {
		return false
	}

	return tableNameRegex.MatchString(name)
}

// validateGoPackage validates Go package names according to Go conventions.
// This validation ensures package names are valid Go identifiers and follow
// the community naming standards for Go packages.
//
// Validation Rules:
//   - Length between 1 and 100 characters
//   - Must start with a lowercase letter
//   - Can contain lowercase letters and numbers only
//   - No uppercase letters, underscores, or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid Go package name, false otherwise
//
// Example:
//
//	type Package struct {
//	    Name string `validate:"gopackage"` // Valid: "mypackage", "utils", "api2"
//	}
func validateGoPackage(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) < 1 || len(name) > 100 {
		return false
	}

	return goPackageRegex.MatchString(name)
}

// validateDockerImage validates Docker image names according to Docker
// conventions. This validation ensures image names are compatible with Docker
// registry requirements and follow established naming patterns for container
// images.
//
// Validation Rules:
//   - Length between 1 and 255 characters (Docker limitation)
//   - Lowercase alphanumeric characters with periods, underscores, hyphens
//   - Optional organization prefix separated by slash
//   - No uppercase letters or special characters beyond allowed set
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid Docker image name, false otherwise
//
// Example:
//
//	type Container struct {
//	    Image string `validate:"dockerimage"` // Valid: "nginx", "myorg/api", "app:v1.0"
//	}
func validateDockerImage(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) < 1 || len(name) > 255 {
		return false
	}

	return dockerImageRegex.MatchString(name)
}

// validateEnvName validates environment variable names for shell compatibility.
// This validation ensures environment variable names follow POSIX conventions
// and are safe to use in various shell environments and configuration files.
//
// Validation Rules:
//   - Must not be empty
//   - Must start with an uppercase letter
//   - Can contain uppercase letters, numbers, and underscores
//   - No lowercase letters, spaces, or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid environment variable name, false otherwise
//
// Example:
//
//	type Config struct {
//	    EnvVar string `validate:"envname"` // Valid: "DATABASE_URL", "API_KEY"
//	}
func validateEnvName(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if len(value) == 0 {
		return false
	}

	return envNameRegex.MatchString(value)
}

// validateStrongPassword validates password strength for enhanced security.
// This validation enforces strong password policies to protect user accounts
// and sensitive data. Use this for applications requiring high security.
//
// Validation Rules:
//   - Minimum 8 characters length
//   - At least one uppercase letter (A-Z)
//   - At least one lowercase letter (a-z)
//   - At least one number (0-9)
//   - At least one special character (punctuation or symbol)
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value meets strong password requirements, false otherwise
//
// Example:
//
//	type User struct {
//	    Password string `validate:"strongpassword"` // Valid: "SecurePass123!"
//	}
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validatePassword validates basic password requirements for general use cases.
// This validation provides a less restrictive alternative to strongpassword
// for applications where user convenience is prioritized over maximum security.
//
// Validation Rules:
//   - Length between 6 and 128 characters
//   - No character type requirements (unlike strongpassword)
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value meets basic password requirements, false otherwise
//
// Example:
//
//	type User struct {
//	    Password string `validate:"password"` // Valid: "pass123", "simple"
//	}
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	return len(password) >= 6 && len(password) <= 128
}

// validateAPIPath validates API endpoint paths for URL compatibility.
// This validation ensures API paths are well-formed and support common
// URL patterns including path parameters for RESTful API design.
//
// Validation Rules:
//   - Must start with a forward slash (/)
//   - Path segments cannot be empty
//   - Regular segments: alphanumeric, underscores, hyphens
//   - Path parameters allowed: :param or {param} format
//   - Root path (/) is valid
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid API path, false otherwise
//
// Example:
//
//	type Route struct {
//	    Path string `validate:"apipath"` // Valid: "/users", "/api/v1/:id", "/items/{item_id}"
//	}
func validateAPIPath(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if !strings.HasPrefix(path, "/") {
		return false
	}

	if path == "/" {
		return true
	}

	pattern := regexp.MustCompile(`^[a-zA-Z0-9_+$]`)
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for _, segment := range segments {
		if segment == "" {
			return false
		}

		if strings.HasPrefix(segment, ":") ||
			(strings.HasPrefix(segment, "{") && strings.HasPrefix(segment, "}")) {
			continue
		}

		if !pattern.MatchString(segment) {
			return false
		}
	}

	return true
}

// validateSlug validates URL-friendly slugs for SEO and readability.
// This validation ensures slugs are compatible with URL requirements
// and follow best practices for human-readable URLs.
//
// Validation Rules:
//   - Length between 1 and 100 characters
//   - Lowercase letters, numbers, and hyphens only
//   - Words separated by hyphens (kebab-case)
//   - No underscores, spaces, or special characters allowed
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid slug, false otherwise
//
// Example:
//
//	type Article struct {
//	    Slug string `validate:"slug"` // Valid: "my-article", "product-2024"
//	}
func validateSlug(fl validator.FieldLevel) bool {
	slug := fl.Field().String()
	if len(slug) < 1 || len(slug) > 100 {
		return false
	}

	return slugRegex.MatchString(slug)
}

// validateSemVer validates semantic version strings according to semver.org.
// This validation ensures version strings follow the semantic versioning
// specification for consistent version management and dependency resolution.
//
// Validation Rules:
//   - Must not be empty
//   - Format: major.minor.patch (e.g., 1.0.0)
//   - Optional pre-release version (e.g., -alpha, -beta.1)
//   - Optional build metadata (e.g., +build.20240101)
//   - Optional 'v' prefix (e.g., v1.0.0)
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value is a valid semantic version, false otherwise
//
// Example:
//
//	type Version struct {
//	    Number string `validate:"semver"` // Valid: "1.0.0", "v2.1.4-beta.1"
//	}
func validateSemVer(fl validator.FieldLevel) bool {
	version := fl.Field().String()
	if len(version) == 0 {
		return false
	}

	return semVerRegex.MatchString(version)
}

// validateNotEmpty validates that a string contains non-whitespace content.
// This validation is more strict than the standard "required" tag as it
// ensures the string has meaningful content beyond just being non-empty.
//
// Validation Rules:
//   - Must contain at least one non-whitespace character
//   - Strings containing only spaces/tabs/newlines are invalid
//
// Parameters:
//   - fl: FieldLevel containing the value to validate
//
// Returns:
//   - bool: True if the value contains non-whitespace content, false otherwise
//
// Example:
//
//	type Document struct {
//	    Title string `validate:"notempty"` // Valid: "Hello", Invalid: "   "
//	}
func validateNotEmpty(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return strings.TrimSpace(value) != ""
}
