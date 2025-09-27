package validator

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

// Validator wraps the go-playground/validator with enhanced functionality
// including custom validation rules, internationalization support, and
// structured error handling.
//
// It provides a production-ready validation solution for Go applications with
// support for context-aware validation and comprehensive error reporting.
type Validator struct {
	validate   *validator.Validate
	translator ut.Translator
}

// New creates and initializes a new Validator instance with custom validation
// rules and English translations. This function sets up JSON tag name usage,
// configures the translator, and registers all custom validation rules.
//
// Returns:
//   - *Validator: Initialized validator instance ready for use
//   - error: Initialization error if any step fails
//
// Example:
//
//	validator, err := New()
//	if err != nil {
//	  log.Fatal("Failed to create validation:", err)
//	}
//	defer // validator cleanup if needed
func New() (*Validator, error) {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}

		return name
	})

	english := en.New()
	uni := ut.New(english, english)
	translator, _ := uni.GetTranslator("en")

	if err := en_translations.RegisterDefaultTranslations(validate, translator); err != nil {
		return nil, fmt.Errorf("failed to register translations: %w", err)
	}

	v := &Validator{
		validate:   validate,
		translator: translator,
	}

	if err := v.registerCustomValidations(); err != nil {
		return nil, fmt.Errorf("failed to register custom validations: %w", err)
	}

	return v, nil
}

// Validate performs structural validation on the provided object and returns
// a collection of validation errors. This is the primary method for validating
// structs with tagged validation rules.
//
// Parameters:
//   - s: The struct or value to validate (must be a struct, pointer to struct, or slice)
//
// Returns:
//   - ValidationErrors: Collection of validation errors, or nil if validation passes
//
// Example:
//
//	type User struct {
//	    Email    string `json:"email" validate:"required,email"`
//	    Password string `json:"password" validate:"required,min=8"`
//	}
//
//	user := User{Email: "invalid", Password: "short"}
//	errors := validator.Validate(user)
//	if len(errors) > 0 {
//	    return c.JSON(400, errors)
//	}
func (v *Validator) Validate(s any) ValidationErrors {
	return v.ValidateWithContext(context.Background(), s)
}

// ValidateWithContext performs structural validation with context support,
// allowing for context-aware validation rules. The context can be used to pass
// additional information to custom validation functions.
//
// Parameters:
//   - ctx: Context containing additional validation information
//   - s: The struct or value to validate
//
// Returns:
//   - ValidationErrors: Collection of validation errors, or nil if validation passes
//
// Example:
//
//	ctx := context.WithValue(context.Background(), "db", dbConnection)
//	errors := validator.ValidateWithContext(ctx, user)
func (v *Validator) ValidateWithContext(ctx context.Context, s any) ValidationErrors {
	err := v.validate.StructCtx(ctx, s)
	if err == nil {
		return nil
	}

	var validationErrors ValidationErrors
	switch e := err.(type) {
	case validator.ValidationErrors:
		for _, fieldError := range e {
			validationError := ValidationError{
				Field: fieldError.Field(),
				Tag:   fieldError.Tag(),
				Value: fmt.Sprintf("%v", fieldError.Value()),
				Param: fieldError.Param(),
			}

			if translated := fieldError.Translate(v.translator); translated != "" {
				validationError.Message = translated
			} else {
				validationError.Message = v.generateFallbackMessage(fieldError)
			}

			validationErrors = append(validationErrors, validationError)
		}

	case *validator.InvalidValidationError:
		validationErrors = append(validationErrors, ValidationError{
			Field:   "validation",
			Tag:     "invalid",
			Message: "Invalid validation target",
		})

	default:
		validationErrors = append(validationErrors, ValidationError{
			Field:   "unknown",
			Tag:     "unknown",
			Message: err.Error(),
		})
	}

	return validationErrors
}

// ValidateVar validates a single variable against a validation tag. This is
// useful for validating individual values without wrapping them in a struct.
//
// Parameters:
//   - field: The value to validate
//   - tag: The validation tag to apply (e.g., "required,email")
//
// Returns:
//   - error: Validation error if validation fails, nil otherwise
//
// Example:
//
//	email := "test@example.com"
//	if err := validator.ValidateVar(email, "required,email"); err != nil {
//	    return fmt.Errorf("invalid email: %w", err)
//	}
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	return v.validate.Var(field, tag)
}

// ValidateVarWithValue validates a field against another field's value using
// a validation tag. This is useful for cross-field validation like password
// confirmation.
//
// Parameters:
//   - field: The primary field value to validate
//   - other: The other field value to compare against
//   - tag: The validation tag specifying the comparison (e.g., "eqfield=Password")
//
// Returns:
//   - error: Validation error if validation fails, nil otherwise
//
// Example:
//
//	password := "secret123"
//	confirmPassword := "secret123"
//	err := validator.ValidateVarWithValue(confirmPassword, password, "eqfield")
//	if err != nil {
//	    return fmt.Errorf("passwords do not match")
//	}
func (v *Validator) ValidateVarWithValue(field, other any, tag string) error {
	return v.validate.VarWithValue(field, other, tag)
}

// registerCustomValidations registers all custom validation rules with the
// underlying validator. This includes domain-specific validations for API
// names, project names, HTTP methods, and other common validation scenarios.
//
// Returns:
//   - error: Registration error if any custom validation fails to register
func (v *Validator) registerCustomValidations() error {
	validations := map[string]validator.Func{
		"apiname":        validateAPIName,
		"projectname":    validateProjectName,
		"httpmethod":     validateHTTPMethod,
		"jsonfield":      validateJSONField,
		"tablename":      validateTableName,
		"gopackage":      validateGoPackage,
		"dockerimage":    validateDockerImage,
		"envname":        validateEnvName,
		"strongpassword": validateStrongPassword,
		"apipath":        validateAPIPath,
		"slug":           validateSlug,
		"semver":         validateSemVer,
		"notempty":       validateNotEmpty,
		"password":       validatePassword,
	}

	for tag, fn := range validations {
		if err := v.validate.RegisterValidation(tag, fn); err != nil {
			return fmt.Errorf("failed to regsiter validation '%s': %w", tag, err)
		}
	}

	return v.registerCustomTranslations()
}

// registerCustomTranslations registers custom error messages for all custom
// validation tags. This ensures that custom validation rules have meaningful,
// human-readable error messages.
//
// Returns:
//   - error: Registration error if any translation fails
func (v *Validator) registerCustomTranslations() error {
	translations := []struct {
		tag         string
		translation string
		override    bool
	}{
		{
			tag:         "apiname",
			translation: "{0} must be a valid API name (letters, numbers, underscores, hyphens)",
			override:    false,
		},
		{
			tag:         "projectname",
			translation: "{0} must be a valid project name",
			override:    false,
		},
		{
			tag:         "httpmethod",
			translation: "{0} must be a valid HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)",
			override:    false,
		},
		{
			tag:         "strongpassword",
			translation: "{0} must contain at least 8 characters with uppercase, lowercase, number, and special character",
			override:    false,
		},
		{
			tag:         "apipath",
			translation: "{0} must be a valid API path starting with /",
			override:    false,
		},
		{
			tag:         "slug",
			translation: "{0} must be a valid slug (lowercase letters, numbers, hyphens)",
			override:    false,
		},
		{
			tag:         "notempty",
			translation: "{0} cannot be empty or contain only whitespace",
			override:    false,
		},
	}

	for _, t := range translations {
		err := v.validate.RegisterTranslation(
			t.tag,
			v.translator,
			registrationFunc(t.tag, t.translation, t.override),
			translateFunc,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

// generateFallbackMessage creates a fallback error message when no translation
// is available for a validation tag. This ensures all validation errors have
// meaningful messages even without custom translations.
//
// Parameters:
//   - fe: The field error to generate a message for
//
// Returns:
//   - string: Generated fallback error message
func (v *Validator) generateFallbackMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", fe.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", fe.Field())
	case "min":
		return fmt.Sprintf(
			"%s must be at least %s characters long",
			fe.Field(),
			fe.Param(),
		)
	case "max":
		return fmt.Sprintf(
			"%s must be at most %s characters long",
			fe.Field(),
			fe.Param(),
		)
	case "len":
		return fmt.Sprintf(
			"%s must be exactly %s characters long",
			fe.Field(),
			fe.Param(),
		)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", fe.Field(), fe.Param())
	default:
		return fmt.Sprintf("%s is invalid", fe.Field())
	}
}

// Helper functions for translation registration

// registrationFunc creates a translation registration function for a specific
// validation tag. This is used internally to register custom error messages
// with the translator.
//
// Parameters:
//   - tag: The validation tag to register translation for
//   - translation: The translated error message template
//   - override: Whether to override existing translations
//
// Returns:
//   - validator.RegisterTranslationsFunc: Registration function for the translator
func registrationFunc(
	tag, translation string,
	override bool,
) validator.RegisterTranslationsFunc {
	return func(ut ut.Translator) (err error) {
		if err = ut.Add(tag, translation, override); err != nil {
			return
		}

		return
	}
}

// translateFunc translates validation errors using the universal translator.
// This function is used as the translation function for custom validation tags.
//
// Parameters:
//   - ut: The universal translator instance
//   - fe: The field error to translate
//
// Returns:
//   - string: Translated error message
func translateFunc(ut ut.Translator, fe validator.FieldError) string {
	t, err := ut.T(fe.Tag(), fe.Field())
	if err != nil {
		return fe.(error).Error()
	}

	return t
}

// Global validator instance management

// globalValidator is the singleton validator instance used by package-level
// convenience functions. This allows applications to use validation without
// managing validator instances explicitly.
var globalValidator *Validator

// InitGlobalValidator initializes the global validator instance. This should
// be called during application startup to ensure the global validator is ready
// for use.
//
// Returns:
//   - error: Initialization error if validator creation fails
//
// Example:
//
//	func main() {
//	    if err := validator.InitGlobalValidator(); err != nil {
//	        log.Fatal("Failed to initialize validator:", err)
//	    }
//	    // Now you can use package-level validation functions
//	}
func InitGlobalValidator() error {
	var err error
	globalValidator, err = New()
	return err
}

// GetGlobalValidator returns the global validator instance, initializing it if
// necessary. This function provides safe access to the global validator with
// lazy initialization.
//
// Returns:
//   - *Validator: The global validator instance
//
// Note: This function will panic if validator initialization fails during lazy
// initialization.
// Use InitGlobalValidator() during app startup for proper error handling.
func GetGlobalValidator() *Validator {
	if globalValidator == nil {
		var err error
		globalValidator, err = New()

		if err != nil {
			panic(fmt.Sprintf("Failed to initialize global validator: %v", err))
		}
	}

	return globalValidator
}

// Convenience functions using the global validator

// Validate validates a struct using the global validator instance. This
// provides a convenient package-level function for common validation scenarios.
//
// Parameters:
//   - s: The struct or value to validate
//
// Returns:
//   - ValidationErrors: Collection of validation errors, or nil if validation passes
//
// Example:
//
//	user := User{Name: "John", Email: "john@example.com"}
//	if errors := validator.Validate(user); len(errors) > 0 {
//	    return handleValidationErrors(errors)
//	}
func Validate(s any) ValidationErrors {
	return GetGlobalValidator().Validate(s)
}

// ValidateWithContext validates a struct with context using the global
// validator instance.
//
// Parameters:
//   - ctx: Context for context-aware validation
//   - s: The struct or value to validate
//
// Returns:
//   - ValidationErrors: Collection of validation errors, or nil if validation passes
func ValidateWithContext(ctx context.Context, s interface{}) ValidationErrors {
	return GetGlobalValidator().ValidateWithContext(ctx, s)
}

// ValidateVar validates a single variable using the global validator instance.
//
// Parameters:
//   - field: The value to validate
//   - tag: The validation tag to apply
//
// Returns:
//   - error: Validation error if validation fails, nil otherwise
func ValidateVar(field interface{}, tag string) error {
	return GetGlobalValidator().ValidateVar(field, tag)
}

// Helper functions for common validation patterns

// ValidateStruct is a convenience function that returns a boolean indicating
// validation success along with the validation errors. This pattern is useful
// when you need both a success flag and the detailed errors.
//
// Parameters:
//   - s: The struct or value to validate
//
// Returns:
//   - bool: True if validation passes, false otherwise
//   - ValidationErrors: Collection of validation errors (empty if validation passes)
//
// Example:
//
//	valid, errors := validator.ValidateStruct(user)
//	if !valid {
//	    return fmt.Errorf("validation failed: %v", errors)
//	}
func ValidateStruct(s interface{}) (bool, ValidationErrors) {
	errors := Validate(s)
	return len(errors) == 0, errors
}

// ValidateStructWithContext is a context-aware version of ValidateStruct.
//
// Parameters:
//   - ctx: Context for context-aware validation
//   - s: The struct or value to validate
//
// Returns:
//   - bool: True if validation passes, false otherwise
//   - ValidationErrors: Collection of validation errors (empty if validation passes)
func ValidateStructWithContext(ctx context.Context, s interface{}) (bool, ValidationErrors) {
	errors := ValidateWithContext(ctx, s)
	return len(errors) == 0, errors
}

// MustValidate panics if validation fails. This function is primarily useful
// in testing scenarios or during initialization where validation failures
// should terminate the application.
//
// Parameters:
//   - s: The struct or value to validate
//
// Example:
//
//	func TestUserValidation(t *testing.T) {
//	    user := User{Name: "Test", Email: "test@example.com"}
//	    validator.MustValidate(user) // Panics if user is invalid
//	}
func MustValidate(s interface{}) {
	if errors := Validate(s); len(errors) > 0 {
		panic(fmt.Sprintf("Validation failed: %v", errors))
	}
}
