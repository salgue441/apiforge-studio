package validator

import "strings"

// ValidationError represents a structured validation error containing detailed
// information about a specific field validation failure. It implements the
// error interface and provides machine-readable error details suitable for API
// responses and client applications.
//
// Fields:
//   - Field: The name of the validated field (matches JSON tag names)
//   - Tag: The validation rule that failed (e.g., "required", "email", "min")
//   - Value: The actual value that failed validation (formatted as string)
//   - Message: Human-readable error message describing the validation failure
//   - Param: Optional parameter for the validation rule (e.g., min length)
//
// Example:
//
//	ValidationError{
//	    Field:   "email",
//	    Tag:     "email",
//	    Value:   "invalid-email",
//	    Message: "email must be a valid email address",
//	}
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Param   string `json:"param"`
}

// ValidationErrors represents a collection of validation errors for multiple
// fields. It implements the error interface and provides utility methods for
// error handling and inspection. This type is typically returned from
// validation operations and can be directly serialized to JSON for API
// responses.
//
// Example usage:
//
//	errors := validator.Validate(user)
//	if len(errors) > 0 {
//	    return c.JSON(400, errors) // Direct JSON serialization
//	}
type ValidationErrors []ValidationError

// Error implements the error interface for ValidationErrors, returning a
// concatenated string of all error messages separated by semicolons. This
// provides a simple way to get a human-readable summary of all validation
// failures.
//
// Returns:
//   - string: Semicolon-separated list of error messages, or empty string if no errors
//
// Example:
//
//	errors := ValidationErrors{
//	    {Message: "Email is required"},
//	    {Message: "Password must be at least 8 characters"},
//	}
//	fmt.Println(errors.Error()) // "Email is required; Password must be at least 8 characters"
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}

	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Message)
	}

	return strings.Join(messages, "; ")
}

// HasField checks whether the validation errors contain any errors for the
// specified field. This is useful for conditionally handling errors for
// specific fields in form validation or API response formatting.
//
// Parameters:
//   - field: The field name to check for errors (case-sensitive)
//
// Returns:
//   - bool: True if any errors exist for the specified field, false otherwise
//
// Example:
//
//	errors := validator.Validate(user)
//	if errors.HasField("email") {
//	    // Show email-specific error message in UI
//	    showEmailError(errors.GetFieldErrors("email"))
//	}
func (ve ValidationErrors) HasField(field string) bool {
	for _, err := range ve {
		if err.Field == field {
			return true
		}
	}

	return false
}

// GetFieldErrors returns all validation errors for a specific field. This is
// particularly useful when you need to display all errors for a single field
// or when implementing field-specific error handling logic.
//
// Parameters:
//   - field: The field name to retrieve errors for (case-sensitive)
//
// Returns:
//   - []ValidationError: Slice of validation errors for the specified field.
//     Returns empty slice if no errors exist for the field.
//
// Example:
//
//	errors := validator.Validate(user)
//	emailErrors := errors.GetFieldErrors("email")
//	for _, err := range emailErrors {
//	    fmt.Printf("Email error: %s\n", err.Message)
//	}
func (ve ValidationErrors) GetFieldErrors(field string) []ValidationError {
	var fieldErrors []ValidationError
	for _, err := range ve {
		if err.Field == field {
			fieldErrors = append(fieldErrors, err)
		}
	}

	return fieldErrors
}

// CreateFieldError creates a custom ValidationError with the specified field,
// tag, and message. This function is useful for creating custom validation
// errors when the built-in validation rules are insufficient or when you need
// to add business logic validation errors.
//
// Parameters:
//   - field: The name of the field that failed validation
//   - tag: The validation rule identifier (e.g., "unique", "business_rule")
//   - message: Human-readable error message describing the validation failure
//
// Returns:
//   - ValidationError: A new ValidationError instance with the provided details
//
// Example:
//
//	if user.EmailExists(email) {
//	    return CreateFieldError("email", "unique", "Email address is already registered")
//	}
func CreateFieldError(field, tag, message string) ValidationError {
	return ValidationError{
		Field:   field,
		Tag:     tag,
		Message: message,
	}
}

// CreateFieldErrors creates multiple ValidationErrors from a map of field
// names to error messages. This is useful for converting business logic
// validation results or external validation results into the standard
// ValidationErrors format.
//
// Parameters:
//   - errors: Map where keys are field names and values are error messages
//
// Returns:
//   - ValidationErrors: Collection of validation errors created from the input map
//
// Example:
//
//	businessErrors := map[string]string{
//	    "username": "Username must be unique",
//	    "password": "Password does not meet security requirements",
//	}
//	validationErrors := CreateFieldErrors(businessErrors)
func CreateFieldErrors(errors map[string]string) ValidationErrors {
	var validationErrors ValidationErrors
	for field, message := range errors {
		validationErrors = append(validationErrors, ValidationError{
			Field:   field,
			Tag:     "custom",
			Message: message,
		})
	}

	return validationErrors
}
