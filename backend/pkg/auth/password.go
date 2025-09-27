package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// PasswordHasher defines the interface for secure password hashing operations.
// This interface supports multiple hashing algorithms and provides methods for
// password verification and hash maintenance.
type PasswordHasher interface {
	// HashPassword creates a secure hash of a password using the configured
	// algorithm.
	//
	// Parameters:
	//   - password: Plain text password to hash
	//
	// Returns:
	//   - string: Encoded password hash suitable for storage
	//   - error: Hashing error if operation fails
	HashPassword(password string) (string, error)

	// VerifyPassword compares a plain text password against a stored hash.
	// This method uses constant-time comparison to prevent timing attacks.
	//
	// Parameters:
	//   - password: Plain text password to verify
	//   - hash: Stored password hash to verify against
	//
	// Returns:
	//   - error: Verification error if passwords don't match
	VerifyPassword(password, hash string) error

	// NeedsRehash checks if a stored hash needs to be updated.
	// This is useful when hashing parameters change (e.g., cost increates).
	//
	// Parameters:
	//   - hash: Stored password hash to check
	//
	// Returns:
	//   - bool: True if the hash should be rehashed with current parameters
	NeedsRehash(hash string) bool
}

// HashingAlgorithm represents the supported password hashing algorithms.
// The package supports both bcrypt and Argon2id for different security requirements.
type HashingAlgorithm string

const (
	// Bcrypt uses the bcrypt algorithm, suitable for general-purpose applications
	// with good security and wide compatibility.
	Bcrypt HashingAlgorithm = "bcrypt"

	// Argon2 uses the Argon2id algorithm, winner of the Password Hashing
	// Competition, providing superior resistance to GPU and ASIC attacks.
	Argon2 HashingAlgorithm = "argon2"
)

// PasswordHasherConfig holds configuration parameters for password hashing.
// This structure allows flexible configuration of different hashing algorithms
// with their specific parameters.
type PasswordHasherConfig struct {
	Algorithm    HashingAlgorithm
	BcryptCost   int
	Argon2Config *Argon2Config
}

// Argon2Config holds Argon2id algorithm-specific configuration parameters.
// These parameters control the computational cost and memory usage of hashing.
type Argon2Config struct {
	Memory      uint32 // Memory usage in kilobytes (affects GPU resistance)
	Iterations  uint32 // Number of iterations (time cost)
	Parallelism uint8  // Number of parallel threads (CPU cores)
	SaltLength  uint32 // Salt length in bytes (recommended: 16)
	KeyLength   uint32 // Output hash length in bytes (recommended: 32)
}

// DefaultArgon2Config returns a secure default Argon2 configuration.
// These defaults provide strong security for most applications while
// maintaining reasonable performance characteristics.
//
// Returns:
//   - *Argon2Config: Secure default Argon2 configuration
//
// Default Values:
//   - Memory: 64 MB (64 * 1024 KB)
//   - Iterations: 3
//   - Parallelism: 2 threads
//   - Salt Length: 16 bytes
//   - Key Length: 32 bytes
func DefaultArgon2Config() *Argon2Config {
	return &Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// NewPasswordHasher creates a new password hasher based on the provided
// configuration. This factory function validates configuration parameters and
// returns the appropriate hasher implementation for the specified algorithm.
//
// Parameters:
//   - config: PasswordHasherConfig with algorithm selection and parameters
//
// Returns:
//   - PasswordHasher: Initialized password hasher instance
//   - error: Configuration error if parameters are invalid
//
// Example:
//
//	config := auth.PasswordHasherConfig{
//	    Algorithm: auth.Argon2,
//	    Argon2Config: auth.DefaultArgon2Config(),
//	}
//
//	hasher, err := auth.NewPasswordHasher(config)
//	if err != nil {
//	    log.Fatal("Failed to create password hasher:", err)
//	}
func NewPasswordHasher(config PasswordHasherConfig) (PasswordHasher, error) {
	switch config.Algorithm {
	case Bcrypt:
		return NewBcryptHasher(config.BcryptCost)
	case Argon2:
		if config.Argon2Config == nil {
			config.Argon2Config = DefaultArgon2Config()
		}

		return NewArgon2Hasher(config.Argon2Config)
	default:
		return nil, fmt.Errorf(
			"unsupported hashing algorithm: %s",
			config.Algorithm,
		)
	}
}

// Bcrypt Implementation

// BcryptHasher implements password hashing using the bcrypt algorithm.
// Bcrypt is a well-established algorithm that provides good security and
// is widely supported across different platforms and languages.
//
// Advantages:
//   - Widely supported and battle-tested
//   - Automatic salt generation and storage
//   - Built-in work factor adjustment
//
// Limitations:
//   - Maximum password length of 72 bytes
//   - Less resistant to GPU attacks than Argon2
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new bcrypt hasher with validated cost parameter.
//
// Parameters:
//   - cost: Bcrypt cost factor (4-31, higher is more secure but slower)
//
// Returns:
//   - *BcryptHasher: Initialized bcrypt hasher
//   - error: Validation error if cost is out of range
//
// Recommended Costs:
//   - Development: 10-12
//   - Production: 12-14
//   - High Security: 14-16
func NewBcryptHasher(cost int) (*BcryptHasher, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf(
			"invalid bcrypt cost: %d (must be between %d and %d)",
			cost,
			bcrypt.MinCost,
			bcrypt.MaxCost,
		)
	}

	return &BcryptHasher{cost: cost}, nil
}

// HashPassword hashes a password using bcrypt with the configured cost factor.
// Bcrypt automatically generates a cryptographically secure salt and includes
// it in the output hash.
//
// Parameters:
//   - password: Plain text password to hash
//
// Returns:
//   - string: Bcrypt-encoded hash string
//   - error: Hashing error if password is too long or hashing fails
//
// Security Note: Bcrypt truncates passwords longer than 72 bytes.
func (bh *BcryptHasher) HashPassword(password string) (string, error) {
	if len(password) > 72 {
		return "", errors.New("password too long for bcrypt (max 72 bytes)")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bh.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against a bcrypt hash using constant-time
// comparison.
//
// Parameters:
//   - password: Plain text password to verify
//   - hash: Bcrypt-encoded hash to verify against
//
// Returns:
//   - error: Verification error if passwords don't match or hash is invalid
func (bh *BcryptHasher) VerifyPassword(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}

		return fmt.Errorf("failed to verify password: %w", err)
	}

	return nil
}

// NeedsRehash checks if a bcrypt hash needs to be updated due to cost factor
// changes.
//
// Parameters:
//   - hash: Bcrypt-encoded hash to check
//
// Returns:
//   - bool: True if the hash was created with a different cost factor
func (bh *BcryptHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}

	return cost != bh.cost
}

// Argon2 Implementation

// Argon2Hasher implements password hashing using the Argon2id algorithm.
// Argon2id is the winner of the Password Hashing Competition and provides
// superior resistance to GPU and ASIC attacks compared to bcrypt.
//
// Advantages:
//   - Winner of Password Hashing Competition
//   - Highly resistant to GPU/ASIC attacks
//   - Configurable memory and parallelism parameters
//   - No practical password length limits
//
// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
type Argon2Hasher struct {
	config *Argon2Config
}

// NewArgon2Hasher creates a new Argon2id hasher with validated configuration.
//
// Parameters:
//   - config: Argon2 configuration parameters
//
// Returns:
//   - *Argon2Hasher: Initialized Argon2 hasher
//   - error: Validation error if configuration is invalid
func NewArgon2Hasher(config *Argon2Config) (*Argon2Hasher, error) {
	if config == nil {
		return nil, errors.New("Argon2 config cannot be nil")
	}

	if config.Memory < 1024 {
		return nil, errors.New("Argon2 memory must be at least 1MB")
	}

	if config.Iterations < 1 {
		return nil, errors.New("Argon2 iterations must be at least 1")
	}

	if config.Parallelism < 1 {
		return nil, errors.New("Argon2 parallelism must be at least 1")
	}

	if config.SaltLength < 8 {
		return nil, errors.New("Argon2 salt length must be at least 8 bytes")
	}

	if config.KeyLength < 16 {
		return nil, errors.New("Argon2 key length must be at least 16 bytes")
	}

	return &Argon2Hasher{config: config}, nil
}

// HashPassword hashes a password using Argon2id with cryptographically secure
// salt. The output format follows the PHC string format for interoperability.
//
// Parameters:
//   - password: Plain text password to hash
//
// Returns:
//   - string: Argon2-encoded hash string in PHC format
//   - error: Hashing error if salt generation or hashing fails
//
// Hash Format: $argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$T25lVHdvVGhyZWVGb3Vy
func (ah *Argon2Hasher) HashPassword(password string) (string, error) {
	salt := make([]byte, ah.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		ah.config.Iterations,
		ah.config.Memory,
		ah.config.Parallelism,
		ah.config.KeyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		ah.config.Memory,
		ah.config.Iterations,
		ah.config.Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

// VerifyPassword verifies a password against an Argon2id hash using
// constant-time comparison.
//
// Parameters:
//   - password: Plain text password to verify
//   - encodedHash: Argon2-encoded hash in PHC format
//
// Returns:
//   - error: Verification error if passwords don't match or hash is invalid
func (ah *Argon2Hasher) VerifyPassword(password, encodedHash string) error {
	memory, iterations, parallelism, salt, hash, err := ah.parseHash(encodedHash)
	if err != nil {
		return fmt.Errorf("failed to parse hash: %w", err)
	}

	passwordHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(hash)),
	)

	if subtle.ConstantTimeCompare(hash, passwordHash) != 1 {
		return ErrInvalidCredentials
	}

	return nil
}

// NeedsRehash checks if an Argon2id hash needs to be updated due to parameter
// changes.
//
// Parameters:
//   - encodedHash: Argon2-encoded hash to check
//
// Returns:
//   - bool: True if the hash was created with different parameters
func (ah *Argon2Hasher) NeedsRehash(encodedHash string) bool {
	memory, iterations, parallelism, _, _, err := ah.parseHash(encodedHash)
	if err != nil {
		return true
	}

	return memory != ah.config.Memory ||
		iterations != ah.config.Iterations ||
		parallelism != ah.config.Parallelism
}

// parseHash parses an Argon2-encoded hash string and extracts its components.
// This internal method handles the PHC string format used by Argon2.
//
// Parameters:
//   - encodedHash: Argon2-encoded hash string
//
// Returns:
//   - memory: Memory parameter from hash
//   - iterations: Iterations parameter from hash
//   - parallelism: Parallelism parameter from hash
//   - salt: Decoded salt bytes
//   - hash: Decoded hash bytes
//   - error: Parsing error if format is invalid
func (ah *Argon2Hasher) parseHash(encodedHash string) (uint32, uint32, uint8, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 0 {
		return 0, 0, 0, nil, nil, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("not an Argon2id hash")
	}

	if parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, errors.New("unsupported Argon2 version")
	}

	var memory, iterations uint32
	var parallelism uint8

	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&memory,
		&iterations,
		&parallelism,
	)

	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("failed to parse parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	return memory, iterations, parallelism, salt, hash, nil
}

// PasswordStrengthChecker provides comprehensive password strength validation.
// This component enforces password policies to prevent weak passwords.
type PasswordStrengthChecker struct {
	MinLength      int      // Minimum password length requirement
	RequireUpper   bool     // Require uppercase letters
	RequireLower   bool     // Require lowercase letters
	RequireDigit   bool     // Require numeric digits
	RequireSpecial bool     // Require special characters
	ForbiddenWords []string // List of forbidden/common passwords
}

// DefaultPasswordStrengthChecker returns a secure password strength checker
// configuration. This configuration provides strong password policy
// enforcement suitable for most applications.
//
// Returns:
//   - *PasswordStrengthChecker: Configured password strength checker
//
// Default Policy:
//   - Minimum length: 8 characters
//   - Require uppercase, lowercase, digits, and special characters
//   - Block common weak passwords and application-specific terms
func DefaultPasswordStrengthChecker() *PasswordStrengthChecker {
	return &PasswordStrengthChecker{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		ForbiddenWords: []string{
			"password", "123456", "qwerty", "admin", "login",
			"welcome", "monkey", "dragon", "letmein", "master",
			"apiforge", "studio", "secret", "default",
		},
	}
}

// CheckStrength validates a password against the configured strength
// requirements. This method performs multiple checks and returns detailed
// error messages.
//
// Parameters:
//   - password: Password to validate
//
// Returns:
//   - error: Validation error with specific failure reason
//
// Example:
//
//	err := strengthChecker.CheckStrength("WeakPass123")
//	if err != nil {
//	    fmt.Printf("Password strength failure: %v\n", err)
//	}
func (psc *PasswordStrengthChecker) CheckStrength(password string) error {
	if len(password) < psc.MinLength {
		return fmt.Errorf(
			"password must be at least %d characters long",
			psc.MinLength,
		)
	}

	if len(password) > 128 {
		return errors.New("password is too long (max 128 characters)")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if psc.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	if psc.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	if psc.RequireDigit && !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	if psc.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	lowerPassword := strings.ToLower(password)
	for _, word := range psc.ForbiddenWords {
		if strings.Contains(lowerPassword, strings.ToLower(word)) {
			return fmt.Errorf("password cannot contain the word '%s'", word)
		}
	}

	return nil
}

// GenerateSecurePassword generates a cryptographically secure random password.
// This function uses crypto/rand for secure random number generation.
//
// Parameters:
//   - length: Desired password length (8-128 characters)
//   - includeSymbols: Whether to include special characters
//
// Returns:
//   - string: Generated secure password
//   - error: Generation error if length is invalid or random generation fails
//
// Example:
//
//	password, err := auth.GenerateSecurePassword(16, true)
//	if err != nil {
//	    return fmt.Errorf("failed to generate password: %w", err)
//	}
func GenerateSecurePassword(length int, includeSymbols bool) (string, error) {
	if length < 8 {
		return "", errors.New("password length must be at least 8")
	}

	if length > 128 {
		return "", errors.New("password length cannot exceed 128")
	}

	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	)

	charset := lowercase + uppercase + digits
	if includeSymbols {
		charset += symbols
	}

	password := make([]byte, length)
	for i := range password {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}

		password[i] = charset[randomBytes[0]%byte(len(charset))]
	}

	return string(password), nil
}

// Common authentication errors for consistent error handling.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrWeakPassword       = errors.New("password does not meet strength requirements")
	ErrPasswordTooLong    = errors.New("password is too long")
	ErrPasswordTooShort   = errors.New("password is too short")
)
