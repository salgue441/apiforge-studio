package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AuthService combines all authentication operations into a single service.
// This service provides a unified interface for token management, password
// operations, role-based authentication, and security features.
//
// The service coordinates between multiple components:
//   - JWTManager: Token generation and valiation
//   - PasswordHasher: Secure password storage and verification
//   - TokenBlacklist: Token revocation management
//   - RoleRegistry: Role and permission management
//   - PasswordStrengthChecker: Password policy enforcement
type AuthService struct {
	jwtManager      *JWTManager
	passwordHasher  PasswordHasher
	tokenBlacklist  TokenBlacklist
	roleRegistry    *RoleRegistry
	strengthChecker *PasswordStrengthChecker
}

// AuthServiceConfig holds configuration parameters for initializing AuthService
// This structure allows flexible configuration of all authentication components
// with sensible defaults for optional parameters.
type AuthServiceConfig struct {
	JWTConfig               JWTConfig
	PasswordHasherConfig    PasswordHasherConfig
	TokenBlacklist          TokenBlacklist
	RoleRegistry            *RoleRegistry
	PasswordStrengthChecker *PasswordStrengthChecker
}

// NewAuthService creates a new authentication service with validated
// configuration. This factory function ensures all dependencies are properly
// initialized and provides sensible defaults for optional components.
//
// Parameters:
//   - config: AuthServiceConfig containing service configuration
//
// Returns:
//   - *AuthService: Initialized authentication service
//   - error: Configuration error if initialization fails
//
// Example:
//
//	config := auth.AuthServiceConfig{
//	    JWTConfig: auth.JWTConfig{
//	        SecretKey: "your-32-character-secret-key",
//	        AccessTokenDuration: 15 * time.Minute,
//	    },
//	    PasswordHasherConfig: auth.PasswordHasherConfig{
//	        Cost: 12,
//	    },
//	    TokenBlacklist: redisBlacklist, // Optional Redis blacklist
//	}
//
//	authService, err := auth.NewAuthService(config)
//	if err != nil {
//	    log.Fatal("Failed to create auth service:", err)
//	}
func NewAuthService(config AuthServiceConfig) (*AuthService, error) {
	jwtManager, err := NewJWTManager(config.JWTConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	passwordHasher, err := NewPasswordHasher(config.PasswordHasherConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create password hasher: %w", err)
	}

	roleRegistry := config.RoleRegistry
	if roleRegistry == nil {
		roleRegistry = NewRoleRegistry()
	}

	strengthChecker := config.PasswordStrengthChecker
	if strengthChecker == nil {
		strengthChecker = DefaultPasswordStrengthChecker()
	}

	return &AuthService{
		jwtManager:      jwtManager,
		passwordHasher:  passwordHasher,
		tokenBlacklist:  config.TokenBlacklist,
		roleRegistry:    roleRegistry,
		strengthChecker: strengthChecker,
	}, nil
}

// LoginCredentials represents user login information for authentication.
// This structure is used for login operations and includes validation tags
// for request validation.
type LoginCredentials struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResult represents the result of a successful login operation.
// This structure contains the generated tokens and user information for
// the authenticated session.
type LoginResult struct {
	TokenPair *TokenPair `json:"token_pair"`
	User      *UserInfo  `json:"user"`
	ExpiresAt time.Time  `json:"expires_at"`
	RefreshAt time.Time  `json:"refresh_at"`
}

// UserInfo represents user information returned after authentication.
// This structure provides essential user data for client applications
// without exposing sensitive information.
type UserInfo struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// CreateUserRequest represents a request to create a new user account.
// This structure includes validation tags for request validation and
// allows specifying custom permissions beyond the base role.
type CreateUserRequest struct {
	Email       string   `json:"email" validate:"required,email"`
	Password    string   `json:"password" validate:"required"`
	Role        string   `json:"role" validate:"required,oneof=user premium admin"`
	Permissions []string `json:"permissions,omitempty"`
}

// ChangePasswordRequest represents a password change operation.
// This structure ensures both current and new passwords are provided
// for secure password updates.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required"`
}

// GenerateTokenPair creates a new access/refresh token pair for a user.
// This method combines role-based permissions with custom permissions
// and generates properly scoped tokens for the user session.
//
// Parameters:
//   - userID: Unique identifier for the user
//   - email: User's email address
//   - role: User's role for permission determination
//   - customPermissions: Additional permissions beyond the role's base permissions
//
// Returns:
//   - *TokenPair: Generated access and refresh tokens with expiration times
//   - error: Token generation error if operation fails
//
// Example:
//
//	tokenPair, err := authService.GenerateTokenPair(
//	    "user-123",
//	    "user@example.com",
//	    "premium",
//	    []string{"project:export", "analytics:advanced"},
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to generate tokens: %w", err)
//	}
func (as *AuthService) GenerateTokenPair(
	userID, email, role string,
	customPermissions []string,
) (*TokenPair, error) {
	rolePermissions := as.roleRegistry.GetRolePermissions(role)
	allPermissions := append(rolePermissions, customPermissions...)
	permissions := removeDuplicates(allPermissions)

	return as.jwtManager.GenerateTokenPair(userID, email, role, permissions)
}

// GenerateAPIToken creates a long-lived API token for programmatic access.
// API tokens are designed for machine-to-machine communication and can be
// scoped to specific projects for enhanced security.
//
// Parameters:
//   - userID: Unique identifier for the user
//   - email: User's email address
//   - role: User's role for permission determination
//   - customPermissions: Additional permissions for API access
//   - projectID: Optional project scope for project-specific tokens
//
// Returns:
//   - string: Generated API token string
//   - error: Token generation error if operation fails
//
// Example:
//
//	apiToken, err := authService.GenerateAPIToken(
//	    "user-123",
//	    "api@example.com",
//	    "service",
//	    []string{"project:read", "project:generate"},
//	    "project-456",
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to generate API token: %w", err)
//	}
func (as *AuthService) GenerateAPIToken(
	userID, email, role string,
	customPermissions []string,
	projectID string,
) (string, error) {
	rolePermissions := as.roleRegistry.GetRolePermissions(role)
	allPermissions := append(rolePermissions, customPermissions...)
	permissions := removeDuplicates(allPermissions)

	return as.jwtManager.GenerateAPIToken(
		userID, email, role, permissions, projectID,
	)
}

// ValidateToken validates a JWT token and checks if it has been revoked.
// This method performs comprehensive validation including signature
// verification, claim validation, and blacklist checking for enhanced security.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - tokenString: JWT token string to validate
//
// Returns:
//   - *Claims: Validated token claims if token is valid
//   - error: Validation error if token is invalid or revoked
//
// Example:
//
//	claims, err := authService.ValidateToken(ctx, tokenString)
//	if err != nil {
//	    if errors.Is(err, auth.ErrTokenRevoked) {
//	        // Handle revoked token (force logout)
//	    }
//	    return fmt.Errorf("token validation failed: %w", err)
//	}
func (as *AuthService) ValidateToken(
	ctx context.Context,
	tokenString string,
) (*Claims, error) {
	claims, err := as.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if as.tokenBlacklist != nil {
		isBlacklisted, err := as.tokenBlacklist.IsTokenBlacklisted(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token blacklist: %w", err)
		}

		if isBlacklisted {
			return nil, ErrTokenRevoked
		}
	}

	return claims, nil
}

// RefreshTokenPair creates a new token pair using a valid refresh token.
// This method implements secure token rotation by validating the refresh token
// and issuing new tokens with updated expiration times.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - refreshToken: Valid refresh token string
//
// Returns:
//   - *TokenPair: New access and refresh tokens
//   - error: Validation or generation error if refresh fails
//
// Example:
//
//	newTokenPair, err := authService.RefreshTokenPair(ctx, oldRefreshToken)
//	if err != nil {
//	    // Force re-authentication if refresh fails
//	    return fmt.Errorf("token refresh failed: %w", err)
//	}
func (as *AuthService) RefreshTokenPair(
	ctx context.Context,
	refreshToken string,
) (*TokenPair, error) {
	claims, err := as.ValidateToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != RefreshToken {
		return nil, errors.New("token is not a refresh token")
	}

	return as.jwtManager.GenerateTokenPair(
		claims.UserID, claims.Email, claims.Role, claims.Permissions,
	)
}

// RevokeToken blacklists a token to prevent further use.
// This method is typically called during logout or when a token needs to be
// invalidated for security reasons.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - tokenString: Token string to revoke
//
// Returns:
//   - error: Revocation error if operation fails
//
// Example:
//
//	// During logout
//	err := authService.RevokeToken(ctx, accessToken)
//	if err != nil {
//	    log.Printf("Warning: failed to revoke token: %v", err)
//	}
func (as *AuthService) RevokeToken(
	ctx context.Context,
	tokenString string,
) error {
	if as.tokenBlacklist == nil {
		return errors.New("token blacklist not configured")
	}

	expiry, err := as.jwtManager.GetTokenExpiry(tokenString)
	if err != nil {
		return fmt.Errorf("failed to get token expiry: %w", err)
	}

	jti, err := as.jwtManager.GetTokenJTI(tokenString)
	if err != nil {
		return fmt.Errorf("failed to get token JTI: %w", err)
	}

	return as.tokenBlacklist.BlacklistToken(ctx, jti, expiry)
}

// RevokeAllUserTokens blacklists all tokens for a specific user.
// This method requires additional token storage infrastructure to track
// all tokens issued to a user. Currently returns an error indicating
// the need for implementation.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - userID: User identifier whose tokens should be revoked
//
// Returns:
//   - error: Always returns an error indicating need for implementation
func (as *AuthService) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// This would require a way to track all tokens for a user
	// For now, we'll return an error indicating this needs to be implemented
	// with a proper token storage mechanism
	return errors.New("revoking all user tokens requires token storage implementation")
}

// HashPassword hashes a password after validating its strength.
// This method ensures that only strong passwords are stored in the system.
//
// Parameters:
//   - password: Plain text password to hash
//
// Returns:
//   - string: Hashed password suitable for storage
//   - error: Hashing error or password strength validation failure
//
// Example:
//
//	hashedPassword, err := authService.HashPassword("SecurePass123!")
//	if err != nil {
//	    return fmt.Errorf("password hashing failed: %w", err)
//	}
func (as *AuthService) HashPassword(password string) (string, error) {
	if err := as.strengthChecker.CheckStrength(password); err != nil {
		return "", fmt.Errorf("password strength validation failed: %w", err)
	}

	return as.passwordHasher.HashPassword(password)
}

// VerifyPassword verifies a password against its stored hash.
// This method uses constant-time comparison to prevent timing attacks.
//
// Parameters:
//   - password: Plain text password to verify
//   - hash: Stored password hash to verify against
//
// Returns:
//   - error: Verification error if password doesn't match
//
// Example:
//
//	err := authService.VerifyPassword(inputPassword, storedHash)
//	if err != nil {
//	    return fmt.Errorf("invalid password: %w", err)
//	}
func (as *AuthService) VerifyPassword(password, hash string) error {
	return as.passwordHasher.VerifyPassword(password, hash)
}

// VerifyAndRehashPassword verifies a password and rehashes if needed.
// This method is useful for password hash upgrades when hashing parameters
// change.
//
// Parameters:
//   - password: Plain text password to verify
//   - hash: Stored password hash to verify against
//
// Returns:
//   - string: Current or updated password hash
//   - bool: True if the password was rehashed, false otherwise
//   - error: Verification error if password doesn't match
//
// Example:
//
//	newHash, rehashed, err := authService.VerifyAndRehashPassword(password, oldHash)
//	if err != nil {
//	    // Password verification failed
//	} else if rehashed {
//	    // Password was verified and rehashed - update stored hash
//	    user.PasswordHash = newHash
//	}
func (as *AuthService) VerifyAndRehashPassword(password, hash string) (string, bool, error) {
	if err := as.passwordHasher.VerifyPassword(password, hash); err != nil {
		return "", false, err
	}

	if as.passwordHasher.NeedsRehash(hash) {
		newHash, err := as.passwordHasher.HashPassword(password)
		if err != nil {
			return hash, false, nil
		}

		return newHash, true, nil
	}

	return hash, false, nil
}

// ValidatePasswordStrength validates password strength without hashing.
// This method is useful for client-side validation or password strength
// indicators.
//
// Parameters:
//   - password: Password to validate
//
// Returns:
//   - error: Validation error if password doesn't meet strength requirements
func (as *AuthService) ValidatePasswordStrength(password string) error {
	return as.strengthChecker.CheckStrength(password)
}

// GetRolePermissions returns all permissions associated with a role.
//
// Parameters:
//   - roleName: Name of the role to get permissions for
//
// Returns:
//   - []string: List of permissions granted to the role
func (as *AuthService) GetRolePermissions(roleName string) []string {
	return as.roleRegistry.GetRolePermissions(roleName)
}

// HasRolePermission checks if a specific role has a given permission.
//
// Parameters:
//   - roleName: Name of the role to check
//   - permission: Permission to check for
//
// Returns:
//   - bool: True if the role has the permission, false otherwise
func (as *AuthService) HasRolePermission(roleName, permission string) bool {
	return as.roleRegistry.HasPermission(roleName, permission)
}

// CreateUserContext creates a UserContext from JWT claims for request handling.
//
// Parameters:
//   - claims: Validated JWT claims
//
// Returns:
//   - *UserContext: User context for request processing
func (as *AuthService) CreateUserContext(claims *Claims) *UserContext {
	return ConvertClaimsToUserContext(claims)
}

// ExtractTokenFromHeader extracts and validates a token from an authorization
// header.
//
// Parameters:
//   - authHeader: HTTP Authorization header value
//
// Returns:
//   - string: Extracted JWT token
//   - error: Extraction error if header format is invalid
func (as *AuthService) ExtractTokenFromHeader(authHeader string) (string, error) {
	return ExtractTokenFromBearer(authHeader)
}

// AuthenticateRequest authenticates an HTTP request and returns user context.
// This is a convenience method that combines token extraction, validation,
// and user context creation in a single operation.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - authHeader: HTTP Authorization header value
//
// Returns:
//   - *UserContext: Authenticated user context
//   - error: Authentication error if any step fails
//
// Example:
//
//	userCtx, err := authService.AuthenticateRequest(ctx, r.Header.Get("Authorization"))
//	if err != nil {
//	    return c.JSON(401, map[string]string{"error": "Authentication failed"})
//	}
func (as *AuthService) AuthenticateRequest(
	ctx context.Context,
	authHeader string,
) (*UserContext, error) {
	token, err := as.ExtractTokenFromHeader(authHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to extract token: %w", err)
	}

	claims, err := as.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	userContext := as.CreateUserContext(claims)
	return userContext, nil
}

// GenerateSecurePassword generates a cryptographically secure random password.
//
// Parameters:
//   - length: Desired password length
//   - includeSymbols: Whether to include special characters
//
// Returns:
//   - string: Generated secure password
//   - error: Generation error if cryptographically secure random fails
func (as *AuthService) GenerateSecurePassword(length int, includeSymbols bool) (string, error) {
	return GenerateSecurePassword(length, includeSymbols)
}

// Cleanup performs maintenance tasks like cleaning up expired blacklist
// entries. This method should be called periodically to maintain system health.
//
// Parameters:
//   - ctx: Context for operation cancellation
//
// Returns:
//   - error: Cleanup error if operation fails
func (as *AuthService) Cleanup(ctx context.Context) error {
	if as.tokenBlacklist != nil {
		return as.tokenBlacklist.CleanupExpiredTokens(ctx)
	}

	return nil
}

// GetBlacklistStats returns statistics about blacklisted tokens.
// Useful for monitoring and administrative purposes.
//
// Parameters:
//   - ctx: Context for operation cancellation
//
// Returns:
//   - int64: Number of currently blacklisted tokens
//   - error: Counting error if operation fails
func (as *AuthService) GetBlacklistStats(ctx context.Context) (int64, error) {
	if as.tokenBlacklist != nil {
		return as.tokenBlacklist.GetBlacklistedCount(ctx)
	}

	return 0, nil
}

// Utility functions

// removeDuplicates removes duplicate strings from a slice while preserving
// order. This internal function is used for permission deduplication.
//
// Parameters:
//   - items: Slice of strings that may contain duplicates
//
// Returns:
//   - []string: Slice with duplicates removed
func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Common authentication errors for consistent error handling across the
// application.
var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrInsufficientRole  = errors.New("insufficient role")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrAuthRequired      = errors.New("authentication required")
)
