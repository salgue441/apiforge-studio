package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType represents the type of JWT token, determining its intended use
// case and validation rules. Different token types have different security
// characteristics and expiration times.
type TokenType string

const (
	// AccessToken is a short-lived token used for API access with frequent
	// expiration
	AccessToken TokenType = "access"

	// RefreshToken is a long-lived token used to obtain new access token
	RefreshToken TokenType = "refresh"

	// APIToken is a long-lived token for prgrammatic API access
	APIToken TokenType = "api"
)

// Claims represents the JWT claims structure with APIForge-specific fields.
// This structure extends the standard JWT registered claims with application-
// specific claims for user identification, authorization, and token management.
type Claims struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	TokenType   TokenType `json:"token_type"`
	Permissions []string  `json:"permissions,omitempty"`
	ProjectID   string    `json:"project_id,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair represents a pair of access and refresh tokens with their
// expiration times. This structure is typically returned after successful
// authentication and used for maintaining user sessions with secure token
// rotation.
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// JWTConfig holds configuration parameters for JWT token generation and
// validation. This structure allows flexible configuration of security
// parameters and token lifetimes.
type JWTConfig struct {
	SecretKey            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	APITokenDuration     time.Duration
	Issuer               string
	Audience             string
}

// JWTManager handles JWT token operations with security best practices.
// It provides methods for token generation, validation, and management with
// proper security controls and error handling.
type JWTManager struct {
	secretKey            []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	apiTokenDuration     time.Duration
	issuer               string
	audience             string
}

// NewJWTManager creates a new JWT manager with configuration validation.
// This function ensures that all configuration parameters meet security
// requirements and provides sensible defaults for optional parameters.
//
// Parameters:
//   - config: JWTConfig containing security parameters and token durations
//
// Returns:
//   - *JWTManager: Initialized JWT manager instance
//   - error: Validation error if configuration is invalid
//
// Example:
//
//	config := auth.JWTConfig{
//	    SecretKey:            "your-32-character-secret-key-here",
//	    AccessTokenDuration:  15 * time.Minute,
//	    RefreshTokenDuration: 7 * 24 * time.Hour,
//	}
//	manager, err := auth.NewJWTManager(config)
//	if err != nil {
//	    log.Fatal("Failed to create JWT manager:", err)
//	}
func NewJWTManager(config JWTConfig) (*JWTManager, error) {
	if len(config.SecretKey) < 32 {
		return nil, errors.New("JWT secret key must be at least 32 characters")
	}

	if config.AccessTokenDuration <= 0 {
		config.AccessTokenDuration = 15 * time.Minute
	}

	if config.RefreshTokenDuration <= 0 {
		config.RefreshTokenDuration = 7 * 24 * time.Hour
	}

	if config.APITokenDuration <= 0 {
		config.APITokenDuration = 365 * 24 * time.Hour
	}

	if config.Issuer == "" {
		config.Issuer = "apiforge-studio"
	}

	if config.Audience == "" {
		config.Audience = "apiforge-studio"
	}

	return &JWTManager{
		secretKey:            []byte(config.SecretKey),
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		apiTokenDuration:     config.APITokenDuration,
		issuer:               config.Issuer,
		audience:             config.Audience,
	}, nil
}

// GenerateTokenPair generates both access and refresh tokens as a paired set.
// The tokens share the same JTI (JWT ID) for correlation and are generated with
// appropriate lifetimes for their respective purposes.
//
// Parameters:
//   - userID: Unique identifier for the user
//   - email: User's email address
//   - role: User's role for authorization
//   - permissions: List of permissions granted to the user
//
// Returns:
//   - *TokenPair: Generated token pair with expiration times
//   - error: Generation error if token creation fails
//
// Example:
//
//	tokenPair, err := manager.GenerateTokenPair(
//	    "user-123",
//	    "user@example.com",
//	    "admin",
//	    []string{"read:users", "write:projects"},
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to generate tokens: %w", err)
//	}
func (jm *JWTManager) GenerateTokenPair(
	userID, email, role string,
	permissions []string,
) (*TokenPair, error) {
	now := time.Now().UTC()
	jti := uuid.New().String()

	accessToken, err := jm.generateToken(
		userID, email, role,
		permissions,
		"",
		AccessToken,
		jti,
		now,
		jm.accessTokenDuration,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := jm.generateToken(
		userID, email, role,
		nil,
		"",
		RefreshToken,
		jti,
		now,
		jm.refreshTokenDuration,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  now.Add(jm.accessTokenDuration),
		RefreshTokenExpiresAt: now.Add(jm.refreshTokenDuration),
		TokenType:             "Bearer",
	}, nil
}

// GenerateAPIToken generates a long-lived API token for programmatic access.
// API tokens are designed for machine-to-machine communication and have longer
// expiration times than user-facing tokens.
//
// Parameters:
//   - userID: Unique identifier for the user
//   - email: User's email address
//   - role: User's role for authorization
//   - permissions: List of permissions granted for API access
//   - projectID: Optional project scope for project-specific tokens
//
// Returns:
//   - string: Generated API token string
//   - error: Generation error if token creation fails
//
// Example:
//
//	apiToken, err := manager.GenerateAPIToken(
//	    "user-123",
//	    "api@example.com",
//	    "api",
//	    []string{"read:data", "write:data"},
//	    "project-456",
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to generate API token: %w", err)
//	}
func (jm *JWTManager) GenerateAPIToken(
	userID, email, role string,
	permissions []string,
	projectID string,
) (string, error) {
	now := time.Now().UTC()
	jti := uuid.New().String()

	return jm.generateToken(
		userID, email, role,
		permissions,
		projectID,
		APIToken,
		jti,
		now,
		jm.apiTokenDuration,
	)
}

// ValidateToken validates a JWT token and returns its claims if valid.
// This method performs comprehensive validation including signature
// verification, expiration checks, and custom claim validation.
//
// Parameters:
//   - tokenString: JWT token string to validate
//
// Returns:
//   - *Claims: Validated token claims
//   - error: Validation error if token is invalid
//
// Example:
//
//	claims, err := manager.ValidateToken(tokenString)
//	if err != nil {
//	    return fmt.Errorf("invalid token: %w", err)
//	}
//
//	// Use claims for authorization
//	if claims.Role != "admin" {
//	    return errors.New("insufficient permissions")
//	}
func (jm *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf(
					"unexpected signing method: %v",
					token.Header["alg"],
				)
			}

			return jm.secretKey, nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if err := jm.validateClaims(claims); err != nil {
		return nil, fmt.Errorf("invalid cliams: %w", err)
	}

	return claims, nil
}

// RefreshTokenPair generates a new token pair using a valid refresh token.
// This method implements secure token rotation by validating the refresh token
// and issuing a new access/refresh token pair.
//
// Parameters:
//   - refreshTokenString: Valid refresh token string
//
// Returns:
//   - *TokenPair: New token pair with updated expiration
//   - error: Validation or generation error if refresh fails
//
// Example:
//
//	newTokenPair, err := manager.RefreshTokenPair(oldRefreshToken)
//	if err != nil {
//	    return fmt.Errorf("token refresh failed: %w", err)
//	}
func (jm *JWTManager) RefreshTokenPair(refreshTokenString string) (*TokenPair, error) {
	claims, err := jm.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.TokenType != RefreshToken {
		return nil, errors.New("token is not a refresh token")
	}

	return jm.GenerateTokenPair(
		claims.UserID,
		claims.Email,
		claims.Role,
		claims.Permissions,
	)
}

// GetTokenExpiry returns the expiry time of a token without full validation.
// This method is useful for token introspection without performing expensive
// signature verification or claim validation.
//
// Parameters:
//   - tokenString: JWT token string to inspect
//
// Returns:
//   - time.Time: Token expiration time
//   - error: Parsing error if token is malformed
//
// Example:
//
//	expiry, err := manager.GetTokenExpiry(tokenString)
//	if err != nil {
//	    log.Printf("Failed to get token expiry: %v", err)
//	} else if expiry.Before(time.Now()) {
//	    log.Println("Token has expired")
//	}
func (jm *JWTManager) GetTokenExpiry(tokenString string) (time.Time, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (any, error) {
			return jm.secretKey, nil
		},
		jwt.WithoutClaimsValidation(),
	)

	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return time.Time{}, errors.New("invalid token claims")
	}

	if claims.ExpiresAt == nil {
		return time.Time{}, errors.New("token has no expiry")
	}

	return claims.ExpiresAt.Time, nil
}

// GetTokenJTI extracts the JTI (JWT ID) from a token without full validation.
// The JTI can be used for token tracking, revocation, or correlation purposes.
//
// Parameters:
//   - tokenString: JWT token string to inspect
//
// Returns:
//   - string: Token's JWT ID (JTI) claim
//   - error: Parsing error if token is malformed
//
// Example:
//
//	jti, err := manager.GetTokenJTI(tokenString)
//	if err != nil {
//	    log.Printf("Failed to extract JTI: %v", err)
//	} else {
//	    log.Printf("Token JTI: %s", jti)
//	}
func (jm *JWTManager) GetTokenJTI(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return jm.secretKey, nil
		},
		jwt.WithoutClaimsValidation(),
	)

	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return claims.ID, nil
}

// Private methods

// generateToken generates a JWT token with specified parameters and claims.
// This internal method handles the actual token creation with proper claim
// population and security settings.
//
// Parameters:
//   - userID: User identifier for the subject claim
//   - email: User's email for identification
//   - role: User's role for authorization
//   - permissions: List of granted permissions
//   - projectID: Optional project scope
//   - tokenType: Type of token being generated
//   - jti: Unique JWT ID for token identification
//   - issuedAt: Token issuance timestamp
//   - duration: Token validity duration
//
// Returns:
//   - string: Signed JWT token string
//   - error: Generation error if token creation fails
func (jm *JWTManager) generateToken(
	userID, email, role string,
	permissions []string,
	projectID string,
	tokenType TokenType,
	jti string,
	issuedAt time.Time,
	duration time.Duration,
) (string, error) {
	claims := Claims{
		UserID:      userID,
		Email:       email,
		Role:        role,
		TokenType:   tokenType,
		Permissions: permissions,
		ProjectID:   projectID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    jm.issuer,
			Subject:   userID,
			Audience:  []string{jm.audience},
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(duration)),
			NotBefore: jwt.NewNumericDate(issuedAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jm.secretKey)
}

// validateClaims performs additional validation on JWT claims beyond standard
// validation. This method checks token expiration, issuer, audience, and
// required custom claims.
//
// Parameters:
//   - claims: Token claims to validate
//
// Returns:
//   - error: Validation error if claims are invalid
func (jm *JWTManager) validateClaims(claims *Claims) error {
	now := time.Now().UTC()
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now) {
		return errors.New("token is expired")
	}

	if claims.NotBefore != nil && claims.NotBefore.Time.After(now) {
		return errors.New("token is not yet valid")
	}

	if claims.Issuer != jm.issuer {
		return errors.New("invalid token issuer")
	}

	if len(claims.Audience) == 0 || claims.Audience[0] != jm.audience {
		return errors.New("invaid token audience")
	}

	if claims.UserID == "" {
		return errors.New("missing user ID in token")
	}

	if claims.Email == "" {
		return errors.New("missing email in token")
	}

	if claims.TokenType != AccessToken &&
		claims.TokenType != RefreshToken &&
		claims.TokenType != APIToken {
		return errors.New("invalid token type")
	}

	return nil
}

// Helper methods

// ExtractTokenFromBearer extracts JWT token from Bearer authorization header.
// This utility function handles the common pattern of Bearer token
// authentication used in HTTP Authorization headers.
//
// Parameters:
//   - authHeader: HTTP Authorization header value
//
// Returns:
//   - string: Extracted JWT token
//   - error: Extraction error if header format is invalid
//
// Example:
//
//	token, err := auth.ExtractTokenFromBearer(r.Header.Get("Authorization"))
//	if err != nil {
//	    return c.JSON(401, map[string]string{"error": "Invalid authorization header"})
//	}
func ExtractTokenFromBearer(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "
	if authHeader == "" {
		return "", errors.New("authorization header is empty")
	}

	if len(authHeader) < len(bearerPrefix) {
		return "", errors.New("invalid authorization header format")
	}

	if authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("authorization header must start with 'Bearer '")
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		return "", errors.New("token is empty")
	}

	return token, nil
}
