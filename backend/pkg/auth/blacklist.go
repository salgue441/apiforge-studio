package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBlacklist defines the interface for token blacklisting operations.
// This interface allows for different storage backends (Redis, in-memory,
// database) while maintaining a consistent API for token revocation management.
type TokenBlacklist interface {
	// BlacklistToken adds a token to the blacklist with an expiration time.
	// The token will be automatically removed from the blacklist after it
	// expires.
	//
	// Parameters:
	//  - ctx: Context for request cancellation and timeouts
	//  - jti: JWT ID (unique token identifier) to blacklist
	//  - expiresAt: Time when the token naturally expires
	//
	// Returns:
	//  - error: Any error that ocurred during blacklisting
	BlacklistToken(ctx context.Context, jti string, expiresAt time.Time) error

	// IsTokenBlacklisted checks if a token is currently blacklisted.
	// This is used during token validation to reject revoked tokens.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeouts
	//   - jti: JWT ID to check for blacklisting
	//
	// Returns:
	//   - bool: True if the token is blacklisted, false otherwise
	//   - error: Any error that occurred during the check
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)

	// CleanupExpiredTokens removes tokens that have expired from the blacklist.
	// This is a maintenance operation to free up storage space.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeouts
	//
	// Returns:
	//   - error: Any error that occurred during cleanup
	CleanupExpiredTokens(ctx context.Context) error

	// GetBlacklistedCount returns the current number of blacklisted tokens.
	// Useful for monitoring and administrative purposes.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeouts
	//
	// Returns:
	//   - int64: Number of blacklisted tokens
	//   - error: Any error that occurred during counting
	GetBlacklistedCount(ctx context.Context) (int64, error)
}

// Redis Implementation

// RedisTokenBlacklist implements TokenBlacklist using Redis for distributed
// storage. This implementation is suitable for multi-instance deployments
// where blacklist state needs to be shared across multiple application servers.
//
// Features:
//   - Automatic expiration via Redis TTL
//   - High performance and scalability
//   - Distributed consistency across instances
//   - Persistent storage (if Redis is configured for persistence)
type RedisTokenBlacklist struct {
	client redis.Cmdable
	prefix string
}

// NewRedisTokenBlacklist creates a new Redis-based token blacklist instance.
// This constructor validates configuration and sets up the Redis client for
// use.
//
// Parameters:
//   - client: Redis client implementing redis.Cmdable interface
//   - prefix: Key prefix for namespacing (default: "auth:blacklist:")
//
// Returns:
//   - *RedisTokenBlacklist: Configured Redis token blacklist instance
//
// Example:
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr: "localhost:6379",
//	})
//
//	blacklist := auth.NewRedisTokenBlacklist(redisClient, "apiforge:blacklist:")
//	defer redisClient.Close()
func NewRedisTokenBlacklist(client redis.Cmdable, prefix string) *RedisTokenBlacklist {
	if prefix == "" {
		prefix = "auth:blacklist"
	}

	return &RedisTokenBlacklist{
		client: client,
		prefix: prefix,
	}
}

// BlacklistToken adds a token to the Redis blacklist with automatic expiration.
// The token is stored in Redis with a TTL that matches its natural expiration
// time, ensuring automatic cleanup without requiring manual intervention.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - jti: JWT ID (unique token identifier) to blacklist
//   - expiresAt: Time when the token naturally expires
//
// Returns:
//   - error: Redis error if the operation fails, nil on success
//
// Example:
//
//	// After user logout or token revocation
//	err := blacklist.BlacklistToken(ctx, claims.ID, claims.ExpiresAt.Time)
//	if err != nil {
//	    log.Printf("Failed to blacklist token: %v", err)
//	}
func (rtb *RedisTokenBlacklist) BlacklistToken(
	ctx context.Context,
	jti string,
	expiresAt time.Time,
) error {
	key := rtb.getKey(jti)
	ttl := time.Until(expiresAt)

	if ttl <= 0 {
		return nil
	}

	err := rtb.client.Set(ctx, key, "blacklisted", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted in Redis.
// This method performs a quick existence check in Redis to determine
// if the token has been revoked.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - jti: JWT ID to check for blacklisting
//
// Returns:
//   - bool: True if the token exists in the blacklist, false otherwise
//   - error: Redis error if the check fails, nil on success
//
// Example:
//
//	// During token validation
//	blacklisted, err := blacklist.IsTokenBlacklisted(ctx, claims.ID)
//	if err != nil {
//	    return fmt.Errorf("failed to check token blacklist: %w", err)
//	}
//	if blacklisted {
//	    return errors.New("token has been revoked")
//	}
func (rtb *RedisTokenBlacklist) IsTokenBlacklisted(
	ctx context.Context,
	jti string,
) (bool, error) {
	key := rtb.getKey(jti)
	exists, err := rtb.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}

	return exists > 0, nil
}

// CleanupExpiredTokens is a no-op for Redis implementation since Redis
// automatically removes expired keys based on their TTL. This method
// is provided for interface compatibility.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//
// Returns:
//   - error: Always returns nil for Redis implementation
func (rtb *RedisTokenBlacklist) CleanupExpiredTokens(ctx context.Context) error {
	// Redis automatically removes expired keys due to TTL,
	// so manual cleanup is not required.
	// This method is maintained for interface compatibility.
	return nil
}

// GetBlacklistedCount returns the number of currently blacklisted tokens
// by scanning Redis keys matching the blacklist pattern.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//
// Returns:
//   - int64: Number of blacklisted tokens
//   - error: Redis error if the count operation fails, nil on success
//
// Example:
//
//	count, err := blacklist.GetBlacklistedCount(ctx)
//	if err != nil {
//	    log.Printf("Failed to get blacklist count: %v", err)
//	} else {
//	    metrics.Gauge("blacklisted_tokens", count)
//	}
func (rtb *RedisTokenBlacklist) GetBlacklistedCount(ctx context.Context) (int64, error) {
	pattern := rtb.prefix + "*"
	keys, err := rtb.client.Keys(ctx, pattern).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count blacklisted tokens: %w", err)
	}

	return int64(len(keys)), nil
}

// getKey generates the Redis key for a token JTI with proper namespacing.
// This internal method ensures consistent key formatting across operations.
//
// Parameters:
//   - jti: JWT ID to convert to Redis key
//
// Returns:
//   - string: Formatted Redis key
func (rtb *RedisTokenBlacklist) getKey(jti string) string {
	return rtb.prefix + jti
}

// InMemory Implementation

// InMemoryTokenBlacklist implements TokenBlacklist using in-memory storage.
// This implementation is suitable for:
//   - Testing environments
//   - Single-instance deployments
//   - Development and prototyping
//   - Scenarios where Redis is not available
//
// Limitations:
//   - Not suitable for multi-instance deployments
//   - Blacklist state is lost on application restart
//   - Memory usage grows with the number of blacklisted tokens
type InMemoryTokenBlacklist struct {
	tokens map[string]time.Time
}

// NewInMemoryTokenBlacklist creates a new in-memory token blacklist instance.
// This is useful for testing or single-server deployments without Redis.
//
// Returns:
//   - *InMemoryTokenBlacklist: New in-memory blacklist instance
//
// Example:
//
//	// For testing or development
//	blacklist := auth.NewInMemoryTokenBlacklist()
//
//	// Use in tests
//	err := blacklist.BlacklistToken(ctx, "test-jti", time.Now().Add(time.Hour))
//	assert.NoError(t, err)
func NewInMemoryTokenBlacklist() *InMemoryTokenBlacklist {
	return &InMemoryTokenBlacklist{
		tokens: make(map[string]time.Time),
	}
}

// BlacklistToken adds a token to the in-memory blacklist.
// The token expiration is stored but automatic cleanup requires
// calling CleanupExpiredTokens periodically.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - jti: JWT ID to blacklist
//   - expiresAt: Time when the token expires
//
// Returns:
//   - error: Always returns nil for in-memory implementation
func (imtb *InMemoryTokenBlacklist) BlacklistToken(
	ctx context.Context,
	jti string,
	expiresAt time.Time,
) error {
	imtb.tokens[jti] = expiresAt
	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted in memory.
// This method automatically removes expired tokens during the check
// to prevent memory leaks.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - jti: JWT ID to check for blacklisting
//
// Returns:
//   - bool: True if the token is blacklisted and not expired
//   - error: Always returns nil for in-memory implementation
func (imtb *InMemoryTokenBlacklist) IsTokenBlacklisted(
	ctx context.Context,
	jti string,
) (bool, error) {
	expiry, exists := imtb.tokens[jti]
	if !exists {
		return false, nil
	}

	if time.Now().UTC().After(expiry) {
		delete(imtb.tokens, jti)
		return false, nil
	}

	return true, nil
}

// CleanupExpiredTokens removes expired tokens from the in-memory blacklist.
// This should be called periodically to prevent memory leaks from accumulated
// expired token entries.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//
// Returns:
//   - error: Always returns nil for in-memory implementation
//
// Example:
//
//	// Periodic cleanup in a background goroutine
//	go func() {
//	    ticker := time.NewTicker(time.Hour)
//	    defer ticker.Stop()
//
//	    for {
//	        select {
//	        case <-ticker.C:
//	            blacklist.CleanupExpiredTokens(context.Background())
//	        case <-ctx.Done():
//	            return
//	        }
//	    }
//	}()
func (imtb *InMemoryTokenBlacklist) CleanupExpiredTokens(ctx context.Context) error {
	now := time.Now().UTC()
	for jti, expiry := range imtb.tokens {
		if now.After(expiry) {
			delete(imtb.tokens, jti)
		}
	}

	return nil
}

// GetBlacklistedCount returns the number of currently blacklisted tokens
// after cleaning up expired entries.
//
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//
// Returns:
//   - int64: Number of active blacklisted tokens
//   - error: Always returns nil for in-memory implementation
func (imtb *InMemoryTokenBlacklist) GetBlacklistedCount(ctx context.Context) (int64, error) {
	imtb.CleanupExpiredTokens(ctx)
	return int64(len(imtb.tokens)), nil
}
