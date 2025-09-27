package auth

import (
	"context"
	"errors"
	"slices"
)

// UserContext represents authenticated user information stored in request
// context. This struct is used to pass user authentication and authorization
// data through the request lifecycle without repeatedly parsing JWT tokens.
type UserContext struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
	TokenType   TokenType `json:"token_type"`
	ProjectID   string    `json:"project_id,omitempty"`
	TokenJTI    string    `json:"token_jti"`
}

// Context keys for storing authentication and request information in context.
// These type keys prevent context key collisions and provide type safety.
type contextKey string

const (
	// UserContextKey stores the UserContext in request context
	UserContextKey contextKey = "user"

	// ClaimsKey stores raw JWT Claims in context for advanced use cases
	ClaimsKey contextKey = "claims"

	// RequestIDKey stores the unique request identifier for tracing
	RequestIDKey contextKey = "request_id"

	// TraceIDKey stores the distributed tracing identifier
	TraceIDKey contextKey = "trace_id"
)

// AddUserToContext adds user information to the request context. This function
// should be called by authentication middleware after successful token
// validation to make user data available to downstream handlers.
//
// Parameters:
//   - ctx: The original context to enhance
//   - userCtx: UserContext containing authenticated user information
//
// Returns:
//   - context.Context: New context with user information added
//
// Example
//
//	 func authMiddleware(next http.Handler) http.Handler {
//			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	     token := extractToken(r)
//	     claims, err := jwtManager.ValidateToken(token)
//
//	     if err != nil {
//	       http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	     }
//
//	     userCtx := ConvertClaimsToUserContext(claims)
//	     ctx := auth.AddUserToContext(r.Context(), userCtx)
//	     next.ServeHTTP(w, r.WithContext(ctx))
//	   })
//	 }
func AddUserToContext(ctx context.Context, userCtx *UserContext) context.Context {
	return context.WithValue(ctx, UserContextKey, userCtx)
}

// GetUserFromContext extracts user information from context.
// This function is used by request handlers to access authenticated user data.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - *UserContext: User context if present
//   - bool: True if user context was found, false otherwise
//
// Example:
//
//	func getUserProfile(ctx context.Context) (*UserProfile, error) {
//	    userCtx, ok := auth.GetUserFromContext(ctx)
//	    if !ok {
//	        return nil, errors.New("user not authenticated")
//	    }
//
//	    return userService.GetProfile(userCtx.UserID)
//	}
func GetUserFromContext(ctx context.Context) (*UserContext, bool) {
	user, ok := ctx.Value(UserContextKey).(*UserContext)
	return user, ok
}

// MustGetUserFromContext extracts user from context or panics if not found.
// This function should only be used in contexts where authentication is
// guaranteed by preceding middleware. Use GetUserFromContext for safe access.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - *UserContext: User context (panics if not found)
//
// Example:
//
//	// In a handler where auth middleware already validated the request
//	func secureHandler(ctx context.Context) {
//	    user := auth.MustGetUserFromContext(ctx)
//	    // Safe to use user without nil checks
//	}
func MustGetUserFromContext(ctx context.Context) *UserContext {
	user, ok := GetUserFromContext(ctx)
	if !ok {
		panic("user not found in context")
	}

	return user
}

// AddClaimsToContext adds raw JWT claims to context for advanced use cases.
// This is useful when handlers need access to the full JWT claims structure
// beyond the simplified UserContext.
//
// Parameters:
//   - ctx: The original context to enhance
//   - claims: JWT claims to store in context
//
// Returns:
//   - context.Context: New context with claims added
func AddClaimsToContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ClaimsKey, claims)
}

// GetClaimsFromContext extracts JWT claims from context.
//
// Parameters:
//   - ctx: Context containing claims
//
// Returns:
//   - *Claims: JWT claims if present
//   - bool: True if claims were found, false otherwise
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*Claims)
	return claims, ok
}

// GetUserIDFromContext extracts user ID from context.
// Convenience function for quickly accessing the user ID without full user context.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - string: User ID if present
//   - bool: True if user ID was found, false otherwise
//
// Example:
//
//	userID, ok := auth.GetUserIDFromContext(ctx)
//	if !ok {
//	    return errors.New("user not authenticated")
//	}
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.UserID, true
	}

	return "", false
}

// GetUserEmailFromContext extracts user email from context.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - string: User email if present
//   - bool: True if user email was found, false otherwise
func GetUserEmailFromContext(ctx context.Context) (string, bool) {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.Email, true
	}

	return "", false
}

// GetUserRoleFromContext extracts user role from context.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - string: User role if present
//   - bool: True if user role was found, false otherwise
func GetUserRoleFromContext(ctx context.Context) (string, bool) {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.Role, true
	}

	return "", false
}

// GetUserPermissionsFromContext extracts user permissions from context.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - []string: User permissions if present
//   - bool: True if permissions were found, false otherwise
func GetUserPermissionsFromContext(ctx context.Context) ([]string, bool) {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.Permissions, true
	}

	return nil, false
}

// GetProjectIDFromContext extracts project ID from context for project-scoped tokens.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - string: Project ID if present and non-empty
//   - bool: True if project ID was found and non-empty, false otherwise
func GetProjectIDFromContext(ctx context.Context) (string, bool) {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.ProjectID, user.ProjectID != ""
	}

	return "", false
}

// ConvertClaimsToUserContext converts JWT claims to UserContext for context storage.
// This function transforms the JWT claims into a more convenient format for
// request handlers to use without dealing with JWT-specific details.
//
// Parameters:
//   - claims: JWT claims to convert
//
// Returns:
//   - *UserContext: Converted user context
//
// Example:
//
//	claims, err := jwtManager.ValidateToken(token)
//	if err != nil {
//	    return err
//	}
//	userCtx := auth.ConvertClaimsToUserContext(claims)
//	ctx := auth.AddUserToContext(r.Context(), userCtx)
func ConvertClaimsToUserContext(claims *Claims) *UserContext {
	return &UserContext{
		UserID:      claims.UserID,
		Email:       claims.Email,
		Role:        claims.Role,
		Permissions: claims.Permissions,
		TokenType:   claims.TokenType,
		ProjectID:   claims.ProjectID,
		TokenJTI:    claims.ID,
	}
}

// Role represents a user role with associated permissions and description.
// Roles are used to group permissions and simplify authorization management.
type Role struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// Permission represents a specific permission that can be granted to roles or
// users. Permissions follow the "resource:action" naming convention for
// consistency.
type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// Predefined permissions for APIForge Studio following least privilege
// principle. These permissions control access to various features and
// resources in the system.
var (
	// Project management permissions
	PermissionCreateProject = "project:create"   // Create new projects
	PermissionReadProject   = "project:read"     // View project details
	PermissionUpdateProject = "project:update"   // Modify project settings
	PermissionDeleteProject = "project:delete"   // Delete projects
	PermissionShareProject  = "project:share"    // Share projects with others
	PermissionGenerateCode  = "project:generate" // Generate code from projects
	PermissionDeployProject = "project:deploy"   // Deploy projects to envs

	// User management permissions
	PermissionCreateUser  = "user:create"  // Create new users
	PermissionReadUser    = "user:read"    // View user information
	PermissionUpdateUser  = "user:update"  // Modify user profiles
	PermissionDeleteUser  = "user:delete"  // Delete users
	PermissionSuspendUser = "user:suspend" // Suspend user accounts

	// Analytics and system permissions
	PermissionViewAnalytics   = "analytics:view"  // View usage analytics
	PermissionViewSystemStats = "system:stats"    // View system statistics
	PermissionViewSystemLogs  = "system:logs"     // View system logs
	PermissionManageTemplates = "template:manage" // Manage code templates

	// API key management permissions
	PermissionCreateAPIKey = "apikey:create" // Create API keys
	PermissionRevokeAPIKey = "apikey:revoke" // Revoke API keys

	// System-level administrative permissions
	PermissionSystemAdmin       = "system:admin"       // Full system admin
	PermissionSystemMaintenance = "system:maintenance" // System maintenance ops
)

// Predefined roles with carefully curated permission sets.
// These roles provide graduated access levels from basic user to full
// administrator.
var (
	// RoleUser represents a standard user with basic project management
	// capabilities
	RoleUser = Role{
		Name:        "user",
		Description: "Regular user with basic project access",
		Permissions: []string{
			PermissionCreateProject,
			PermissionReadProject,
			PermissionUpdateProject,
			PermissionDeleteProject,
			PermissionShareProject,
			PermissionGenerateCode,
			PermissionDeployProject,
			PermissionCreateAPIKey,
			PermissionRevokeAPIKey,
		},
	}

	// RolePremium represents a premium user with enhanced features and analytics
	RolePremium = Role{
		Name:        "premium",
		Description: "Premium user with enhanced features",
		Permissions: append(RoleUser.Permissions, []string{
			PermissionViewAnalytics,
			PermissionManageTemplates,
		}...),
	}

	// RoleAdmin represents a system administrator with full access
	RoleAdmin = Role{
		Name:        "admin",
		Description: "Administrator with full system access",
		Permissions: []string{
			// All user permissions
			PermissionCreateProject,
			PermissionReadProject,
			PermissionUpdateProject,
			PermissionDeleteProject,
			PermissionShareProject,
			PermissionGenerateCode,
			PermissionDeployProject,

			// User management
			PermissionCreateUser,
			PermissionReadUser,
			PermissionUpdateUser,
			PermissionDeleteUser,
			PermissionSuspendUser,

			// System permissions
			PermissionViewAnalytics,
			PermissionViewSystemStats,
			PermissionViewSystemLogs,
			PermissionManageTemplates,
			PermissionSystemAdmin,

			// API keys
			PermissionCreateAPIKey,
			PermissionRevokeAPIKey,
		},
	}

	// RoleService represents a service account for internal operations
	RoleService = Role{
		Name:        "service",
		Description: "Service account for internal operations",
		Permissions: []string{
			PermissionReadProject,
			PermissionGenerateCode,
			PermissionViewAnalytics,
		},
	}
)

// RoleRegistry manages available roles and their permissions in a centralized
// registry. This provides a single source of truth for role definitions and
// permissions.
type RoleRegistry struct {
	roles map[string]Role
}

// NewRoleRegistry creates a new role registry with default roles
// pre-registered.
//
// Returns:
//   - *RoleRegistry: Initialized role registry with default roles
func NewRoleRegistry() *RoleRegistry {
	registry := &RoleRegistry{
		roles: make(map[string]Role),
	}

	registry.RegisterRole(RoleUser)
	registry.RegisterRole(RolePremium)
	registry.RegisterRole(RoleAdmin)
	registry.RegisterRole(RoleService)

	return registry
}

// RegisterRole registers a new role in the registry.
//
// Parameters:
//   - role: Role definition to register
func (rr *RoleRegistry) RegisterRole(role Role) {
	rr.roles[role.Name] = role
}

// GetRole retrieves a role by name from the registry.
//
// Parameters:
//   - name: Role name to retrieve
//
// Returns:
//   - Role: Role definition if found
//   - bool: True if role exists, false otherwise
func (rr *RoleRegistry) GetRole(name string) (Role, bool) {
	role, exists := rr.roles[name]
	return role, exists
}

// GetRolePermissions returns the permissions associated with a role.
//
// Parameters:
//   - roleName: Name of the role to get permissions for
//
// Returns:
//   - []string: List of permissions for the role, empty slice if role not found
func (rr *RoleRegistry) GetRolePermissions(roleName string) []string {
	if role, exists := rr.roles[roleName]; exists {
		return role.Permissions
	}

	return []string{}
}

// HasPermission checks if a specific role has a given permission.
//
// Parameters:
//   - roleName: Name of the role to check
//   - permission: Permission to check for
//
// Returns:
//   - bool: True if the role has the permission, false otherwise
func (rr *RoleRegistry) HasPermission(roleName, permission string) bool {
	role, exists := rr.roles[roleName]
	if !exists {
		return false
	}

	return slices.Contains(role.Permissions, permission)
}

// ListRoles returns all registered roles in the registry.
//
// Returns:
//   - []Role: Slice of all registered roles
func (rr *RoleRegistry) ListRoles() []Role {
	roles := make([]Role, 0, len(rr.roles))
	for _, role := range rr.roles {
		roles = append(roles, role)
	}

	return roles
}

// Global role registry instance for convenient access to role definitions.
var defaultRoleRegistry = NewRoleRegistry()

// Authorization helper functions for common authorization patterns.

// HasRole checks if the authenticated user has a specific role.
//
// Parameters:
//   - ctx: Context containing user information
//   - role: Role name to check for
//
// Returns:
//   - bool: True if user has the specified role, false otherwise
//
// Example:
//
//	if auth.HasRole(ctx, "admin") {
//	    // Perform admin-only operation
//	}
func HasRole(ctx context.Context, role string) bool {
	if user, ok := GetUserFromContext(ctx); ok {
		return user.Role == role
	}

	return false
}

// HasPermission checks if the authenticated user has a specific permission.
// This checks both direct user permissions and role-based permissions.
//
// Parameters:
//   - ctx: Context containing user information
//   - permission: Permission to check for
//
// Returns:
//   - bool: True if user has the permission, false otherwise
//
// Example:
//
//	if auth.HasPermission(ctx, "project:create") {
//	    // Allow project creation
//	}
func HasPermission(ctx context.Context, permission string) bool {
	user, ok := GetUserFromContext(ctx)
	if !ok {
		return false
	}

	if slices.Contains(user.Permissions, permission) {
		return true
	}

	return defaultRoleRegistry.HasPermission(user.Role, permission)
}

// HasAnyPermission checks if the user has any of the specified permissions.
//
// Parameters:
//   - ctx: Context containing user information
//   - permissions: List of permissions to check
//
// Returns:
//   - bool: True if user has any of the permissions, false otherwise
//
// Example:
//
//	if auth.HasAnyPermission(ctx, "project:read", "project:write") {
//	    // Allow access to project
//	}
func HasAnyPermission(ctx context.Context, permissions ...string) bool {
	for _, permission := range permissions {
		if HasPermission(ctx, permission) {
			return true
		}
	}

	return false
}

// HasAllPermissions checks if the user has all specified permissions.
//
// Parameters:
//   - ctx: Context containing user information
//   - permissions: List of permissions to check
//
// Returns:
//   - bool: True if user has all permissions, false otherwise
//
// Example:
//
//	if auth.HasAllPermissions(ctx, "project:read", "project:write") {
//	    // Allow full project access
//	}
func HasAllPermissions(ctx context.Context, permissions ...string) bool {
	for _, permission := range permissions {
		if !HasPermission(ctx, permission) {
			return false
		}
	}

	return true
}

// IsAdmin checks if the user has admin role.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - bool: True if user is admin, false otherwise
func IsAdmin(ctx context.Context) bool {
	return HasRole(ctx, "admin")
}

// IsUser checks if the user has at least user-level privileges.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - bool: True if user has user role or higher, false otherwise
func IsUser(ctx context.Context) bool {
	return HasAnyRole(ctx, "user", "premium", "admin")
}

// IsPremium checks if the user has at least premium-level privileges.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - bool: True if user has premium role or higher, false otherwise
func IsPremium(ctx context.Context) bool {
	return HasAnyRole(ctx, "premium", "admin")
}

// IsService checks if the user is a service account.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - bool: True if user is a service account, false otherwise
func IsService(ctx context.Context) bool {
	return HasRole(ctx, "service")
}

// HasAnyRole checks if the user has any of the specified roles.
//
// Parameters:
//   - ctx: Context containing user information
//   - roles: List of roles to check
//
// Returns:
//   - bool: True if user has any of the roles, false otherwise
func HasAnyRole(ctx context.Context, roles ...string) bool {
	user, ok := GetUserFromContext(ctx)
	if !ok {
		return false
	}

	return slices.Contains(roles, user.Role)
}

// RequireAuth returns an error if the user is not authenticated.
//
// Parameters:
//   - ctx: Context containing user information
//
// Returns:
//   - error: Error if not authenticated, nil otherwise
//
// Example:
//
//	func protectedHandler(ctx context.Context) error {
//	    if err := auth.RequireAuth(ctx); err != nil {
//	        return err
//	    }
//	    // Proceed with authenticated user
//	}
func RequireAuth(ctx context.Context) error {
	if _, ok := GetUserFromContext(ctx); !ok {
		return errors.New("authentication required")
	}

	return nil
}

// RequireRole returns an error if the user doesn't have the required role.
//
// Parameters:
//   - ctx: Context containing user information
//   - role: Required role
//
// Returns:
//   - error: Error if role requirement not met, nil otherwise
func RequireRole(ctx context.Context, role string) error {
	if err := RequireAuth(ctx); err != nil {
		return err
	}

	if !HasRole(ctx, role) {
		return errors.New("insufficient role privileges")
	}

	return nil
}

// RequirePermission returns an error if the user doesn't have the required
// permission.
//
// Parameters:
//   - ctx: Context containing user information
//   - permission: Required permission
//
// Returns:
//   - error: Error if permission requirement not met, nil otherwise
func RequirePermission(ctx context.Context, permission string) error {
	if err := RequireAuth(ctx); err != nil {
		return err
	}

	if !HasPermission(ctx, permission) {
		return errors.New("insufficient permissions")
	}

	return nil
}

// RequireAnyPermission returns an error if the user doesn't have any of the
// required permissions.
//
// Parameters:
//   - ctx: Context containing user information
//   - permissions: List of required permissions (any one suffices)
//
// Returns:
//   - error: Error if no permissions are met, nil otherwise
func RequireAnyPermission(ctx context.Context, permissions ...string) error {
	if err := RequireAuth(ctx); err != nil {
		return err
	}

	if !HasAnyPermission(ctx, permissions...) {
		return errors.New("insufficient permissions")
	}

	return nil
}

// CanAccessProject checks if the user can access a specific project.
// This implements project-level authorization with support for project-scoped
// tokens and role-based access control.
//
// Parameters:
//   - ctx: Context containing user information
//   - projectID: Project identifier to check access for
//
// Returns:
//   - bool: True if user can access the project, false otherwise
func CanAccessProject(ctx context.Context, projectID string) bool {
	user, ok := GetUserFromContext(ctx)
	if !ok {
		return false
	}

	if user.Role == "admin" {
		return true
	}

	if user.ProjectID != "" {
		return user.ProjectID == projectID
	}

	return HasPermission(ctx, PermissionReadProject)
}

// RequireProjectAccess returns an error if the user cannot access the 
// specified project.
//
// Parameters:
//   - ctx: Context containing user information
//   - projectID: Project identifier to check access for
//
// Returns:
//   - error: Error if project access is denied, nil otherwise
//
// Example:
//
//	func getProjectHandler(ctx context.Context, projectID string) error {
//	    if err := auth.RequireProjectAccess(ctx, projectID); err != nil {
//	        return err
//	    }
//	    // Proceed with project access
//	}
func RequireProjectAccess(ctx context.Context, projectID string) error {
	if err := RequireAuth(ctx); err != nil {
		return err
	}

	if !CanAccessProject(ctx, projectID) {
		return errors.New("insufficient project access")
	}
	
	return nil
}
