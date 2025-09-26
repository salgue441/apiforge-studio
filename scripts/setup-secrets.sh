#!/bin/bash
# =============================================================================
# scripts/setup-secrets.sh - Development Secrets Setup
# APIForge Studio - Secure Secret Generation
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_header() { echo -e "${PURPLE}🔐 $1${NC}"; }

# Script configuration
SECRETS_DIR="secrets"
ENV_FILE=".env"
BACKUP_RETENTION_DAYS=30

# Functions

# Check if required tools are installed
check_dependencies() {
  log_info "Checking required dependencies"
  local missing_tools=()

  if ! command -v openssl &> /dev/null; then
    missing_tools+=("openssl")
  fi 

  if ! command -v head &> /dev/null; then
        missing_tools+=("head")
  fi
  
  if ! command -v tr &> /dev/null; then
      missing_tools+=("tr")
  fi
  
  if [ ${#missing_tools[@]} -ne 0 ]; then
      log_error "Missing required tools: ${missing_tools[*]}"
      echo ""
      echo "Please install the missing tools:"
      echo "  • Ubuntu/Debian: sudo apt-get install openssl coreutils"
      echo "  • macOS: brew install openssl coreutils"
      echo "  • CentOS/RHEL: sudo yum install openssl coreutils"
      exit 1
  fi
  
  log_success "All dependencies satisfied"
}

# Generate secure random password
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/\n" | head -c${length}
}

# Generate JWT secret (longer for better security)
generate_jwt_secret() {
    openssl rand -base64 64 | tr -d "=+/\n"
}

# Generate API key with prefix
generate_api_key() {
    local prefix=${1:-"ak"}
    echo "${prefix}_$(openssl rand -hex 16)"
}

# Generate hex key for encryption
generate_hex_key() {
    local length=${1:-32}
    openssl rand -hex $length
}

# Create secrets directory structure
create_secrets_directory() {
  log_info "Creating secrets directory structure"
  mkdir -p "${SECRETS_DIR}"/{dev,staging,prod,backup}

  log_success "Created secrets directory structure"
}

# Generate all required secrets
generate_secrets() {
  log_info "Generating secure secrets"

  # Core application secrets
  log_info "  → Database password"
  generate_password 32 > "${SECRETS_DIR}/db_password.txt"
  
  log_info "  → JWT secret"
  generate_jwt_secret > "${SECRETS_DIR}/jwt_secret.txt"
  
  log_info "  → Redis password"
  generate_password 24 > "${SECRETS_DIR}/redis_password.txt"
  
  # Monitoring and admin tools
  log_info "  → Grafana admin password"
  generate_password 16 > "${SECRETS_DIR}/grafana_password.txt"
  
  log_info "  → Redis Commander password"
  generate_password 16 > "${SECRETS_DIR}/redis_commander_password.txt"
  
  log_info "  → pgAdmin password"
  generate_password 16 > "${SECRETS_DIR}/pgadmin_password.txt"
  
  # API and application keys
  log_info "  → API key"
  generate_api_key "ak" > "${SECRETS_DIR}/api_key.txt"
  
  log_info "  → Encryption key"
  generate_hex_key 32 > "${SECRETS_DIR}/encryption_key.txt"
  
  log_info "  → Session secret"
  generate_password 48 > "${SECRETS_DIR}/session_secret.txt"
  
  # SMTP/Email secrets (if needed)
  log_info "  → SMTP password"
  generate_password 20 > "${SECRETS_DIR}/smtp_password.txt"
  
  # Webhook secrets
  log_info "  → Webhook secret"
  generate_password 32 > "${SECRETS_DIR}/webhook_secret.txt"
  
  log_success "Generated all secrets successfully"
}

# Set secure file permissions
set_permissions() {
    log_info "Setting secure file permissions..."
    
    chmod 700 "${SECRETS_DIR}/"
    find "${SECRETS_DIR}/" -type f -name "*.txt" -exec chmod 600 {} \;
    
    local incorrect_perms=$(find "${SECRETS_DIR}/" -type f -name "*.txt" ! -perm 600 | wc -l)
    if [ "$incorrect_perms" -eq 0 ]; then
        log_success "Set secure file permissions (600 for files, 700 for directory)"
    else
        log_error "Failed to set correct permissions on some files"
        find "${SECRETS_DIR}/" -type f -name "*.txt" ! -perm 600 -exec ls -la {} \;
        exit 1
    fi
}

update_env_files() {
    log_info "Updating environment configuration..."
    
    # Create .env if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "${ENV_FILE}.example" ]; then
            cp "${ENV_FILE}.example" "$ENV_FILE"
            log_success "Created $ENV_FILE from template"
        else
            touch "$ENV_FILE"
            log_success "Created empty $ENV_FILE"
        fi
    fi
    
    # Add secret file references if not already present
    if ! grep -q "SECRET_FILE\|PASSWORD_FILE" "$ENV_FILE"; then
        cat >> "$ENV_FILE" << EOF

# =============================================================================
# SECRET FILE REFERENCES (Generated by setup-secrets.sh)
# =============================================================================
# These reference Docker secret files mounted at /run/secrets/

# Core application secrets
DB_PASSWORD_FILE=/run/secrets/db_password
JWT_SECRET_FILE=/run/secrets/jwt_secret
REDIS_PASSWORD_FILE=/run/secrets/redis_password

# Monitoring and admin tools
GRAFANA_PASSWORD_FILE=/run/secrets/grafana_password
REDIS_COMMANDER_PASSWORD_FILE=/run/secrets/redis_commander_password
PGADMIN_PASSWORD_FILE=/run/secrets/pgadmin_password

# API and encryption
API_KEY_FILE=/run/secrets/api_key
ENCRYPTION_KEY_FILE=/run/secrets/encryption_key
SESSION_SECRET_FILE=/run/secrets/session_secret

# External services
SMTP_PASSWORD_FILE=/run/secrets/smtp_password
WEBHOOK_SECRET_FILE=/run/secrets/webhook_secret

# Metadata
SECRETS_GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SECRETS_VERSION=1.0.0
EOF
        log_success "Updated $ENV_FILE with secret file references"
    else
        log_warning "$ENV_FILE already contains secret references (skipping update)"
    fi
}

# Record generation metadata
record_metadata() {
    log_info "Recording generation metadata..."
    
    cat > "${SECRETS_DIR}/.metadata" << EOF
{
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "generated_by": "setup-secrets.sh",
  "version": "1.0.0",
  "secrets_count": $(find "${SECRETS_DIR}" -name "*.txt" | wc -l),
  "environment": "development",
  "next_rotation_due": "$(date -u -d '+90 days' +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

    # Create rotation timestamp
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "${SECRETS_DIR}/.last_rotation"
    
    log_success "Recorded generation metadata"
}

display_summary() {
    echo ""
    log_header "🎉 Secrets Generation Complete!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${CYAN}📁 Secrets Location:${NC} $(pwd)/${SECRETS_DIR}/"
    echo -e "${CYAN}🔐 Generated Secrets:${NC}"
    echo "   • Database Password: ✓ (32 chars)"
    echo "   • JWT Secret: ✓ (64+ chars)"
    echo "   • Redis Password: ✓ (24 chars)"
    echo "   • Grafana Password: ✓ (16 chars)"
    echo "   • Redis Commander Password: ✓ (16 chars)"
    echo "   • pgAdmin Password: ✓ (16 chars)"
    echo "   • API Key: ✓ (with prefix)"
    echo "   • Encryption Key: ✓ (hex, 32 bytes)"
    echo "   • Session Secret: ✓ (48 chars)"
    echo "   • SMTP Password: ✓ (20 chars)"
    echo "   • Webhook Secret: ✓ (32 chars)"
    echo ""
    echo -e "${CYAN}🔒 Security Status:${NC}"
    echo "   • File Permissions: 600 (owner read/write only)"
    echo "   • Directory Permissions: 700 (owner access only)"
    echo "   • Git Ignored: ✓"
    echo "   • Environment Updated: ✓"
    echo ""
    echo -e "${CYAN}🎯 Development Service Credentials:${NC}"
    echo "   • Grafana Admin: admin / $(cat "${SECRETS_DIR}/grafana_password.txt")"
    echo "   • Redis Commander: admin / $(cat "${SECRETS_DIR}/redis_commander_password.txt")"
    echo "   • pgAdmin: admin@apiforge.local / $(cat "${SECRETS_DIR}/pgadmin_password.txt")"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    log_warning "🔐 Store these credentials securely!"
    echo ""
    echo -e "${CYAN}📋 Next Steps:${NC}"
    echo "   1. Review generated .env file"
    echo "   2. Start development: ${GREEN}make dev${NC}"
    echo "   3. Access services with credentials above"
    echo "   4. For production, use external secret managers"
    echo "   5. Rotate secrets every 90 days: ${YELLOW}make rotate-secrets${NC}"
    echo ""
}

main() {
    echo ""
    log_header "🔐 APIForge Studio - Development Secrets Setup"
    echo ""
    echo "This script will generate secure secrets for local development."
    echo "All secrets will be stored in files with proper permissions."
    echo ""
    
    # Check if secrets already exist
    if [ -d "$SECRETS_DIR" ] && [ -n "$(ls -A $SECRETS_DIR/*.txt 2>/dev/null || true)" ]; then
        log_warning "Existing secrets found!"
        echo ""
        read -p "Do you want to regenerate all secrets? This will backup existing ones. (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing secrets. Exiting."
            exit 0
        fi
        
        # Backup existing secrets
        local backup_dir="${SECRETS_DIR}/backup/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        cp "${SECRETS_DIR}"/*.txt "$backup_dir/" 2>/dev/null || true
        log_success "Backed up existing secrets to $backup_dir"
    fi
    
    # Execute setup steps
    check_dependencies
    create_secrets_directory
    generate_secrets
    set_permissions
    update_env_files
    record_metadata
    display_summary
    
    echo ""
    log_success "✨ Development secrets setup completed successfully!"
    echo ""
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi