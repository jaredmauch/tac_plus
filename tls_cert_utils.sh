#!/bin/bash
#
# TLS Certificate Utilities for TACACS+ Server
# Quick reference script for common certificate operations
#

set -e

# Configuration
TACACS_DIR="/etc/tacacs"
CA_DIR="/etc/tacacs/ca"
DOMAIN=""
EMAIL=""
COUNTRY="US"
STATE="State"
CITY="City"
ORG="Organization"
OU="IT Department"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Show usage
show_usage() {
    cat << EOF
TLS Certificate Utilities for TACACS+ Server

Usage: $0 <command> [options]

Commands:
    setup-letsencrypt <domain> <email>     Setup Let's Encrypt certificates
    setup-openssl <domain>                 Setup OpenSSL internal CA and certificates
    renew-letsencrypt                      Renew Let's Encrypt certificates
    verify                                  Verify current certificates
    status                                  Show certificate status
    help                                    Show this help message

Examples:
    $0 setup-letsencrypt tacacs.example.com admin@example.com
    $0 setup-openssl tacacs.internal.local
    $0 renew-letsencrypt
    $0 verify
    $0 status

EOF
}

# Setup Let's Encrypt certificates
setup_letsencrypt() {
    local domain="$1"
    local email="$2"
    
    if [[ -z "$domain" || -z "$email" ]]; then
        log_error "Domain and email are required for Let's Encrypt setup"
        show_usage
        exit 1
    fi
    
    log_info "Setting up Let's Encrypt certificates for $domain"
    
    # Install certbot if not present
    if ! command -v certbot &> /dev/null; then
        log_info "Installing certbot..."
        if command -v apt &> /dev/null; then
            apt update && apt install -y certbot
        elif command -v yum &> /dev/null; then
            yum install -y certbot
        elif command -v pkg &> /dev/null; then
            pkg install -y py39-certbot
        else
            log_error "Cannot install certbot automatically. Please install it manually."
            exit 1
        fi
    fi
    
    # Create TACACS directory
    mkdir -p "$TACACS_DIR"
    chmod 755 "$TACACS_DIR"
    
    # Obtain certificate
    log_info "Obtaining certificate from Let's Encrypt..."
    certbot certonly --standalone \
        --preferred-challenges http \
        -d "$domain" \
        --email "$email" \
        --agree-tos \
        --no-eff-email
    
    # Copy certificates
    log_info "Copying certificates to TACACS directory..."
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$TACACS_DIR/tac_plus.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$TACACS_DIR/tac_plus.key"
    
    # Set permissions
    chmod 644 "$TACACS_DIR/tac_plus.crt"
    chmod 600 "$TACACS_DIR/tac_plus.key"
    chown root:root "$TACACS_DIR/tac_plus."*
    
    # Create CA certificate (use Let's Encrypt root)
    log_info "Setting up CA certificate..."
    curl -s https://letsencrypt.org/certs/isrgrootx1.pem > "$TACACS_DIR/ca.crt"
    chmod 644 "$TACACS_DIR/ca.crt"
    chown root:root "$TACACS_DIR/ca.crt"
    
    log_success "Let's Encrypt certificates setup complete!"
    log_info "Certificates installed in $TACACS_DIR"
    
    # Setup auto-renewal
    setup_auto_renewal
}

# Setup OpenSSL internal CA and certificates
setup_openssl() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        log_error "Domain is required for OpenSSL setup"
        show_usage
        exit 1
    fi
    
    log_info "Setting up OpenSSL internal CA and certificates for $domain"
    
    # Create directories
    mkdir -p "$TACACS_DIR"
    mkdir -p "$CA_DIR"/{certs,crl,newcerts,private}
    chmod 700 "$CA_DIR/private"
    touch "$CA_DIR/index.txt"
    echo 1000 > "$CA_DIR/serial"
    
    # Create CA configuration
    log_info "Creating CA configuration..."
    cat > "$CA_DIR/ca.conf" << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $CA_DIR
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
RANDFILE = \$dir/private/.rand
private_key = \$dir/private/ca.key
certificate = \$dir/certs/ca.crt
crlnumber = \$dir/crlnumber
crl = \$dir/crl/ca.crl
crl_extensions = crl_ext
default_crl_days = 30
default_md = sha256
name_opt = ca_default
cert_opt = ca_default
default_days = 365
preserve = no
policy = policy_strict

[ policy_strict ]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
string_mask = utf8only
default_md = sha256
x509_extensions = v3_ca

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
stateOrProvinceName = State or Province Name
localityName = Locality Name
0.organizationName = Organization Name
organizationalUnitName = Organizational Unit Name
commonName = Common Name
emailAddress = Email Address

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $domain
DNS.2 = ${domain%%.*}
IP.1 = 127.0.0.1
EOF

    # Generate CA
    log_info "Generating CA private key and certificate..."
    openssl genrsa -out "$CA_DIR/private/ca.key" 4096
    chmod 600 "$CA_DIR/private/ca.key"
    
    openssl req -config "$CA_DIR/ca.conf" \
        -key "$CA_DIR/private/ca.key" \
        -new -x509 -days 3650 -sha256 -extensions v3_ca \
        -out "$CA_DIR/certs/ca.crt" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=TACACS+ CA"
    
    # Copy CA certificate
    cp "$CA_DIR/certs/ca.crt" "$TACACS_DIR/ca.crt"
    chmod 644 "$TACACS_DIR/ca.crt"
    chown root:root "$TACACS_DIR/ca.crt"
    
    # Generate server certificate
    log_info "Generating server certificate..."
    openssl genrsa -out "$TACACS_DIR/tac_plus.key" 4096
    chmod 600 "$TACACS_DIR/tac_plus.key"
    
    openssl req -config "$CA_DIR/ca.conf" \
        -key "$TACACS_DIR/tac_plus.key" \
        -new -sha256 -out "$TACACS_DIR/tac_plus.csr" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=$domain"
    
    openssl ca -config "$CA_DIR/ca.conf" \
        -extensions server_cert -days 365 -notext -md sha256 \
        -in "$TACACS_DIR/tac_plus.csr" \
        -out "$TACACS_DIR/tac_plus.crt"
    
    # Clean up
    rm "$TACACS_DIR/tac_plus.csr"
    chmod 644 "$TACACS_DIR/tac_plus.crt"
    chown root:root "$TACACS_DIR/tac_plus."*
    
    log_success "OpenSSL certificates setup complete!"
    log_info "Certificates installed in $TACACS_DIR"
    log_info "CA certificate: $TACACS_DIR/ca.crt"
    log_info "Server certificate: $TACACS_DIR/tac_plus.crt"
    log_info "Server private key: $TACACS_DIR/tac_plus.key"
}

# Renew Let's Encrypt certificates
renew_letsencrypt() {
    log_info "Renewing Let's Encrypt certificates..."
    
    if ! command -v certbot &> /dev/null; then
        log_error "certbot not found. Please install it first."
        exit 1
    fi
    
    certbot renew --post-hook "cp /etc/letsencrypt/live/*/fullchain.pem $TACACS_DIR/tac_plus.crt && cp /etc/letsencrypt/live/*/privkey.pem $TACACS_DIR/tac_plus.key && chmod 644 $TACACS_DIR/tac_plus.crt && chmod 600 $TACACS_DIR/tac_plus.key && chown root:root $TACACS_DIR/tac_plus.* && systemctl reload tac_plus 2>/dev/null || true"
    
    log_success "Certificate renewal complete!"
}

# Verify certificates
verify() {
    log_info "Verifying certificates..."
    
    if [[ ! -f "$TACACS_DIR/tac_plus.crt" ]]; then
        log_error "Server certificate not found: $TACACS_DIR/tac_plus.crt"
        exit 1
    fi
    
    if [[ ! -f "$TACACS_DIR/tac_plus.key" ]]; then
        log_error "Server private key not found: $TACACS_DIR/tac_plus.key"
        exit 1
    fi
    
    # Check certificate validity
    log_info "Checking certificate validity..."
    if openssl x509 -in "$TACACS_DIR/tac_plus.crt" -checkend 86400 >/dev/null 2>&1; then
        log_success "Certificate is valid for at least 24 hours"
    else
        log_warning "Certificate expires within 24 hours or is invalid"
    fi
    
    # Check private key matches certificate
    log_info "Verifying private key matches certificate..."
    cert_modulus=$(openssl x509 -noout -modulus -in "$TACACS_DIR/tac_plus.crt" | openssl md5)
    key_modulus=$(openssl rsa -noout -modulus -in "$TACACS_DIR/tac_plus.key" | openssl md5)
    
    if [[ "$cert_modulus" == "$key_modulus" ]]; then
        log_success "Private key matches certificate"
    else
        log_error "Private key does not match certificate!"
        exit 1
    fi
    
    # Check CA certificate if present
    if [[ -f "$TACACS_DIR/ca.crt" ]]; then
        log_info "Verifying certificate chain..."
        if openssl verify -CAfile "$TACACS_DIR/ca.crt" "$TACACS_DIR/tac_plus.crt" >/dev/null 2>&1; then
            log_success "Certificate chain is valid"
        else
            log_warning "Certificate chain verification failed"
        fi
    fi
    
    log_success "Certificate verification complete!"
}

# Show certificate status
status() {
    log_info "Certificate Status:"
    echo
    
    if [[ -f "$TACACS_DIR/tac_plus.crt" ]]; then
        echo "Server Certificate:"
        openssl x509 -in "$TACACS_DIR/tac_plus.crt" -noout -subject -issuer -dates -text | head -20
        echo
    else
        log_warning "Server certificate not found"
    fi
    
    if [[ -f "$TACACS_DIR/ca.crt" ]]; then
        echo "CA Certificate:"
        openssl x509 -in "$TACACS_DIR/ca.crt" -noout -subject -issuer -dates
        echo
    else
        log_warning "CA certificate not found"
    fi
    
    echo "File permissions:"
    ls -la "$TACACS_DIR"/tac_plus.* 2>/dev/null || log_warning "Certificate files not found"
    ls -la "$TACACS_DIR"/ca.crt 2>/dev/null || log_warning "CA certificate not found"
}

# Setup auto-renewal
setup_auto_renewal() {
    log_info "Setting up automatic certificate renewal..."
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet --post-hook \"cp /etc/letsencrypt/live/*/fullchain.pem $TACACS_DIR/tac_plus.crt && cp /etc/letsencrypt/live/*/privkey.pem $TACACS_DIR/tac_plus.key && chmod 644 $TACACS_DIR/tac_plus.crt && chmod 600 $TACACS_DIR/tac_plus.key && chown root:root $TACACS_DIR/tac_plus.* && systemctl reload tac_plus 2>/dev/null || true\"") | crontab -
    
    log_success "Auto-renewal setup complete!"
    log_info "Certificates will be checked for renewal twice daily"
}

# Main script logic
main() {
    check_root
    
    case "${1:-}" in
        setup-letsencrypt)
            setup_letsencrypt "$2" "$3"
            ;;
        setup-openssl)
            setup_openssl "$2"
            ;;
        renew-letsencrypt)
            renew_letsencrypt
            ;;
        verify)
            verify
            ;;
        status)
            status
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: ${1:-}"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
