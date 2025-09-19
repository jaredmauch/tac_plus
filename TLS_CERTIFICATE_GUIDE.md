# TLS Certificate Guide for TACACS+ Server

This guide provides comprehensive instructions for creating and managing TLS certificates for the TACACS+ server, supporting both Let's Encrypt/ACME automation and manual OpenSSL certificate creation.

## Table of Contents

1. [Overview](#overview)
2. [Certificate Requirements](#certificate-requirements)
3. [Let's Encrypt/ACME Setup](#lets-encryptacme-setup)
4. [OpenSSL Manual Certificate Creation](#openssl-manual-certificate-creation)
5. [Certificate Management](#certificate-management)
6. [Configuration Examples](#configuration-examples)
7. [Troubleshooting](#troubleshooting)

## Overview

The TACACS+ server supports TLS 1.3 transport security (RFC 8907 compliance) with mutual authentication. This requires:

- **Server Certificate**: For the TACACS+ server identity
- **Server Private Key**: Corresponding private key
- **CA Certificate**: For client certificate verification (mutual authentication)

## Certificate Requirements

### Server Certificate
- **Format**: PEM (Privacy-Enhanced Mail)
- **Key Size**: 2048-bit RSA minimum, 4096-bit recommended
- **Signature Algorithm**: SHA-256 or stronger
- **Validity**: Maximum 398 days (Let's Encrypt limit) or custom
- **Subject Alternative Names (SAN)**: Include all server hostnames/IPs

### CA Certificate
- **Format**: PEM
- **Purpose**: Verify client certificates
- **Validity**: Long-term (years) for internal CAs

## Let's Encrypt/ACME Setup

### Prerequisites

```bash
# Install certbot
# Ubuntu/Debian
sudo apt update
sudo apt install certbot

# CentOS/RHEL/Rocky Linux
sudo yum install certbot

# FreeBSD
sudo pkg install py39-certbot

# Or use snap (universal)
sudo snap install --classic certbot
```

### Method 1: Standalone HTTP Challenge (Recommended)

```bash
# Create certificate directory
sudo mkdir -p /etc/tacacs
sudo chown root:root /etc/tacacs
sudo chmod 755 /etc/tacacs

# Obtain certificate (replace tacacs.example.com with your domain)
sudo certbot certonly --standalone \
  --preferred-challenges http \
  -d tacacs.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email

# Copy certificates to TACACS+ directory
sudo cp /etc/letsencrypt/live/tacacs.example.com/fullchain.pem /etc/tacacs/tac_plus.crt
sudo cp /etc/letsencrypt/live/tacacs.example.com/privkey.pem /etc/tacacs/tac_plus.key
sudo chmod 644 /etc/tacacs/tac_plus.crt
sudo chmod 600 /etc/tacacs/tac_plus.key
sudo chown root:root /etc/tacacs/tac_plus.*
```

### Method 2: Webroot Challenge (If running web server)

```bash
# Create webroot directory
sudo mkdir -p /var/www/html/.well-known/acme-challenge

# Obtain certificate
sudo certbot certonly --webroot \
  -w /var/www/html \
  -d tacacs.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email

# Copy certificates
sudo cp /etc/letsencrypt/live/tacacs.example.com/fullchain.pem /etc/tacacs/tac_plus.crt
sudo cp /etc/letsencrypt/live/tacacs.example.com/privkey.pem /etc/tacacs/tac_plus.key
sudo chmod 644 /etc/tacacs/tac_plus.crt
sudo chmod 600 /etc/tacacs/tac_plus.key
sudo chown root:root /etc/tacacs/tac_plus.*
```

### Method 3: DNS Challenge (For internal domains)

```bash
# Install DNS plugin (example for Cloudflare)
sudo apt install python3-certbot-dns-cloudflare

# Create credentials file
sudo mkdir -p /etc/letsencrypt
sudo tee /etc/letsencrypt/cloudflare.ini > /dev/null <<EOF
dns_cloudflare_email = admin@example.com
dns_cloudflare_api_key = your-cloudflare-api-key
EOF
sudo chmod 600 /etc/letsencrypt/cloudflare.ini

# Obtain certificate
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  -d tacacs.internal.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email

# Copy certificates
sudo cp /etc/letsencrypt/live/tacacs.internal.example.com/fullchain.pem /etc/tacacs/tac_plus.crt
sudo cp /etc/letsencrypt/live/tacacs.internal.example.com/privkey.pem /etc/tacacs/tac_plus.key
sudo chmod 644 /etc/tacacs/tac_plus.crt
sudo chmod 600 /etc/tacacs/tac_plus.key
sudo chown root:root /etc/tacacs/tac_plus.*
```

### Automatic Renewal Setup

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab for automatic renewal
sudo crontab -e

# Add this line (runs twice daily, checks for renewal)
0 12 * * * /usr/bin/certbot renew --quiet --post-hook "cp /etc/letsencrypt/live/tacacs.example.com/fullchain.pem /etc/tacacs/tac_plus.crt && cp /etc/letsencrypt/live/tacacs.example.com/privkey.pem /etc/tacacs/tac_plus.key && systemctl reload tac_plus"
```

## OpenSSL Manual Certificate Creation

### Create Internal CA (For Development/Internal Use)

```bash
# Create CA directory structure
sudo mkdir -p /etc/tacacs/ca/{certs,crl,newcerts,private}
sudo chmod 700 /etc/tacacs/ca/private
sudo touch /etc/tacacs/ca/index.txt
echo 1000 > /etc/tacacs/ca/serial

# Create CA configuration
sudo tee /etc/tacacs/ca/ca.conf > /dev/null <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = /etc/tacacs/ca
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

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
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

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

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
DNS.1 = tacacs.example.com
DNS.2 = tacacs
IP.1 = 192.168.1.100
IP.2 = 10.0.0.100
EOF

# Generate CA private key
sudo openssl genrsa -out /etc/tacacs/ca/private/ca.key 4096
sudo chmod 600 /etc/tacacs/ca/private/ca.key

# Generate CA certificate
sudo openssl req -config /etc/tacacs/ca/ca.conf \
  -key /etc/tacacs/ca/private/ca.key \
  -new -x509 -days 3650 -sha256 -extensions v3_ca \
  -out /etc/tacacs/ca/certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT Department/CN=TACACS+ CA"

# Copy CA certificate to TACACS+ directory
sudo cp /etc/tacacs/ca/certs/ca.crt /etc/tacacs/ca.crt
sudo chmod 644 /etc/tacacs/ca.crt
```

### Create Server Certificate

```bash
# Generate server private key
sudo openssl genrsa -out /etc/tacacs/tac_plus.key 4096
sudo chmod 600 /etc/tacacs/tac_plus.key

# Generate server certificate signing request
sudo openssl req -config /etc/tacacs/ca/ca.conf \
  -key /etc/tacacs/tac_plus.key \
  -new -sha256 -out /etc/tacacs/tac_plus.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT Department/CN=tacacs.example.com"

# Create server certificate
sudo openssl ca -config /etc/tacacs/ca/ca.conf \
  -extensions server_cert -days 365 -notext -md sha256 \
  -in /etc/tacacs/tac_plus.csr \
  -out /etc/tacacs/tac_plus.crt

# Clean up CSR
sudo rm /etc/tacacs/tac_plus.csr

# Set proper permissions
sudo chmod 644 /etc/tacacs/tac_plus.crt
sudo chown root:root /etc/tacacs/tac_plus.*
```

### Create Client Certificate (For Mutual Authentication)

```bash
# Generate client private key
sudo openssl genrsa -out /etc/tacacs/client.key 4096
sudo chmod 600 /etc/tacacs/client.key

# Generate client certificate signing request
sudo openssl req -config /etc/tacacs/ca/ca.conf \
  -key /etc/tacacs/client.key \
  -new -sha256 -out /etc/tacacs/client.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT Department/CN=tacacs-client"

# Create client certificate
sudo openssl ca -config /etc/tacacs/ca/ca.conf \
  -extensions usr_cert -days 365 -notext -md sha256 \
  -in /etc/tacacs/client.csr \
  -out /etc/tacacs/client.crt

# Clean up CSR
sudo rm /etc/tacacs/client.csr

# Set proper permissions
sudo chmod 644 /etc/tacacs/client.crt
sudo chmod 600 /etc/tacacs/client.key
sudo chown root:root /etc/tacacs/client.*
```

## Certificate Management

### Verify Certificate

```bash
# Check server certificate
openssl x509 -in /etc/tacacs/tac_plus.crt -text -noout

# Check certificate validity
openssl x509 -in /etc/tacacs/tac_plus.crt -checkend 86400

# Verify certificate chain
openssl verify -CAfile /etc/tacacs/ca.crt /etc/tacacs/tac_plus.crt

# Check private key matches certificate
openssl x509 -noout -modulus -in /etc/tacacs/tac_plus.crt | openssl md5
openssl rsa -noout -modulus -in /etc/tacacs/tac_plus.key | openssl md5
```

### Certificate Renewal

```bash
# Let's Encrypt automatic renewal
sudo certbot renew --post-hook "cp /etc/letsencrypt/live/tacacs.example.com/fullchain.pem /etc/tacacs/tac_plus.crt && cp /etc/letsencrypt/live/tacacs.example.com/privkey.pem /etc/tacacs/tac_plus.key && systemctl reload tac_plus"

# Manual OpenSSL renewal
sudo openssl ca -config /etc/tacacs/ca/ca.conf \
  -extensions server_cert -days 365 -notext -md sha256 \
  -in /etc/tacacs/tac_plus.csr \
  -out /etc/tacacs/tac_plus.crt
```

### Certificate Revocation

```bash
# Revoke certificate
sudo openssl ca -config /etc/tacacs/ca/ca.conf \
  -revoke /etc/tacacs/ca/newcerts/1001.pem

# Generate CRL
sudo openssl ca -config /etc/tacacs/ca/ca.conf \
  -gencrl -out /etc/tacacs/ca/crl/ca.crl
```

## Configuration Examples

### TACACS+ Configuration with TLS

```bash
# /etc/tacacs/tac_plus.conf
key = "your-shared-secret"

# Enable TLS
tls
tls-cert = /etc/tacacs/tac_plus.crt
tls-key = /etc/tacacs/tac_plus.key
tls-ca = /etc/tacacs/ca.crt
tls-port = 8443

# User configuration
user = admin {
    login = cleartext password
    service = shell {
        default attribute = permit
    }
}
```

### Systemd Service with Certificate Monitoring

```bash
# /etc/systemd/system/tac_plus.service
[Unit]
Description=TACACS+ Authentication Server
After=network.target

[Service]
Type=forking
PIDFile=/var/run/tac_plus.pid
ExecStart=/usr/local/sbin/tac_plus -C /etc/tacacs/tac_plus.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Certificate monitoring
ExecStartPost=/bin/sleep 5
ExecStartPost=/usr/bin/inotifywait -m -e modify /etc/tacacs/tac_plus.crt /etc/tacacs/tac_plus.key --format '%w%f' | while read file; do systemctl reload tac_plus; done

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Common Issues

1. **Certificate not found**
   ```bash
   # Check file permissions
   ls -la /etc/tacacs/tac_plus.*
   
   # Check file ownership
   sudo chown root:root /etc/tacacs/tac_plus.*
   ```

2. **Private key doesn't match certificate**
   ```bash
   # Verify modulus match
   openssl x509 -noout -modulus -in /etc/tacacs/tac_plus.crt | openssl md5
   openssl rsa -noout -modulus -in /etc/tacacs/tac_plus.key | openssl md5
   ```

3. **Certificate expired**
   ```bash
   # Check expiration
   openssl x509 -in /etc/tacacs/tac_plus.crt -noout -dates
   
   # Renew certificate
   sudo certbot renew
   ```

4. **TLS handshake fails**
   ```bash
   # Test with OpenSSL client
   openssl s_client -connect tacacs.example.com:8443 -cert /etc/tacacs/client.crt -key /etc/tacacs/client.key -CAfile /etc/tacacs/ca.crt
   ```

### Log Analysis

```bash
# Check TACACS+ logs
sudo journalctl -u tac_plus -f

# Check certificate renewal logs
sudo journalctl -u certbot.timer -f

# Check system logs
sudo tail -f /var/log/syslog | grep tac_plus
```

### Performance Considerations

- Use 2048-bit RSA keys for better performance
- Consider ECDSA keys for improved performance
- Monitor certificate expiration dates
- Implement proper certificate rotation procedures

## Security Best Practices

1. **Key Management**
   - Use strong passphrases for private keys
   - Store private keys securely (600 permissions)
   - Regularly rotate certificates
   - Use hardware security modules (HSM) for production

2. **Certificate Validation**
   - Implement certificate pinning
   - Use short certificate lifetimes
   - Monitor certificate expiration
   - Implement proper revocation checking

3. **Network Security**
   - Use firewall rules to restrict access
   - Implement proper network segmentation
   - Monitor TLS connections
   - Use strong cipher suites only

This guide provides comprehensive coverage of TLS certificate management for TACACS+ servers, supporting both automated Let's Encrypt workflows and manual OpenSSL certificate creation for various deployment scenarios.
