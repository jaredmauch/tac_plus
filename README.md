# Tacacs+ (tac_plus)

C Daemon that authenticates requests via the Tacacs+ Protocol and logs accounting information.

This is a fork of Cisco + Shruberry's Tacacas+ daemons (http://www.shrubbery.net/tac_plus/)

## Requirements
- Linux or FreeBSD
- tcpwrappers(-devel)
- pam(-devel)
- libsodium (for Argon2 and modern crypto support)
- libbcrypt (optional, for bcrypt support)
- System crypt() function (for SHA-256/SHA-512 support)

## Supports
- IPv4 + IPv6
- RPM Spec Files included
- SystemD .service files
- PAM Support
- tcpwrappers support
- Syslog Logging
- Modern password hashing algorithms (bcrypt, Argon2, SHA-256, SHA-512)
- RFC 8907 compliance with SHA-2/SHA-3 support
- Backward compatibility with existing DES/MD5 authentication

## Modern Security Features

This fork includes modern security enhancements while maintaining full backward compatibility:

### TLS 1.3 Transport Security (RFC 8907 Compliance)
- **TLS 1.3 Support**: Modern transport security with OpenSSL or mbedTLS
- **Mutual Authentication**: Client and server certificate verification
- **Strong Cipher Suites**: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM
- **Security Hardening**: Disabled compression, session tickets, weak protocols
- **Certificate Management**: Comprehensive guide for Let's Encrypt and OpenSSL

See [TLS_CERTIFICATE_GUIDE.md](TLS_CERTIFICATE_GUIDE.md) for detailed certificate setup instructions.

### Modern Password Hashing
- **Argon2**: Winner of the Password Hashing Competition (2015) - uses libsodium
- **bcrypt**: Adaptive password hashing with configurable cost factor
- **SHA-256/SHA-512**: Strong crypt-based hashing using system crypt()

### RFC 8907 Compliance
- Support for SHA-2 and SHA-3 hash algorithms
- Maintains backward compatibility with MD5/SHA-1
- Enhanced packet encryption options

### Usage Examples

Generate modern password hashes:
```bash
# bcrypt (recommended for new deployments)
tac_pwd -b

# Argon2 (high security)
tac_pwd -a

# SHA-256 crypt
tac_pwd -s 256

# SHA-512 crypt
tac_pwd -s 512
```

Configuration examples:
```
user = alice {
    login = bcrypt $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6vKz4Q5Q2O
}

user = bob {
    login = argon2 $argon2id$v=19$m=65536,t=3,p=4$salt$hash
}

user = charlie {
    login = sha256 $5$rounds=5000$salt$hash
}
```

## Default Behavior
- tacacs+ logs accounting to syslog and /var/log/tac_plus.acct
- PIDS live in /var/run/tac_plus

## INSTALLING
Build from source (./configure ; make ; make install)
or build an RPM
- rpmbuild -ba tacacs.spec

### RPM Build
- git clone git@github.com:facebook/tac_plus.git
- cd tac_plus
- mkdir -p ~/rpmbuild/SOURCES
- tar cvzf ~/rpmbuild/SOURCES/tacacs-F4.0.4.28.tar.gz tacacs-F4.0.4.28
- echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
- sudo yum install rpm-build redhat-rpm-config gcc bison flex m4 pam-devel tcp_wrappers tcp_wrappers-devel
- rpmbuild -ba tacacs.spec
- Have a beer 🍺

## License
tac_plus is MIT licensed, as found in the LICENSE file.
