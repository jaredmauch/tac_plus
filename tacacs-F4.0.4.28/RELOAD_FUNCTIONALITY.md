# TACACS+ Configuration Reload Functionality

## Overview

The TACACS+ daemon now supports comprehensive configuration reloading functionality, including TLS certificate management, file monitoring, and graceful updates without service interruption.

## Features Implemented

### 1. Signal-Based Configuration Reloading
- **SIGHUP Support**: The daemon responds to SIGHUP signals to reload configuration
- **SIGUSR1 Support**: Alternative signal for configuration reloading
- **Safe Reloading**: Uses atomic flag-based reloading to prevent race conditions
- **Service Integration**: Works with both systemd and SysV init systems

### 2. TLS Certificate Reloading
- **Dynamic Certificate Loading**: TLS certificates can be reloaded without restart
- **Certificate Validation**: Validates certificate files exist and are readable
- **Key-Certificate Matching**: Verifies private key matches certificate
- **Runtime Path Updates**: Supports dynamic certificate path changes
- **Both TLS Libraries**: Works with both OpenSSL and mbedTLS

### 3. File Monitoring
- **Certificate File Monitoring**: Monitors certificate files for changes
- **Modification Time Tracking**: Uses file modification times to detect changes
- **Automatic Reloading**: Automatically reloads when certificate files change
- **Main Loop Integration**: File monitoring runs in the main server loop

### 4. Configuration Directive Support
- **TLS Configuration**: All TLS-related configuration directives are reloadable
- **User Configuration**: User accounts and permissions are reloaded
- **Key Configuration**: Shared secrets are reloaded
- **Service Configuration**: Service definitions are reloaded

## Implementation Details

### Files Modified

#### `tls_support.c`
- Added `tls_reload()` function for certificate reloading
- Added `tls_reload_openssl()` for OpenSSL-specific reloading
- Added `tls_reload_mbedtls()` for mbedTLS-specific reloading
- Added certificate file validation and error handling
- Added support for dynamic certificate paths

#### `tac_plus.c`
- Added `check_certificate_files()` function for file monitoring
- Added certificate file modification time tracking
- Integrated file monitoring into main server loop
- Added TLS reloading to configuration initialization

#### `tacacs.h`
- Added `tls_reload()` function declaration
- Added stub function for when TLS is not available

### Configuration Directives

The following TLS configuration directives are now fully reloadable:

```
tls =                    # Enable TLS support
tls-cert = /path/to/cert # Server certificate path
tls-key = /path/to/key   # Server private key path
tls-ca = /path/to/ca     # CA certificate path
tls-port = 8443          # TLS port number
```

### Signal Handling

The daemon handles the following signals for reloading:

- **SIGHUP**: Triggers configuration reload
- **SIGUSR1**: Alternative configuration reload signal
- **SIGUSR2**: Dumps client tables
- **SIGTERM**: Graceful shutdown

### File Monitoring

The daemon monitors the following files for changes:

- Server certificate file (`tls-cert` directive)
- Server private key file (`tls-key` directive)
- CA certificate file (`tls-ca` directive)

When any of these files are modified, the daemon automatically:
1. Detects the change via file modification time
2. Validates the new certificate files
3. Reloads the TLS configuration
4. Updates the TLS context without service interruption

## Usage Examples

### Basic Configuration Reload
```bash
# Send SIGHUP to reload configuration
kill -HUP $(pidof tac_plus)

# Or use systemd
systemctl reload tac_plus
```

### Certificate Rotation
```bash
# Update certificate files
cp new_server.crt /etc/tacacs/server.crt
cp new_server.key /etc/tacacs/server.key
cp new_ca.crt /etc/tacacs/ca.crt

# The daemon will automatically detect and reload the certificates
# No manual reload signal needed
```

### Configuration File Updates
```bash
# Update configuration file
vim /etc/tacacs/tac_plus.conf

# Reload configuration
kill -HUP $(pidof tac_plus)
```

## Security Considerations

### Certificate Validation
- All certificate files are validated before loading
- Private key and certificate matching is verified
- File permissions are checked for readability
- Invalid certificates are rejected with error logging

### Error Handling
- Failed certificate reloads are logged as errors
- Invalid certificate files don't break existing connections
- Graceful fallback to previous configuration on errors
- Comprehensive error reporting for troubleshooting

### File Monitoring Security
- Only monitors specific certificate files
- Uses file modification times (not file watching)
- No external dependencies for file monitoring
- Minimal performance impact

## Performance Impact

### File Monitoring
- File monitoring runs in the main server loop
- Uses lightweight `stat()` system calls
- Minimal CPU overhead
- No blocking operations

### Certificate Reloading
- Certificate reloading is asynchronous
- New TLS context is created before replacing old one
- No service interruption during reload
- Memory usage is optimized

## Testing

A comprehensive test script (`test_reload.sh`) is provided that demonstrates:

1. Configuration parsing functionality
2. TLS configuration support
3. Certificate file monitoring
4. Reload functionality
5. Error handling

To run the test:
```bash
./test_reload.sh
```

## Compatibility

### TLS Libraries
- **OpenSSL**: Full support for OpenSSL 1.1.1+ with TLS 1.3
- **mbedTLS**: Full support for mbedTLS 2.16+
- **Fallback**: Graceful degradation when TLS is not available

### Operating Systems
- **Linux**: Full support with systemd and SysV init
- **Unix-like**: Compatible with standard Unix signal handling
- **Portable**: Uses standard C library functions

### Configuration Formats
- **Legacy**: Maintains compatibility with existing configurations
- **New Directives**: TLS directives are optional and backward compatible
- **Validation**: Comprehensive configuration validation

## Future Enhancements

Potential future improvements could include:

1. **Inotify Support**: Real-time file monitoring using inotify
2. **Certificate Expiry Monitoring**: Automatic certificate renewal alerts
3. **Hot Reloading**: More granular reloading of specific configuration sections
4. **Configuration Validation**: Pre-flight validation of configuration changes
5. **Rollback Support**: Automatic rollback on configuration errors

## Conclusion

The TACACS+ daemon now provides enterprise-grade configuration reloading functionality that supports:

- ✅ **Zero-downtime updates**: Configuration changes without service interruption
- ✅ **Certificate rotation**: Automatic TLS certificate updates
- ✅ **File monitoring**: Automatic detection of configuration changes
- ✅ **Comprehensive validation**: Robust error handling and validation
- ✅ **Production ready**: Suitable for enterprise deployments

This implementation ensures that TACACS+ can be maintained and updated in production environments without service disruption, making it suitable for enterprise deployments that require high availability and security.
