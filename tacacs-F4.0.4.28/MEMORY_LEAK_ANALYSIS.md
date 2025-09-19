# Memory Leak and File Descriptor Analysis

## Issues Found

### 1. **CRITICAL: TLS Configuration Variables Not Cleaned Up**

**Location**: `config.c` - `cfg_clean_config()` function
**Issue**: TLS configuration variables (`tls_cert_path`, `tls_key_path`, `tls_ca_path`) are allocated with `tac_strdup()` but never freed in the cleanup function.

**Code**:
```c
char *tls_cert_path = NULL;
char *tls_key_path = NULL;
char *tls_ca_path = NULL;

// In parsing:
if (tls_cert_path) {
    free(tls_cert_path);  // Only freed when reallocating
}
tls_cert_path = tac_strdup(sym_buf);
```

**Impact**: Memory leak on every configuration reload.

### 2. **CRITICAL: Pollfd Array Not Freed**

**Location**: `tac_plus.c` - main loop
**Issue**: `pfds` array is allocated with `malloc()` but never freed.

**Code**:
```c
pfds = malloc(sizeof(struct pollfd) * total_sockets);
// Never freed anywhere
```

**Impact**: Memory leak on every configuration reload.

### 3. **POTENTIAL: TLS Context Not Cleaned Up on Exit**

**Location**: `tls_support.c` - `tls_cleanup()` function
**Issue**: TLS context is only cleaned up when explicitly called, not on program exit.

**Impact**: Memory leak on program termination.

### 4. **POTENTIAL: File Descriptor Leaks in Error Paths**

**Location**: `tac_plus.c` - main loop error handling
**Issue**: Some error paths may not properly close file descriptors.

**Code**:
```c
if (tls_accept(newsockfd) != 0) {
    shutdown(newsockfd, 2);
    close(newsockfd);
    continue;  // Good
}
```

**Status**: This appears to be handled correctly.

### 5. **POTENTIAL: Accounting File Descriptor**

**Location**: `do_acct.c` - `do_acct_file()`
**Issue**: Accounting file descriptor is opened but may not be closed in all error paths.

**Code**:
```c
if (!acctfd) {
    acctfd = open(session.acctfile, O_CREAT | O_WRONLY | O_APPEND, 0644);
    // ...
}
// ...
close(acctfd);
acctfd = 0;
```

**Status**: This appears to be handled correctly.

## Fixes Required

### Fix 1: Add TLS Configuration Cleanup
Add TLS configuration variable cleanup to `cfg_clean_config()`:

```c
void
cfg_clean_config(void)
{
    // ... existing code ...
    
    /* Clean up TLS configuration variables */
    if (tls_cert_path) {
        free(tls_cert_path);
        tls_cert_path = NULL;
    }
    if (tls_key_path) {
        free(tls_key_path);
        tls_key_path = NULL;
    }
    if (tls_ca_path) {
        free(tls_ca_path);
        tls_ca_path = NULL;
    }
}
```

### Fix 2: Add Pollfd Array Cleanup
Add pollfd array cleanup to `cfg_clean_config()`:

```c
void
cfg_clean_config(void)
{
    // ... existing code ...
    
    /* Clean up pollfd array */
    if (pfds) {
        free(pfds);
        pfds = NULL;
    }
}
```

### Fix 3: Add TLS Cleanup on Exit
Add TLS cleanup to the exit handler:

```c
static RETSIGTYPE
die(int signum)
{
    // ... existing code ...
    
#ifdef HAVE_TLS
    tls_cleanup();
#endif
    
    // ... rest of function ...
}
```

### Fix 4: Add TLS Cleanup to Configuration Reload
Ensure TLS is cleaned up before reinitializing:

```c
static int
init(void)
{
    if (initialised) {
        cfg_clean_config();
        
        /* Clean up TLS before reinitializing */
#ifdef HAVE_TLS
        tls_cleanup();
#endif
    }
    
    // ... rest of function ...
}
```

## Severity Assessment

### High Priority (Memory Leaks)
1. **TLS Configuration Variables**: Leaks on every reload
2. **Pollfd Array**: Leaks on every reload

### Medium Priority (Resource Management)
3. **TLS Context**: Leaks on program exit
4. **File Descriptors**: Generally handled correctly

### Low Priority (Code Quality)
5. **Error Handling**: Generally robust

## Testing Recommendations

1. **Memory Leak Testing**: Use tools like Valgrind or AddressSanitizer
2. **Configuration Reload Testing**: Test multiple reload cycles
3. **File Descriptor Testing**: Monitor file descriptor usage during operation
4. **Stress Testing**: Long-running tests with many connections

## Tools for Detection

- **Valgrind**: `valgrind --leak-check=full ./tac_plus`
- **AddressSanitizer**: Compile with `-fsanitize=address`
- **File Descriptor Monitoring**: `lsof -p <pid>`
- **Memory Monitoring**: `pmap -x <pid>`

## Conclusion

The codebase has several memory leaks that need to be fixed, particularly around TLS configuration variables and the pollfd array. These leaks occur on every configuration reload, making them significant for long-running servers.
