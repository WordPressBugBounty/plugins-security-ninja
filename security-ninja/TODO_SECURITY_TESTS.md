# Security Ninja - New Security Tests TODO

## Tests to Implement

### 1. SSL Certificate Validation
- **Test**: `check_ssl_certificate_validity`
- **Description**: Check SSL certificate validity, expiration date, and show warnings for certificates expiring soon
- **Score**: 4
- **Implementation**: Use `openssl_x509_parse()` to check certificate details
- **Status**: TODO

### 2. HTTP to HTTPS Redirect Check
- **Test**: `check_http_to_https_redirect`
- **Description**: Check if HTTP requests are properly redirected to HTTPS
- **Score**: 3
- **Implementation**: Test HTTP response codes and redirects
- **Status**: TODO

### 3. Directory Listing Check
- **Test**: `check_directory_listing`
- **Description**: Check if directory listing is enabled on key directories
- **Score**: 3
- **Implementation**: Test common directories (wp-content/uploads, wp-content/plugins, etc.)
- **Status**: TODO

### 4. XML-RPC Status Check
- **Test**: `check_xmlrpc_status`
- **Description**: Check if XML-RPC is enabled
- **Score**: 3
- **Implementation**: Test if xmlrpc.php is accessible
- **Status**: TODO

### 5. REST API Authentication Check
- **Test**: `check_rest_api_authentication`
- **Description**: Check if sensitive REST API endpoints require authentication
- **Score**: 3
- **Implementation**: Test user endpoints and other sensitive endpoints
- **Status**: TODO

### 6. File Upload Security
- **Test**: `check_file_upload_security`
- **Description**: Check file upload security restrictions
- **Score**: 4
- **Implementation**: Test upload directory permissions and file type restrictions
- **Status**: TODO

### 7. Session Security
- **Test**: `check_session_security`
- **Description**: Check session security configurations
- **Score**: 3
- **Implementation**: Test session timeout, secure cookies, etc.
- **Status**: TODO

## Tests Already Covered (Do NOT implement)

- ✅ MySQL user permissions (already have)
- ✅ Backup files (unwanted files test covers this)
- ✅ Default admin username (already have)
- ✅ Server signature (already have fix)
- ✅ Error log security (already covered)
- ✅ Mixed content (complex, not needed)
- ✅ Rate limiting (cloud firewall module covers this)
- ✅ Server information disclosure (already have)
- ✅ Database connection security (skip)
- ✅ WordPress configuration security (skip)
- ✅ Plugin/theme vulnerabilities (vulnerability scanner covers this)
- ✅ Temporary files (unwanted files test covers this)

## Implementation Priority

1. **SSL Certificate Validation** - High value, easy to implement
2. **HTTP to HTTPS Redirect** - Important for HTTPS sites
3. **Directory Listing** - Simple but effective security check
4. **File Upload Security** - Common attack vector
5. **XML-RPC Status** - If not already covered
6. **REST API Authentication** - Modern WordPress security
7. **Session Security** - Important for user sessions

## Notes

- All tests should be programmatically verifiable
- Focus on simple, definitive pass/fail results
- Avoid complex pattern matching or external dependencies
- Ensure tests work across different server configurations 