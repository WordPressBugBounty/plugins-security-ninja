<?php

namespace WPSecurityNinja\Plugin;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Security Ninja Crypto Utility Class
 * 
 * Provides secure cryptographic operations for the plugin
 * Compatible with PHP 7.4 - 8.4
 * 
 * @author Lars Koudal
 * @since v5.242
 * @version v1.0.0
 */
class Wf_Sn_Crypto
{
    /**
     * Generate a cryptographically secure random key
     * 
     * @param int $length Length in bytes
     * @return string Hex-encoded key
     */
    public static function generate_key($length = 32)
    {
        // PHP 7.0+ has random_bytes, but we need to handle potential errors
        if (function_exists('random_bytes')) {
            try {
                return bin2hex(random_bytes($length));
            } catch (\Exception $e) {
                // Fallback if random_bytes fails
            }
        }
        
        // Fallback to openssl_random_pseudo_bytes (PHP 5.3+)
        if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if ($strong) {
                return bin2hex($bytes);
            }
        }
        
        // Final fallback using WordPress functions
        $key = '';
        for ($i = 0; $i < $length; $i++) {
            $key .= chr(wp_rand(0, 255));
        }
        return bin2hex($key);
    }

    /**
     * Encrypt data using AES-256-CBC
     * 
     * @param string $data Data to encrypt
     * @param string $key Encryption key (will be derived if not provided)
     * @return string|false Encrypted data or false on failure
     */
    public static function encrypt($data, $key = null)
    {
        if ($key === null) {
            $key = self::get_encryption_key();
        }

        // Ensure key is binary
        if (strlen($key) === 64) { // Hex string
            $key = hex2bin($key);
        }
        
        $iv = self::generate_iv();
        
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            return false;
        }

        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt data using AES-256-CBC
     * 
     * @param string $encrypted_data Encrypted data
     * @param string $key Encryption key (will be derived if not provided)
     * @return string|false Decrypted data or false on failure
     */
    public static function decrypt($encrypted_data, $key = null)
    {
        if ($key === null) {
            $key = self::get_encryption_key();
        }

        // Ensure key is binary
        if (strlen($key) === 64) { // Hex string
            $key = hex2bin($key);
        }
        
        $data = base64_decode($encrypted_data);
        
        if (strlen($data) < 16) {
            return false;
        }

        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Generate a JWT token
     * 
     * @param array $payload Token payload
     * @param int $expiry Expiry time in seconds from now
     * @return string JWT token
     */
    public static function generate_jwt($payload, $expiry = 2592000) // 30 days default
    {
        $header = array(
            'alg' => 'HS256',
            'typ' => 'JWT'
        );

        $payload['iat'] = time();
        $payload['exp'] = time() + $expiry;
        $payload['iss'] = get_site_url();

        $header_encoded = self::base64url_encode(json_encode($header));
        $payload_encoded = self::base64url_encode(json_encode($payload));
        
        $signature = hash_hmac('sha256', $header_encoded . '.' . $payload_encoded, self::get_encryption_key(), true);
        $signature_encoded = self::base64url_encode($signature);

        return $header_encoded . '.' . $payload_encoded . '.' . $signature_encoded;
    }

    /**
     * Verify and decode a JWT token
     * 
     * @param string $token JWT token
     * @return array|false Decoded payload or false if invalid
     */
    public static function verify_jwt($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        list($header_encoded, $payload_encoded, $signature_encoded) = $parts;

        // Verify signature
        $expected_signature = hash_hmac('sha256', $header_encoded . '.' . $payload_encoded, self::get_encryption_key(), true);
        $signature = self::base64url_decode($signature_encoded);

        if (!hash_equals($expected_signature, $signature)) {
            return false;
        }

        // Decode payload
        $payload = json_decode(self::base64url_decode($payload_encoded), true);
        if (!$payload) {
            return false;
        }

        // Check expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false;
        }

        // Check issuer
        if (isset($payload['iss']) && $payload['iss'] !== get_site_url()) {
            return false;
        }

        return $payload;
    }

    /**
     * Get or generate the encryption key
     * 
     * @return string Hex-encoded encryption key
     */
    public static function get_encryption_key()
    {
        $key = get_option('wf_sn_encryption_key', '');
        
        if (empty($key)) {
            $key = self::generate_key(32);
            update_option('wf_sn_encryption_key', $key, false);
        }

        return $key;
    }

    /**
     * Get a unique site identifier
     * 
     * @return string Site identifier
     */
    public static function get_site_id()
    {
        $site_id = get_option('wf_sn_site_id', '');
        
        if (empty($site_id)) {
            $site_url = get_site_url();
            $salt = defined('AUTH_KEY') ? AUTH_KEY : 'default_salt';
            $site_id = hash('sha256', $site_url . $salt);
            update_option('wf_sn_site_id', $site_id, false);
        }

        return $site_id;
    }

    /**
     * Generate a secure initialization vector
     * 
     * @return string 16-byte IV
     */
    private static function generate_iv()
    {
        if (function_exists('random_bytes')) {
            try {
                return random_bytes(16);
            } catch (\Exception $e) {
                // Fallback
            }
        }
        
        if (function_exists('openssl_random_pseudo_bytes')) {
            $iv = openssl_random_pseudo_bytes(16, $strong);
            if ($strong) {
                return $iv;
            }
        }
        
        // Final fallback using WordPress functions
        $iv = '';
        for ($i = 0; $i < 16; $i++) {
            $iv .= chr(wp_rand(0, 255));
        }
        return $iv;
    }

    /**
     * Base64 URL encode
     * 
     * @param string $data
     * @return string
     */
    public static function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decode
     * 
     * @param string $data
     * @return string
     */
    public static function base64url_decode($data)
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }

    /**
     * Generate a secure hash for sensitive data
     * 
     * @param string $data Data to hash
     * @param string $salt Optional salt
     * @return string Hash
     */
    public static function hash($data, $salt = null)
    {
        if ($salt === null) {
            $salt = self::get_encryption_key();
        }
        
        return hash_hmac('sha256', $data, $salt);
    }

    /**
     * Verify a hash
     * 
     * @param string $data Original data
     * @param string $hash Hash to verify
     * @param string $salt Salt used for hashing
     * @return bool True if hash matches
     */
    public static function verify_hash($data, $hash, $salt = null)
    {
        if ($salt === null) {
            $salt = self::get_encryption_key();
        }
        
        return hash_equals(self::hash($data, $salt), $hash);
    }

    /**
     * Rotate encryption keys (for security maintenance)
     * 
     * @return bool True if rotation was successful
     */
    public static function rotate_keys()
    {
        $old_key = self::get_encryption_key();
        $new_key = self::generate_key(32);
        
        // Store the new key
        update_option('wf_sn_encryption_key', $new_key, false);
        
        // Log the key rotation if possible
        if (function_exists('secnin_fs') && secnin_fs()->can_use_premium_code__premium_only()) {
            if (class_exists('\WPSecurityNinja\Plugin\wf_sn_el_modules')) {
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'encryption_key_rotated',
                    'Encryption key rotated for enhanced security',
                    array(
                        'old_key_hash' => self::hash($old_key),
                        'new_key_hash' => self::hash($new_key)
                    )
                );
            }
        }
        
        return true;
    }
} 