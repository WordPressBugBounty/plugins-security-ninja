<?php

namespace WPSecurityNinja\Plugin;

/**
 * Centralized Security Class for File Access Validation
 *
 * This class provides secure file access validation using both
 * time-limited hashes and WordPress nonces for maximum security.
 *
 * @package WPSecurityNinja\Plugin
 */
class Wf_Sn_Crypto {

	/**
	 * Salt used for hashing purposes.
	 *
	 * @var string
	 */
	private static $salt = 'wf_sn_crypto_salt';

	/**
	 * Generate a secure file access token with both hash and nonce
	 *
	 * @param string $filepath The file path to generate a token for
	 * @param string $action The action being performed (e.g., 'view_file', 'delete_file')
	 * @return array Array containing hash and nonce
	 */
	public static function generate_secure_file_token($filepath, $action = 'view_file') {
		// Add randomness to prevent predictable hashes
		$random_salt = wp_generate_password(32, false);
		$user_id = get_current_user_id();
		$session_token = wp_get_session_token();
		
		// Create a more secure hash with multiple factors
		$hash_data = $filepath . self::$salt . $random_salt . $user_id . $session_token;
		
		// Store the random salt temporarily for validation
		$hash_key = 'wf_sn_file_token_' . md5($filepath . $user_id . $action);
		set_transient($hash_key, $random_salt, 1800); // 30 minutes expiry
		
		$hash = wp_hash($hash_data);
		$nonce = wp_create_nonce('file_access_' . $action . '_' . md5($filepath));
		
		return array(
			'hash' => $hash,
			'nonce' => $nonce
		);
	}

	/**
	 * Validate a secure file access token
	 *
	 * @param string $filepath The file path to validate
	 * @param string $hash The hash to validate
	 * @param string $nonce The nonce to validate
	 * @param string $action The action being performed
	 * @return bool Whether the token is valid
	 */
	public static function validate_secure_file_token($filepath, $hash, $nonce, $action = 'view_file') {
		// Validate nonce first
		if (!wp_verify_nonce($nonce, 'file_access_' . $action . '_' . md5($filepath))) {
			return false;
		}

		$user_id = get_current_user_id();
		$session_token = wp_get_session_token();
		$hash_key = 'wf_sn_file_token_' . md5($filepath . $user_id . $action);
		
		// Get the stored random salt
		$random_salt = get_transient($hash_key);
		if (false === $random_salt) {
			return false; // Hash expired or doesn't exist
		}
		
		// Recreate the hash for validation
		$hash_data = $filepath . self::$salt . $random_salt . $user_id . $session_token;
		$expected_hash = wp_hash($hash_data);

		return hash_equals($expected_hash, $hash);
	}

	/**
	 * Generate a secure file access URL
	 *
	 * @param string $filepath The file path
	 * @param string $action The action being performed
	 * @param array $additional_params Additional URL parameters
	 * @return string The secure URL
	 */
	public static function generate_secure_file_url($filepath, $action = 'view_file', $additional_params = array()) {
		$token = self::generate_secure_file_token($filepath, $action);
		
		$url = admin_url('admin.php?page=sn-view-file');
		$url = add_query_arg('file', rawurlencode($filepath), $url);
		$url = add_query_arg('hash', rawurlencode($token['hash']), $url);
		$url = add_query_arg('nonce', rawurlencode($token['nonce']), $url);
		$url = add_query_arg('action', rawurlencode($action), $url);
		
		// Add any additional parameters
		foreach ($additional_params as $key => $value) {
			if ($value !== null) {
				$url = add_query_arg($key, rawurlencode($value), $url);
			}
		}
		
		return esc_url($url);
	}

	/**
	 * Validate file access from request parameters
	 *
	 * @param string $action The expected action
	 * @return bool Whether the access is valid
	 */
	public static function validate_file_access_request($action = 'view_file') {
		$filepath = isset($_GET['file']) ? sanitize_text_field(wp_unslash($_GET['file'])) : '';
		$hash = isset($_GET['hash']) ? sanitize_text_field(wp_unslash($_GET['hash'])) : '';
		$nonce = isset($_GET['nonce']) ? sanitize_text_field(wp_unslash($_GET['nonce'])) : '';
		$requested_action = isset($_GET['action']) ? sanitize_text_field(wp_unslash($_GET['action'])) : '';
		
		// Validate all required parameters
		if (empty($filepath) || empty($hash) || empty($nonce) || empty($requested_action)) {
			return false;
		}
		
		// Validate action matches
		if ($requested_action !== $action) {
			return false;
		}
		
		// Validate the token
		return self::validate_secure_file_token($filepath, $hash, $nonce, $action);
	}

	/**
	 * Generate a secure key
	 *
	 * @param int $length Key length
	 * @return string Hex-encoded key
	 */
	public static function generate_key($length = 32)
	{
		if (function_exists('random_bytes')) {
			try {
				return bin2hex(random_bytes($length));
			} catch (\Exception $e) {
				// Fallback
			}
		}
		
		if (function_exists('openssl_random_pseudo_bytes')) {
			$key = openssl_random_pseudo_bytes($length, $strong);
			if ($strong) {
				return bin2hex($key);
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
	 * Encrypt data
	 *
	 * @param string $data Data to encrypt
	 * @param string|null $key Encryption key
	 * @return string Encrypted data
	 */
	public static function encrypt($data, $key = null)
	{
		if ($key === null) {
			$key = self::get_encryption_key();
		}
		
		$iv = self::generate_iv();
		$encrypted = openssl_encrypt($data, 'AES-256-CBC', hex2bin($key), 0, $iv);
		
		if ($encrypted === false) {
			return false;
		}
		
		return base64_encode($iv . $encrypted);
	}

	/**
	 * Decrypt data
	 *
	 * @param string $encrypted_data Encrypted data
	 * @param string|null $key Encryption key
	 * @return string|false Decrypted data or false on failure
	 */
	public static function decrypt($encrypted_data, $key = null)
	{
		if ($key === null) {
			$key = self::get_encryption_key();
		}
		
		$data = base64_decode($encrypted_data);
		$iv = substr($data, 0, 16);
		$encrypted = substr($data, 16);
		
		return openssl_decrypt($encrypted, 'AES-256-CBC', hex2bin($key), 0, $iv);
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
	 * Rotate encryption keys
	 *
	 * @return bool Success status
	 */
	public static function rotate_keys()
	{
		$new_key = self::generate_key(32);
		$old_key = get_option('wf_sn_encryption_key', '');
		
		if (!empty($old_key)) {
			// Store old key for decryption of existing data
			update_option('wf_sn_encryption_key_old', $old_key, false);
		}
		
		return update_option('wf_sn_encryption_key', $new_key, false);
	}
} 