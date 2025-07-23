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
} 