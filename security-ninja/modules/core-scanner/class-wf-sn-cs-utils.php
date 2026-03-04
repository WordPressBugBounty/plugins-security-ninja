<?php

namespace WPSecurityNinja\Plugin;

if ( ! function_exists( 'add_action' ) ) {
	die( 'Please don\'t open this file directly!' );
}

/**
 * Core Scanner utility methods.
 * Loaded conditionally when core scanner functionality is used.
 *
 * @package WPSecurityNinja\Plugin
 */
class Wf_Sn_Cs_Utils {

	/**
	 * Transient expiry for original core file content (1 day).
	 *
	 * @var int
	 */
	const ORIGINAL_FILE_TRANSIENT_EXPIRY = DAY_IN_SECONDS;

	/**
	 * Retrieve file hashes from the WordPress.org API.
	 *
	 * @return array|false List of checksums or false on error.
	 */
	public static function get_file_hashes() {
		$ver    = get_bloginfo( 'version' );
		$locale = get_locale();

		if ( ! function_exists( 'get_core_checksums' ) ) {
			include_once ABSPATH . 'wp-admin/includes/update.php';
		}

		$cs = get_core_checksums( $ver, isset( $locale ) ? $locale : 'en_US' );

		if ( empty( $cs['checksums'] ) ) {
			$cs = get_core_checksums( $ver, 'en_US' );
		}

		if ( $cs ) {
			$cleaned = array();
			foreach ( $cs as $path => $hash ) {
				$cleaned[ $path ] = $hash;
			}
			set_transient( 'wf_sn_hashes_' . $ver . '_' . $locale, $cleaned, MINUTE_IN_SECONDS * 15 );
			return $cleaned;
		}

		if ( function_exists( 'secnin_fs' ) && secnin_fs()->can_use_premium_code__premium_only() ) {
			wf_sn_el_modules::log_event( 'security_ninja', 'core_scanner_update_hashes', sprintf(
				esc_html__( 'There was a problem getting information about the WordPress original files.', 'security-ninja' ) . ' ' . $ver . ' ' . $locale
			) );
		}

		return false;
	}

	/**
	 * Get list of files/folders to ignore in Core Scanner.
	 *
	 * @return array Array of file patterns to ignore.
	 */
	public static function get_ignored_files() {
		$default_ignored = array();
		$ignored        = apply_filters( 'securityninja_core_scanner_ignore_files', $default_ignored );
		if ( ! is_array( $ignored ) ) {
			$ignored = array();
		}
		return $ignored;
	}

	/**
	 * Check if a file should be ignored based on filter rules.
	 *
	 * @param string $file_path Relative file path (e.g. 'wp-includes/SimplePie/src/Core.php').
	 * @return bool True if file should be ignored.
	 */
	public static function is_file_ignored( $file_path ) {
		$ignored_patterns = self::get_ignored_files();
		if ( empty( $ignored_patterns ) ) {
			return false;
		}

		$file_path       = str_replace( '\\', '/', $file_path );
		$file_path_lower = strtolower( $file_path );

		foreach ( $ignored_patterns as $pattern ) {
			if ( $file_path === $pattern || $file_path_lower === strtolower( $pattern ) ) {
				return true;
			}
			if ( fnmatch( $pattern, $file_path ) || fnmatch( $pattern, $file_path_lower ) ) {
				return true;
			}
			if ( basename( $file_path ) === $pattern || basename( $file_path_lower ) === strtolower( $pattern ) ) {
				return true;
			}
			if ( strpos( $file_path, $pattern ) === 0 || strpos( $file_path_lower, strtolower( $pattern ) ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get original WordPress core file content from Trac.
	 * Caches result in a transient for 1 day per file/version.
	 *
	 * @param string      $relative_path Relative path (e.g. 'wp-includes/js/dist/blocks.js').
	 * @param string|null $version       WordPress version. Default current.
	 * @return string|\WP_Error File body or WP_Error on failure.
	 */
	public static function get_original_core_file_content( $relative_path, $version = null ) {
		$version = $version ? $version : get_bloginfo( 'version' );
		$key     = 'wf_sn_cs_orig_' . $version . '_' . md5( $relative_path );
		$cached  = get_transient( $key );
		if ( false !== $cached && is_string( $cached ) ) {
			return $cached;
		}

		$url = 'https://core.trac.wordpress.org/browser/tags/' . $version . '/src/' . $relative_path . '?format=txt';
		$r   = wp_remote_get( $url );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( 404 === wp_remote_retrieve_response_code( $r ) ) {
			return new \WP_Error( 'not_found', __( 'Original file not found.', 'security-ninja' ) );
		}
		$body = wp_remote_retrieve_body( $r );
		if ( '' === $body ) {
			return new \WP_Error( 'empty', __( 'Unable to download remote file source.', 'security-ninja' ) );
		}

		set_transient( $key, $body, self::ORIGINAL_FILE_TRANSIENT_EXPIRY );
		return $body;
	}

	/**
	 * Check whether a stored results array has the expected data-only shape.
	 *
	 * @param mixed $results Value from get_option( 'wf_sn_cs_results' ).
	 * @return bool True when the results contain a valid last_run timestamp.
	 */
	public static function is_valid_results( $results ) {
		return is_array( $results ) && ! empty( $results['last_run'] );
	}
}
