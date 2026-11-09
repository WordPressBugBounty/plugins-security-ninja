<?php

namespace WPSecurityNinja\Plugin;

if ( !function_exists( 'add_action' ) ) {
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
     * Transient expiry for a verified original core file body (1 day).
     *
     * @var int
     */
    const ORIGINAL_FILE_TRANSIENT_EXPIRY = DAY_IN_SECONDS;

    /**
     * Transient expiry for an official checksum map (12 hours).
     *
     * Released checksums do not change. Failures are not cached.
     *
     * @var int
     */
    const CHECKSUM_TRANSIENT_EXPIRY = 12 * HOUR_IN_SECONDS;

    /**
     * One-time flag: old wf_sn_cs_orig_* bodies were cached before the md5 check.
     *
     * @var string
     */
    const ORIGINAL_CACHE_PURGE_OPTION = 'wf_sn_cs_orig_purged_5309';

    /**
     * Option name for user-ignored unknown core files.
     *
     * @var string
     */
    const USER_IGNORE_OPTION = 'wf_sn_cs_user_ignore';

    /**
     * Option name for cached Core Scanner results.
     *
     * @var string
     */
    const RESULTS_OPTION = 'wf_sn_cs_results';

    /**
     * Maximum number of user-ignored paths stored.
     *
     * @var int
     */
    const USER_IGNORE_MAX = 500;

    /**
     * Shortest path that can be a WP-CLI PharData truncation of a core file.
     *
     * Archive paths are cut at 100 bytes. The wordpress/ prefix uses 10 of those,
     * so on-disk names are typically 90 characters. 80 leaves a little room.
     *
     * @var int
     */
    const TRUNCATED_CORE_MIN_LENGTH = 80;

    /**
     * Whether Core Scanner options should be network-scoped.
     *
     * On Multisite, core files under ABSPATH are shared, so Ignore and
     * scan results must be shared across the network.
     *
     * @return bool
     */
    public static function uses_network_storage() {
        return is_multisite();
    }

    /**
     * Read a Core Scanner option, migrating from the main site blog option on first Multisite use.
     *
     * @param string $option  Option name.
     * @param mixed  $default Default when unset.
     * @return mixed
     */
    private static function get_stored_option( $option, $default = false ) {
        if ( !self::uses_network_storage() ) {
            return get_option( $option, $default );
        }
        $not_set = '__sn_cs_not_set__';
        $stored = get_site_option( $option, $not_set );
        if ( $not_set !== $stored ) {
            return $stored;
        }
        $legacy = get_blog_option( get_main_site_id(), $option, $not_set );
        if ( $not_set === $legacy ) {
            return $default;
        }
        update_site_option( $option, $legacy );
        return $legacy;
    }

    /**
     * Write a Core Scanner option (site option on Multisite, blog option otherwise).
     *
     * @param string $option Option name.
     * @param mixed  $value  Value to store.
     * @return bool
     */
    private static function update_stored_option( $option, $value ) {
        if ( self::uses_network_storage() ) {
            return update_site_option( $option, $value );
        }
        return update_option( $option, $value, false );
    }

    /**
     * Delete a Core Scanner option from the active storage scope.
     *
     * @param string $option Option name.
     * @return bool
     */
    private static function delete_stored_option( $option ) {
        if ( self::uses_network_storage() ) {
            return delete_site_option( $option );
        }
        return delete_option( $option );
    }

    /**
     * Get cached Core Scanner results.
     *
     * @param mixed $default Default when unset.
     * @return mixed
     */
    public static function get_scan_results( $default = array() ) {
        return self::get_stored_option( self::RESULTS_OPTION, $default );
    }

    /**
     * Persist cached Core Scanner results.
     *
     * @param mixed $results Results array or null.
     * @return bool
     */
    public static function update_scan_results( $results ) {
        return self::update_stored_option( self::RESULTS_OPTION, $results );
    }

    /**
     * Delete cached Core Scanner results.
     *
     * @return bool
     */
    public static function delete_scan_results() {
        return self::delete_stored_option( self::RESULTS_OPTION );
    }

    /**
     * Retrieve file hashes for the current WordPress version.
     *
     * Uses the site locale when WordPress.org has that map, otherwise en_US.
     * The map is cached. A failed request is not cached.
     *
     * @return array|false Path to md5 map, or false on error.
     */
    public static function get_file_hashes() {
        $map = self::get_checksum_map( get_bloginfo( 'version' ) );
        if ( !is_array( $map ) ) {
            return false;
        }
        return $map;
    }

    /**
     * Official md5 for one core file, from the same map the scanner uses.
     *
     * @param string      $relative_path Relative path (e.g. wp-includes/version.php).
     * @param string|null $version       WordPress version. Default current.
     * @return string|false Lowercase md5, or false when the file cannot be verified.
     */
    public static function get_official_checksum( $relative_path, $version = null ) {
        $relative_path = self::sanitize_core_relative_path( $relative_path );
        $version = self::sanitize_core_version( ( $version ? $version : get_bloginfo( 'version' ) ) );
        if ( '' === $relative_path || '' === $version ) {
            return false;
        }
        $map = self::get_checksum_map( $version );
        if ( !is_array( $map ) || !isset( $map[$relative_path] ) || !is_string( $map[$relative_path] ) ) {
            return false;
        }
        $hash = strtolower( $map[$relative_path] );
        if ( !preg_match( '/^[a-f0-9]{32}$/', $hash ) ) {
            return false;
        }
        return $hash;
    }

    /**
     * Locale whose checksum map is stored for this site locale and version.
     *
     * Empty when the map is not loaded. en_US means the site locale had no map.
     *
     * @param string|null $version WordPress version. Default current.
     * @return string
     */
    public static function get_checksum_locale_used( $version = null ) {
        $version = self::sanitize_core_version( ( $version ? $version : get_bloginfo( 'version' ) ) );
        if ( '' === $version ) {
            return '';
        }
        $cached = self::read_checksum_cache( $version, self::current_checksum_locale() );
        if ( !is_array( $cached ) || empty( $cached['locale'] ) || !is_string( $cached['locale'] ) ) {
            return '';
        }
        return $cached['locale'];
    }

    /**
     * Get list of files/folders to ignore in Core Scanner.
     *
     * @return array Array of file patterns to ignore.
     */
    public static function get_ignored_files() {
        $default_ignored = array('**/.DS_Store', '.DS_Store', 'Thumbs.db');
        $ignored = apply_filters( 'securityninja_core_scanner_ignore_files', $default_ignored );
        if ( !is_array( $ignored ) ) {
            $ignored = array();
        }
        return $ignored;
    }

    /**
     * Normalize a relative file path for Core Scanner storage and comparison.
     *
     * @param string $path Relative path.
     * @return string|false Normalized path or false if invalid.
     */
    public static function normalize_relative_path( $path ) {
        $path = str_replace( '\\', '/', (string) $path );
        $path = ltrim( $path, '/' );
        if ( '' === $path || false !== strpos( $path, '..' ) || false !== strpos( $path, "\x00" ) ) {
            return false;
        }
        return $path;
    }

    /**
     * Get user-ignored file paths from the database option.
     *
     * @return string[]
     */
    public static function get_user_ignored_files() {
        $stored = self::get_stored_option( self::USER_IGNORE_OPTION, array() );
        if ( !is_array( $stored ) ) {
            return array();
        }
        $paths = array();
        foreach ( $stored as $path ) {
            $normalized = self::normalize_relative_path( $path );
            if ( false !== $normalized ) {
                $paths[] = $normalized;
            }
        }
        return array_values( array_unique( $paths ) );
    }

    /**
     * Replace the user ignore list (used by settings import).
     *
     * @param string[] $paths Relative paths.
     * @return true|\WP_Error
     */
    public static function set_user_ignored_files( $paths ) {
        if ( !is_array( $paths ) ) {
            return new \WP_Error('invalid_paths', __( 'Invalid ignore list.', 'security-ninja' ));
        }
        $sanitized = array();
        foreach ( $paths as $path ) {
            $normalized = self::normalize_relative_path( $path );
            if ( false !== $normalized ) {
                $sanitized[] = $normalized;
            }
        }
        $sanitized = array_values( array_unique( $sanitized ) );
        if ( count( $sanitized ) > self::USER_IGNORE_MAX ) {
            $sanitized = array_slice( $sanitized, 0, self::USER_IGNORE_MAX );
        }
        self::update_stored_option( self::USER_IGNORE_OPTION, $sanitized );
        return true;
    }

    /**
     * Delete the user ignore list from storage.
     *
     * @return bool
     */
    public static function delete_user_ignored_files() {
        return self::delete_stored_option( self::USER_IGNORE_OPTION );
    }

    /**
     * Delete cached original-file bodies from before the checksum check.
     *
     * Runs once per site. A later read still rejects a body whose md5 does not match.
     *
     * @return void
     */
    public static function maybe_purge_unverified_originals() {
        if ( get_option( self::ORIGINAL_CACHE_PURGE_OPTION ) ) {
            return;
        }
        self::delete_transient_prefix( 'wf_sn_cs_orig_', true );
        update_option( self::ORIGINAL_CACHE_PURGE_OPTION, '1' );
    }

    /**
     * Delete cached checksum maps and original file bodies.
     *
     * @param bool $include_network Also delete network transients. False on a subsite deactivate.
     * @return void
     */
    public static function delete_reference_transients( $include_network = true ) {
        self::delete_transient_prefix( 'wf_sn_cs_orig_', $include_network );
        self::delete_transient_prefix( 'wf_sn_hashes_', $include_network );
        if ( $include_network ) {
            delete_option( self::ORIGINAL_CACHE_PURGE_OPTION );
        }
    }

    /**
     * Whether a path is in the user ignore list.
     *
     * @param string $file_path Relative file path.
     * @return bool
     */
    public static function is_user_ignored_file( $file_path ) {
        $normalized = self::normalize_relative_path( $file_path );
        if ( false === $normalized ) {
            return false;
        }
        return in_array( $normalized, self::get_user_ignored_files(), true );
    }

    /**
     * Add a path to the user ignore list.
     *
     * @param string $file_path Relative file path.
     * @return true|\WP_Error
     */
    public static function add_user_ignored_file( $file_path ) {
        $normalized = self::normalize_relative_path( $file_path );
        if ( false === $normalized ) {
            return new \WP_Error('invalid_path', __( 'Invalid file path.', 'security-ninja' ));
        }
        $paths = self::get_user_ignored_files();
        if ( in_array( $normalized, $paths, true ) ) {
            return true;
        }
        if ( count( $paths ) >= self::USER_IGNORE_MAX ) {
            return new \WP_Error('ignore_limit', __( 'The ignore list is full. Remove entries before adding more.', 'security-ninja' ));
        }
        $paths[] = $normalized;
        self::update_stored_option( self::USER_IGNORE_OPTION, $paths );
        return true;
    }

    /**
     * Remove a path from the user ignore list.
     *
     * @param string $file_path Relative file path.
     * @return true|\WP_Error
     */
    public static function remove_user_ignored_file( $file_path ) {
        $normalized = self::normalize_relative_path( $file_path );
        if ( false === $normalized ) {
            return new \WP_Error('invalid_path', __( 'Invalid file path.', 'security-ninja' ));
        }
        $paths = self::get_user_ignored_files();
        if ( !in_array( $normalized, $paths, true ) ) {
            return new \WP_Error('not_ignored', __( 'File is not in your ignore list.', 'security-ninja' ));
        }
        $paths = array_values( array_filter( $paths, function ( $path ) use($normalized) {
            return $path !== $normalized;
        } ) );
        self::update_stored_option( self::USER_IGNORE_OPTION, $paths );
        return true;
    }

    /**
     * Check if a file should be ignored based on filter rules.
     *
     * @param string $file_path Relative file path (e.g. 'wp-includes/SimplePie/src/Core.php').
     * @return bool True if file should be ignored.
     */
    public static function is_file_ignored( $file_path ) {
        if ( self::is_user_ignored_file( $file_path ) ) {
            return true;
        }
        $ignored_patterns = self::get_ignored_files();
        if ( empty( $ignored_patterns ) ) {
            return false;
        }
        $file_path = str_replace( '\\', '/', $file_path );
        $file_path_lower = strtolower( $file_path );
        foreach ( $ignored_patterns as $pattern ) {
            if ( $pattern === $file_path || strtolower( $pattern ) === $file_path_lower ) {
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
     * Download one official core file and require it to match the WordPress.org md5.
     *
     * The build repository (core.svn.wordpress.org) is the release package, so minified
     * files match the checksums. Nothing is cached unless the md5 matches. Error codes:
     * unverifiable, http_error, html_challenge, checksum_mismatch, not_found.
     *
     * @param string      $relative_path Relative path (e.g. 'wp-includes/js/dist/blocks.min.js').
     * @param string|null $version       WordPress version. Default current.
     * @return string|\WP_Error File body or WP_Error on failure.
     */
    public static function get_original_core_file_content( $relative_path, $version = null ) {
        $relative_path = self::sanitize_core_relative_path( $relative_path );
        if ( '' === $relative_path ) {
            return new \WP_Error('invalid_path', __( 'Invalid core file path.', 'security-ninja' ));
        }
        $version = self::sanitize_core_version( ( $version ? $version : get_bloginfo( 'version' ) ) );
        if ( '' === $version ) {
            return new \WP_Error('unverifiable', __( 'No official WordPress checksum is available for this file.', 'security-ninja' ));
        }
        $official_md5 = self::get_official_checksum( $relative_path, $version );
        if ( !is_string( $official_md5 ) ) {
            $map = self::get_checksum_map( $version );
            if ( is_array( $map ) ) {
                self::delete_scoped_transient( self::original_transient_key( $version, $relative_path ) );
            }
            return new \WP_Error('unverifiable', __( 'No official WordPress checksum is available for this file.', 'security-ninja' ));
        }
        $key = self::original_transient_key( $version, $relative_path );
        $cached = self::get_scoped_transient( $key );
        if ( is_string( $cached ) && self::body_matches_official( $relative_path, $cached, $official_md5 ) ) {
            return $cached;
        }
        if ( false !== $cached ) {
            self::delete_scoped_transient( $key );
        }
        $errors = array();
        foreach ( self::original_file_urls( $version, $relative_path ) as $url ) {
            $downloaded = self::download_verified_original( $url, $relative_path, $official_md5 );
            if ( is_string( $downloaded ) ) {
                self::set_scoped_transient( $key, $downloaded, self::ORIGINAL_FILE_TRANSIENT_EXPIRY );
                return $downloaded;
            }
            if ( is_wp_error( $downloaded ) ) {
                $errors[] = $downloaded;
            }
        }
        return self::prefer_original_download_error( $errors );
    }

    /**
     * Sentence shown when Diff or Restore cannot use an official copy.
     *
     * @param \WP_Error $error   Error from get_original_core_file_content().
     * @param string    $context `diff` or `restore`.
     * @return string
     */
    public static function describe_original_file_error( $error, $context = 'restore' ) {
        if ( 'diff' === $context ) {
            $base = __( 'Could not verify the official copy of this file, so no comparison is shown. The file still does not match the official WordPress checksum.', 'security-ninja' );
        } else {
            $base = __( 'Could not verify the official copy of this file. Nothing was changed.', 'security-ninja' );
        }
        $code = ( $error instanceof \WP_Error ? $error->get_error_code() : '' );
        $detail = self::original_file_error_detail( $code );
        if ( '' === $detail ) {
            return $base;
        }
        return $base . ' ' . $detail;
    }

    /**
     * Reject HTML challenge pages masquerading as core file downloads.
     *
     * The md5 check in get_original_core_file_content() is what decides the body is official.
     * This only gives a clearer error when the body is an obvious challenge page.
     *
     * @param string $relative_path Path under wp root (e.g. wp-includes/version.php).
     * @param string $body          Response body.
     * @return true|\WP_Error True when body looks like real file content.
     */
    public static function validate_original_core_file_body( $relative_path, $body ) {
        if ( !is_string( $body ) || '' === $body ) {
            return new \WP_Error('empty', __( 'Unable to download remote file source.', 'security-ninja' ));
        }
        $ext = strtolower( pathinfo( $relative_path, PATHINFO_EXTENSION ) );
        if ( in_array( $ext, array('html', 'htm'), true ) ) {
            return true;
        }
        $trim = ltrim( $body );
        if ( 0 === stripos( $trim, '<!DOCTYPE html' ) || 0 === stripos( $trim, '<html' ) ) {
            return new \WP_Error('html_challenge', __( 'Original core file download returned an HTML page instead of file content.', 'security-ninja' ));
        }
        $lower = strtolower( $body );
        $markers = array(
            'cf-browser-verification',
            'cdn-cgi/challenge-platform',
            'just a moment',
            'checking your browser',
            '/__challenge'
        );
        foreach ( $markers as $marker ) {
            if ( false !== strpos( $lower, $marker ) ) {
                return new \WP_Error('html_challenge', __( 'Original core file download returned an HTML page instead of file content.', 'security-ninja' ));
            }
        }
        return true;
    }

    /**
     * Short reason appended to the Diff or Restore failure sentence.
     *
     * @param string $code Error code.
     * @return string
     */
    private static function original_file_error_detail( $code ) {
        switch ( $code ) {
            case 'html_challenge':
                return __( 'The download was a browser check page, not the WordPress file.', 'security-ninja' );
            case 'checksum_mismatch':
                return __( 'The download did not match the official WordPress checksum.', 'security-ninja' );
            case 'http_error':
                return __( 'The download failed.', 'security-ninja' );
            case 'not_found':
                return __( 'WordPress.org has no official copy of this file for this version.', 'security-ninja' );
            case 'unverifiable':
                return __( 'There is no official checksum for this file.', 'security-ninja' );
            default:
                return '';
        }
    }

    /**
     * Load the checksum map for a version, using the site locale, then en_US.
     *
     * Cached under the site locale. The stored locale is the map that was actually used.
     *
     * @param string $version WordPress version.
     * @return array|false
     */
    private static function get_checksum_map( $version ) {
        $version = self::sanitize_core_version( $version );
        if ( '' === $version ) {
            return false;
        }
        $locale = self::current_checksum_locale();
        $cached = self::read_checksum_cache( $version, $locale );
        if ( is_array( $cached ) ) {
            return $cached['checksums'];
        }
        if ( !function_exists( 'get_core_checksums' ) ) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $used_locale = $locale;
        $cs = get_core_checksums( $version, $locale );
        if ( (!is_array( $cs ) || array() === $cs) && 'en_US' !== $locale ) {
            $cs = get_core_checksums( $version, 'en_US' );
            $used_locale = 'en_US';
        }
        if ( !is_array( $cs ) || array() === $cs ) {
            return false;
        }
        $cleaned = array();
        foreach ( $cs as $path => $hash ) {
            if ( !is_string( $path ) || !is_string( $hash ) ) {
                continue;
            }
            $hash = strtolower( $hash );
            if ( !preg_match( '/^[a-f0-9]{32}$/', $hash ) ) {
                continue;
            }
            $cleaned[$path] = $hash;
        }
        if ( array() === $cleaned ) {
            return false;
        }
        self::write_checksum_cache(
            $version,
            $locale,
            $used_locale,
            $cleaned
        );
        return $cleaned;
    }

    /**
     * Site locale used as the checksum cache key.
     *
     * @return string
     */
    private static function current_checksum_locale() {
        $locale = get_locale();
        if ( !is_string( $locale ) || !preg_match( '/^[A-Za-z0-9_]+$/', $locale ) ) {
            return 'en_US';
        }
        return $locale;
    }

    /**
     * @param string $version WordPress version.
     * @param string $locale  Requested locale (cache key).
     * @return array|false Cache payload with checksums and the locale actually used.
     */
    private static function read_checksum_cache( $version, $locale ) {
        $cached = self::get_scoped_transient( self::checksum_transient_key( $version, $locale ) );
        if ( !is_array( $cached ) || empty( $cached['checksums'] ) || !is_array( $cached['checksums'] ) ) {
            return false;
        }
        return $cached;
    }

    /**
     * @param string $version     WordPress version.
     * @param string $locale      Requested locale (cache key).
     * @param string $used_locale Locale whose map was stored.
     * @param array  $checksums   Path to md5 map.
     * @return void
     */
    private static function write_checksum_cache(
        $version,
        $locale,
        $used_locale,
        $checksums
    ) {
        self::set_scoped_transient( self::checksum_transient_key( $version, $locale ), array(
            'locale'    => $used_locale,
            'checksums' => $checksums,
        ), self::CHECKSUM_TRANSIENT_EXPIRY );
    }

    /**
     * @param string $version WordPress version.
     * @param string $locale  Requested locale.
     * @return string
     */
    private static function checksum_transient_key( $version, $locale ) {
        return 'wf_sn_hashes_' . $version . '_' . $locale;
    }

    /**
     * @param string $version       WordPress version.
     * @param string $relative_path Relative core path.
     * @return string
     */
    private static function original_transient_key( $version, $relative_path ) {
        return 'wf_sn_cs_orig_' . $version . '_' . md5( $relative_path );
    }

    /**
     * Official release-package URL for one core file.
     *
     * @param string $version       WordPress version.
     * @param string $relative_path Relative core path.
     * @return string[]
     */
    private static function original_file_urls( $version, $relative_path ) {
        $encoded_version = rawurlencode( $version );
        $encoded_path = self::encode_core_path( $relative_path );
        return array('https://core.svn.wordpress.org/tags/' . $encoded_version . '/' . $encoded_path);
    }

    /**
     * @param string $relative_path Relative core path.
     * @return string
     */
    private static function encode_core_path( $relative_path ) {
        $parts = explode( '/', $relative_path );
        $parts = array_map( 'rawurlencode', $parts );
        return implode( '/', $parts );
    }

    /**
     * Fetch one URL and accept it only when the body matches the official md5.
     *
     * @param string $url           Download URL.
     * @param string $relative_path Relative core path.
     * @param string $official_md5  Expected lowercase md5.
     * @return string|\WP_Error
     */
    private static function download_verified_original( $url, $relative_path, $official_md5 ) {
        $response = wp_remote_get( $url, array(
            'timeout'     => 30,
            'redirection' => 3,
        ) );
        if ( is_wp_error( $response ) ) {
            return new \WP_Error('http_error', __( 'Unable to download original core file.', 'security-ninja' ));
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( 404 === $code ) {
            return new \WP_Error('not_found', __( 'Original file not found.', 'security-ninja' ));
        }
        if ( 200 !== $code ) {
            return new \WP_Error('http_error', sprintf( 
                /* translators: %d: HTTP status code */
                __( 'Unable to download original core file (HTTP %d).', 'security-ninja' ),
                $code
             ));
        }
        $content_type = wp_remote_retrieve_header( $response, 'content-type' );
        $ext = strtolower( pathinfo( $relative_path, PATHINFO_EXTENSION ) );
        $is_html_file = in_array( $ext, array('html', 'htm'), true );
        if ( !$is_html_file && is_string( $content_type ) && false !== stripos( $content_type, 'text/html' ) ) {
            return new \WP_Error('html_challenge', __( 'Original core file download returned an HTML page instead of file content.', 'security-ninja' ));
        }
        $body = wp_remote_retrieve_body( $response );
        $valid = self::validate_original_core_file_body( $relative_path, $body );
        if ( true !== $valid ) {
            return $valid;
        }
        if ( !self::hash_equals_md5( $official_md5, $body ) ) {
            return new \WP_Error('checksum_mismatch', __( 'The downloaded core file does not match the official WordPress checksum.', 'security-ninja' ));
        }
        return $body;
    }

    /**
     * Whether a body passed the challenge checks and the official md5.
     *
     * @param string $relative_path Relative core path.
     * @param string $body          File body.
     * @param string $official_md5  Expected lowercase md5.
     * @return bool
     */
    private static function body_matches_official( $relative_path, $body, $official_md5 ) {
        if ( true !== self::validate_original_core_file_body( $relative_path, $body ) ) {
            return false;
        }
        return self::hash_equals_md5( $official_md5, $body );
    }

    /**
     * @param string $official_md5 Expected lowercase md5.
     * @param string $body         File body.
     * @return bool
     */
    private static function hash_equals_md5( $official_md5, $body ) {
        if ( !is_string( $official_md5 ) || !is_string( $body ) ) {
            return false;
        }
        $actual = md5( $body );
        if ( strlen( $official_md5 ) !== strlen( $actual ) ) {
            return false;
        }
        return hash_equals( $official_md5, $actual );
    }

    /**
     * Pick the most specific failure when every source was rejected.
     *
     * @param \WP_Error[] $errors Download errors.
     * @return \WP_Error
     */
    private static function prefer_original_download_error( $errors ) {
        $rank = array(
            'checksum_mismatch' => 1,
            'html_challenge'    => 2,
            'empty'             => 3,
            'not_found'         => 4,
            'http_error'        => 5,
        );
        $best = null;
        $best_rank = 99;
        foreach ( $errors as $error ) {
            if ( !is_wp_error( $error ) ) {
                continue;
            }
            $code = $error->get_error_code();
            $r = ( isset( $rank[$code] ) ? $rank[$code] : 50 );
            if ( $r < $best_rank ) {
                $best = $error;
                $best_rank = $r;
            }
        }
        if ( $best instanceof \WP_Error ) {
            return $best;
        }
        return new \WP_Error('http_error', __( 'Unable to download original core file.', 'security-ninja' ));
    }

    /**
     * @param string $path Relative or absolute path piece.
     * @return string Empty when the path is not a safe relative core path.
     */
    private static function sanitize_core_relative_path( $path ) {
        $path = str_replace( '\\', '/', (string) $path );
        $path = ltrim( $path, '/' );
        if ( '' === $path || false !== strpos( $path, '..' ) || false !== strpos( $path, "\x00" ) ) {
            return '';
        }
        return $path;
    }

    /**
     * @param string $version WordPress version.
     * @return string Empty when the version cannot be used in a URL.
     */
    private static function sanitize_core_version( $version ) {
        $version = (string) $version;
        if ( !preg_match( '/^[0-9A-Za-z._-]+$/', $version ) ) {
            return '';
        }
        return $version;
    }

    /**
     * @param string $key Transient name without the WordPress prefix.
     * @return mixed
     */
    private static function get_scoped_transient( $key ) {
        if ( self::uses_network_storage() ) {
            return get_site_transient( $key );
        }
        return get_transient( $key );
    }

    /**
     * @param string $key    Transient name.
     * @param mixed  $value  Value.
     * @param int    $expiry Lifetime in seconds.
     * @return void
     */
    private static function set_scoped_transient( $key, $value, $expiry ) {
        if ( self::uses_network_storage() ) {
            set_site_transient( $key, $value, $expiry );
            return;
        }
        set_transient( $key, $value, $expiry );
    }

    /**
     * @param string $key Transient name.
     * @return void
     */
    private static function delete_scoped_transient( $key ) {
        delete_transient( $key );
        if ( self::uses_network_storage() ) {
            delete_site_transient( $key );
        }
    }

    /**
     * Delete blog and, when asked, network transients that start with a prefix.
     *
     * @param string $prefix          Transient name prefix, such as wf_sn_cs_orig_.
     * @param bool   $include_network Also delete the site transient rows.
     * @return void
     */
    private static function delete_transient_prefix( $prefix, $include_network ) {
        global $wpdb;
        $value_like = $wpdb->esc_like( '_transient_' . $prefix ) . '%';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $option_names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $value_like ) );
        if ( is_array( $option_names ) ) {
            foreach ( $option_names as $option_name ) {
                if ( 0 !== strpos( $option_name, '_transient_' ) || 0 === strpos( $option_name, '_transient_timeout_' ) ) {
                    continue;
                }
                delete_transient( substr( $option_name, strlen( '_transient_' ) ) );
            }
        }
        if ( $include_network && is_multisite() ) {
            $site_value = $wpdb->esc_like( '_site_transient_' . $prefix ) . '%';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $meta_keys = $wpdb->get_col( $wpdb->prepare( "SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $site_value ) );
            if ( is_array( $meta_keys ) ) {
                foreach ( $meta_keys as $meta_key ) {
                    if ( 0 !== strpos( $meta_key, '_site_transient_' ) || 0 === strpos( $meta_key, '_site_transient_timeout_' ) ) {
                        continue;
                    }
                    delete_site_transient( substr( $meta_key, strlen( '_site_transient_' ) ) );
                }
            }
        }
    }

    /**
     * Check whether a stored results array has the expected data-only shape.
     *
     * @param mixed $results Value from Wf_Sn_Cs_Utils::get_scan_results().
     * @return bool True when the results contain a valid last_run timestamp.
     */
    public static function is_valid_results( $results ) {
        return is_array( $results ) && !empty( $results['last_run'] );
    }

    /**
     * WordPress root filenames expected from core checksums (no slash in key).
     *
     * @param array $filehashes Checksum map from get_file_hashes().
     * @return array List of relative root filenames.
     */
    public static function get_expected_root_files( $filehashes ) {
        $expected = array();
        if ( !is_array( $filehashes ) ) {
            return $expected;
        }
        foreach ( $filehashes as $path => $hash ) {
            if ( is_string( $path ) && false === strpos( $path, '/' ) ) {
                $expected[] = $path;
            }
        }
        return $expected;
    }

    /**
     * Default allowlist for non-checksum files commonly found in ABSPATH root.
     *
     * @return array Basename or fnmatch patterns.
     */
    public static function get_root_allowlist() {
        $defaults = array(
            'robots.txt',
            'favicon.ico',
            'php.ini',
            'wordfence-waf.php',
            'secnin-waf.php',
            'wp-config.php',
            'wp-config-sample.php',
            '*.shtml'
        );
        $allowlist = apply_filters( 'securityninja_core_scanner_root_allowlist', $defaults );
        return ( is_array( $allowlist ) ? $allowlist : $defaults );
    }

    /**
     * Whether a root-level filename matches the root allowlist.
     *
     * @param string $filename Basename in ABSPATH root.
     * @return bool
     */
    public static function is_root_allowlisted( $filename ) {
        $filename = str_replace( '\\', '/', (string) $filename );
        foreach ( self::get_root_allowlist() as $pattern ) {
            if ( $pattern === $filename ) {
                return true;
            }
            if ( fnmatch( $pattern, $filename ) || fnmatch( $pattern, strtolower( $filename ) ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Scan ABSPATH root for unexpected non-dot files.
     *
     * @param array $filehashes Checksum map from get_file_hashes().
     * @return array{unknown: string[], root_files_scanned: int}
     */
    public static function scan_root_for_unknown_files( $filehashes ) {
        $unknown = array();
        $root_files_scanned = 0;
        $expected = array_flip( self::get_expected_root_files( $filehashes ) );
        $root_path = trailingslashit( ABSPATH );
        if ( !is_dir( $root_path ) ) {
            return array(
                'unknown'            => $unknown,
                'root_files_scanned' => 0,
            );
        }
        $entries = scandir( $root_path );
        if ( !is_array( $entries ) ) {
            return array(
                'unknown'            => $unknown,
                'root_files_scanned' => 0,
            );
        }
        foreach ( $entries as $entry ) {
            if ( '.' === $entry || '..' === $entry ) {
                continue;
            }
            if ( '.' === $entry[0] ) {
                continue;
            }
            $full = $root_path . $entry;
            if ( !is_file( $full ) ) {
                continue;
            }
            ++$root_files_scanned;
            if ( isset( $expected[$entry] ) ) {
                continue;
            }
            if ( self::is_file_ignored( $entry ) ) {
                continue;
            }
            if ( self::is_root_allowlisted( $entry ) ) {
                continue;
            }
            $unknown[] = $entry;
        }
        return array(
            'unknown'            => $unknown,
            'root_files_scanned' => $root_files_scanned,
        );
    }

    /**
     * Severities that count toward the Core Scanner tab badge.
     *
     * @return array
     */
    public static function get_badge_severities() {
        $defaults = array('critical', 'warning');
        $severities = apply_filters( 'securityninja_core_scanner_badge_severities', $defaults );
        return ( is_array( $severities ) ? $severities : $defaults );
    }

    /**
     * Classify an unknown file path by severity and guidance.
     *
     * @param string $relative_path Path relative to ABSPATH.
     * @return array{severity: string, reason: string, guidance: string}
     */
    public static function classify_unknown_file( $relative_path ) {
        $path = str_replace( '\\', '/', (string) $relative_path );
        $basename = basename( $path );
        $basename_lower = strtolower( $basename );
        $classification = array(
            'severity' => 'warning',
            'reason'   => 'generic',
            'guidance' => __( 'This file is not part of the official WordPress package for your version. Review manually.', 'security-ninja' ),
        );
        if ( self::matches_phpinfo_exposure( $basename_lower ) ) {
            $classification = array(
                'severity' => 'warning',
                'reason'   => 'phpinfo_exposure',
                'guidance' => __( 'This file matches a well-known PHP environment or debugging helper. Any file that exposes PHP configuration or server details can be a serious security risk on a production site. Review manually and remove if not needed. With Pro, run Malware Scanner for a deeper content check outside core folders.', 'security-ninja' ),
            );
        } elseif ( 0 === strpos( $path, 'wp-includes/' ) || 0 === strpos( $path, 'wp-admin/' ) ) {
            $classification = array(
                'severity' => 'critical',
                'reason'   => 'core_hidden',
                'guidance' => __( 'Unexpected file inside a WordPress core directory. This may be malware debris or a leftover from a cleanup attempt.', 'security-ninja' ),
            );
        } elseif ( false === strpos( $path, '/' ) ) {
            if ( self::is_root_decoy_name( $basename_lower ) ) {
                $classification = array(
                    'severity' => 'critical',
                    'reason'   => 'root_decoy',
                    'guidance' => __( 'This root file mimics a WordPress core filename but is not part of the official package. Decoy files in the site root are a common malware technique.', 'security-ninja' ),
                );
            } elseif ( preg_match( '/\\.html?$/i', $basename ) || preg_match( '/\\.txt$/i', $basename ) ) {
                $classification = array(
                    'severity' => 'notice',
                    'reason'   => 'custom_root',
                    'guidance' => __( 'Not part of the official WordPress package. If you placed this file intentionally, use Ignore to hide it from future scans.', 'security-ninja' ),
                );
            } else {
                $classification = array(
                    'severity' => 'warning',
                    'reason'   => 'generic',
                    'guidance' => __( 'Unexpected file in the WordPress root. Verify it is intentional before leaving it on a production site.', 'security-ninja' ),
                );
            }
        }
        $filtered = apply_filters( 'securityninja_core_scanner_file_severity', $classification, $path );
        if ( is_array( $filtered ) && isset( $filtered['severity'], $filtered['reason'], $filtered['guidance'] ) ) {
            return $filtered;
        }
        return $classification;
    }

    /**
     * Build unknown_findings map for a list of relative paths.
     *
     * @param array $files Relative file paths.
     * @return array<string, array>
     */
    public static function build_unknown_findings( $files ) {
        $findings = array();
        if ( !is_array( $files ) ) {
            return $findings;
        }
        foreach ( $files as $file ) {
            if ( !is_string( $file ) || '' === $file ) {
                continue;
            }
            $findings[$file] = self::classify_unknown_file( $file );
        }
        return $findings;
    }

    /**
     * Whether an unknown finding severity counts toward the tab badge.
     *
     * @param string $severity Severity key.
     * @return bool
     */
    public static function severity_counts_in_badge( $severity ) {
        return in_array( (string) $severity, self::get_badge_severities(), true );
    }

    /**
     * @param string $basename_lower Lowercase basename.
     * @return bool
     */
    private static function matches_phpinfo_exposure( $basename_lower ) {
        $patterns = array(
            'local-xdebuginfo.php',
            'atomlib.php',
            'phpinfo.php',
            'info.php',
            'i.php',
            'pi.php',
            'test.php',
            'p.php'
        );
        foreach ( $patterns as $pattern ) {
            if ( $basename_lower === $pattern ) {
                return true;
            }
        }
        if ( false !== strpos( $basename_lower, 'phpinfo' ) || false !== strpos( $basename_lower, 'xdebuginfo' ) ) {
            return true;
        }
        return false;
    }

    /**
     * @param string $basename_lower Lowercase root basename.
     * @return bool
     */
    private static function is_root_decoy_name( $basename_lower ) {
        $decoys = array(
            'admin-ajax.php',
            'wp-load.php',
            'wp-blog-header.php',
            'wp-login.php',
            'wp-cron.php',
            'wp-mail.php',
            'wp-signup.php',
            'wp-trackback.php',
            'xmlrpc.php',
            'wp-settings.php',
            'wp-links-opml.php'
        );
        return in_array( $basename_lower, $decoys, true );
    }

    /**
     * Find the single official checksum path this shortened core file belongs to.
     *
     * The unknown path must be a strict prefix of exactly one checksum path, and
     * the file hash must equal that checksum. Two matches are rejected so a shared
     * prefix cannot rename the file to the wrong class.
     *
     * @param string $unknown_path Path relative to ABSPATH.
     * @param string $md5          MD5 of the file on disk.
     * @param array  $filehashes   Official path => md5.
     * @return string|false Official relative path, or false.
     */
    public static function match_truncated_checksum_path( $unknown_path, $md5, $filehashes ) {
        $unknown_path = self::normalize_relative_path( $unknown_path );
        if ( false === $unknown_path || !is_string( $md5 ) || '' === $md5 || !is_array( $filehashes ) ) {
            return false;
        }
        if ( strlen( $unknown_path ) < self::TRUNCATED_CORE_MIN_LENGTH ) {
            return false;
        }
        if ( 0 !== strpos( $unknown_path, 'wp-includes/' ) && 0 !== strpos( $unknown_path, 'wp-admin/' ) ) {
            return false;
        }
        $matches = array();
        $prefix_len = strlen( $unknown_path );
        foreach ( $filehashes as $path => $hash ) {
            if ( !is_string( $path ) || !is_string( $hash ) ) {
                continue;
            }
            if ( strlen( $path ) <= $prefix_len ) {
                continue;
            }
            if ( 0 !== strncmp( $path, $unknown_path, $prefix_len ) ) {
                continue;
            }
            if ( !hash_equals( $hash, $md5 ) ) {
                continue;
            }
            $matches[] = $path;
            if ( count( $matches ) > 1 ) {
                return false;
            }
        }
        if ( 1 !== count( $matches ) ) {
            return false;
        }
        return $matches[0];
    }

    /**
     * Move checksum-matching shortened core files out of the unknown and missing lists.
     *
     * @param array       $results    Scan results, by reference.
     * @param array       $filehashes Official path => md5.
     * @param string|null $root       WordPress root. Default ABSPATH.
     * @return void
     */
    public static function separate_truncated_core_files( &$results, $filehashes, $root = null ) {
        if ( !is_array( $results ) ) {
            return;
        }
        $results['truncated_core'] = array();
        if ( empty( $results['unknown_bad'] ) || !is_array( $results['unknown_bad'] ) || !is_array( $filehashes ) ) {
            return;
        }
        $root = trailingslashit( ( null === $root ? ABSPATH : $root ) );
        $keep_unknown = array();
        $truncated = array();
        $hide_missing = array();
        foreach ( $results['unknown_bad'] as $path ) {
            if ( !is_string( $path ) ) {
                continue;
            }
            $full = $root . $path;
            if ( !is_file( $full ) ) {
                $keep_unknown[] = $path;
                continue;
            }
            $md5 = md5_file( $full );
            if ( !is_string( $md5 ) ) {
                $keep_unknown[] = $path;
                continue;
            }
            $official = self::match_truncated_checksum_path( $path, $md5, $filehashes );
            if ( false === $official ) {
                $keep_unknown[] = $path;
                continue;
            }
            $official_full = $root . $official;
            $official_hash = ( isset( $filehashes[$official] ) ? (string) $filehashes[$official] : '' );
            $official_ok = '' !== $official_hash && is_file( $official_full ) && hash_equals( $official_hash, (string) md5_file( $official_full ) );
            $conflict = is_file( $official_full ) && !$official_ok;
            $truncated[] = array(
                'file'        => $path,
                'official'    => $official,
                'official_ok' => $official_ok,
                'conflict'    => $conflict,
            );
            if ( !$official_ok && !$conflict ) {
                $hide_missing[$official] = true;
            }
        }
        $results['unknown_bad'] = array_values( $keep_unknown );
        $results['truncated_core'] = $truncated;
        if ( !empty( $hide_missing ) && !empty( $results['missing_bad'] ) && is_array( $results['missing_bad'] ) ) {
            $results['missing_bad'] = array_values( array_filter( $results['missing_bad'], function ( $file ) use($hide_missing) {
                return !isset( $hide_missing[$file] );
            } ) );
        }
    }

    /**
     * Rename a shortened core file back to its official path, or delete a leftover copy.
     *
     * Refuses to overwrite an official path whose contents do not match the checksum.
     *
     * @param string      $truncated_path Path relative to the WordPress root.
     * @param array       $filehashes     Official path => md5.
     * @param string|null $root           WordPress root. Default ABSPATH.
     * @return true|\WP_Error
     */
    public static function repair_truncated_core_copy( $truncated_path, $filehashes, $root = null ) {
        $truncated_path = self::normalize_relative_path( $truncated_path );
        if ( false === $truncated_path ) {
            return new \WP_Error('invalid_path', __( 'Invalid file path.', 'security-ninja' ));
        }
        $root_real = realpath( ( null === $root ? ABSPATH : $root ) );
        if ( false === $root_real ) {
            return new \WP_Error('bad_root', __( 'Could not resolve the WordPress root.', 'security-ninja' ));
        }
        $root_real = wp_normalize_path( $root_real );
        $source = $root_real . '/' . $truncated_path;
        if ( !is_file( $source ) ) {
            return new \WP_Error('missing_source', __( 'The shortened file is no longer on disk.', 'security-ninja' ));
        }
        $md5 = md5_file( $source );
        if ( !is_string( $md5 ) ) {
            return new \WP_Error('unreadable', __( 'Could not read the shortened file.', 'security-ninja' ));
        }
        $official = self::match_truncated_checksum_path( $truncated_path, $md5, $filehashes );
        if ( false === $official || empty( $filehashes[$official] ) || !is_string( $filehashes[$official] ) ) {
            return new \WP_Error('no_match', __( 'This file does not match an official WordPress checksum.', 'security-ninja' ));
        }
        $source_real = realpath( $source );
        if ( false === $source_real || 0 !== strpos( wp_normalize_path( $source_real ), $root_real . '/' ) ) {
            return new \WP_Error('bad_source', __( 'The shortened file is outside the WordPress root.', 'security-ninja' ));
        }
        $dest = $root_real . '/' . $official;
        if ( 0 !== strpos( wp_normalize_path( $dest ), $root_real . '/' ) ) {
            return new \WP_Error('bad_dest', __( 'The official path is outside the WordPress root.', 'security-ninja' ));
        }
        $dest_dir = realpath( dirname( $dest ) );
        if ( false === $dest_dir || 0 !== strpos( wp_normalize_path( $dest_dir ), $root_real . '/' ) ) {
            return new \WP_Error('bad_dest_dir', __( 'The official file directory is missing.', 'security-ninja' ));
        }
        if ( is_file( $dest ) ) {
            $dest_md5 = md5_file( $dest );
            if ( !is_string( $dest_md5 ) || !hash_equals( $filehashes[$official], $dest_md5 ) ) {
                return new \WP_Error('dest_conflict', __( 'The official filename already exists, and its contents do not match the checksum. The shortened file was left in place.', 'security-ninja' ));
            }
            wp_delete_file( $source );
            if ( is_file( $source ) ) {
                return new \WP_Error('delete_failed', __( 'Could not delete the shortened leftover.', 'security-ninja' ));
            }
            return true;
        }
        if ( !is_writable( $dest_dir ) ) {
            return new \WP_Error('not_writable', __( 'The core directory is not writable.', 'security-ninja' ));
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Same-directory rename keeps the verified bytes. No new content is written.
        if ( !rename( $source_real, $dest ) ) {
            return new \WP_Error('rename_failed', __( 'Could not restore the official filename.', 'security-ninja' ));
        }
        clearstatcache( true, $dest );
        $renamed_md5 = md5_file( $dest );
        if ( !is_string( $renamed_md5 ) || !hash_equals( $filehashes[$official], $renamed_md5 ) ) {
            return new \WP_Error('rename_mismatch', __( 'The file was renamed, but the checksum no longer matches.', 'security-ninja' ));
        }
        return true;
    }

}
