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
     * Transient expiry for original core file content (1 day).
     *
     * @var int
     */
    const ORIGINAL_FILE_TRANSIENT_EXPIRY = DAY_IN_SECONDS;

    /**
     * Option name for user-ignored unknown core files.
     *
     * @var string
     */
    const USER_IGNORE_OPTION = 'wf_sn_cs_user_ignore';

    /**
     * Maximum number of user-ignored paths stored.
     *
     * @var int
     */
    const USER_IGNORE_MAX = 500;

    /**
     * Retrieve file hashes from the WordPress.org API.
     *
     * @return array|false List of checksums or false on error.
     */
    public static function get_file_hashes() {
        $ver = get_bloginfo( 'version' );
        $locale = get_locale();
        if ( !function_exists( 'get_core_checksums' ) ) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $cs = get_core_checksums( $ver, ( isset( $locale ) ? $locale : 'en_US' ) );
        if ( empty( $cs['checksums'] ) ) {
            $cs = get_core_checksums( $ver, 'en_US' );
        }
        if ( $cs ) {
            $cleaned = array();
            foreach ( $cs as $path => $hash ) {
                $cleaned[$path] = $hash;
            }
            set_transient( 'wf_sn_hashes_' . $ver . '_' . $locale, $cleaned, MINUTE_IN_SECONDS * 15 );
            return $cleaned;
        }
        return false;
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
        $stored = get_option( self::USER_IGNORE_OPTION, array() );
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
        update_option( self::USER_IGNORE_OPTION, $paths, false );
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
        update_option( self::USER_IGNORE_OPTION, $paths, false );
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
     * Get original WordPress core file content from Trac.
     * Caches result in a transient for 1 day per file/version.
     *
     * @param string      $relative_path Relative path (e.g. 'wp-includes/js/dist/blocks.js').
     * @param string|null $version       WordPress version. Default current.
     * @return string|\WP_Error File body or WP_Error on failure.
     */
    public static function get_original_core_file_content( $relative_path, $version = null ) {
        $version = ( $version ? $version : get_bloginfo( 'version' ) );
        $key = 'wf_sn_cs_orig_' . $version . '_' . md5( $relative_path );
        $cached = get_transient( $key );
        if ( false !== $cached && is_string( $cached ) ) {
            return $cached;
        }
        $url = 'https://core.trac.wordpress.org/browser/tags/' . $version . '/src/' . $relative_path . '?format=txt';
        $r = wp_remote_get( $url );
        if ( is_wp_error( $r ) ) {
            return $r;
        }
        if ( 404 === wp_remote_retrieve_response_code( $r ) ) {
            return new \WP_Error('not_found', __( 'Original file not found.', 'security-ninja' ));
        }
        $body = wp_remote_retrieve_body( $r );
        if ( '' === $body ) {
            return new \WP_Error('empty', __( 'Unable to download remote file source.', 'security-ninja' ));
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

}
