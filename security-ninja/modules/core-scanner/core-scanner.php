<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Core Scanner Module
 *
 * This module provides functionality to scan WordPress core files for modifications,
 * missing files, and unknown files that shouldn't be present in core directories.
 *
 * @package WPSecurityNinja\Plugin
 */
/**
 * Core Scanner Class
 */
class Wf_Sn_Cs {
    /**
     * API endpoint for core checksums
     *
     * @var string
     */
    public static $hash_storage = 'https://api.wordpress.org/core/checksums/1.0/';

    /**
     * Check if a file path is within WordPress core directories
     *
     * @param string $filepath The file path to check
     * @return bool Whether the file is within core directories
     */
    public static function is_core_file( $filepath ) {
        // Prevent directory traversal attacks
        if ( strpos( $filepath, '..' ) !== false ) {
            return false;
        }
        // Normalize the file path
        $filepath = realpath( $filepath );
        if ( false === $filepath ) {
            return false;
        }
        // Define core WordPress directories
        $core_dirs = array(realpath( ABSPATH . 'wp-admin' ), realpath( ABSPATH . WPINC ), realpath( ABSPATH ));
        // Check if the file is within any core directory
        foreach ( $core_dirs as $core_dir ) {
            if ( false !== $core_dir && strpos( $filepath, $core_dir ) === 0 ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Initialize the Core Scanner module
     *
     * @return void
     */
    public static function init() {
        add_action( 'secnin_run_core_scanner', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_secnin_run_core_scanner') );
        add_action( 'init', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'schedule_cron_jobs') );
        add_action( 'admin_post_sn_core_scan_report', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'render_scan_report') );
        if ( current_user_can( 'manage_options' ) ) {
            add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'sn_tabs') );
            add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'enqueue_scripts') );
            add_action( 'wp_ajax_sn_core_get_file_source', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'get_file_source') );
            add_action( 'wp_ajax_sn_core_delete_file_do', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'delete_file') );
            add_action( 'wp_ajax_sn_core_restore_file_do', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'restore_file') );
            add_action( 'wp_ajax_sn_core_run_scan', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_core_run_scan') );
            add_action( 'wp_ajax_sn_core_get_cached_results', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'get_cached_results') );
            add_action( 'wp_ajax_sn_core_delete_all_unknowns', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_delete_all_unknowns') );
            add_action( 'wp_ajax_sn_core_ignore_file', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'ignore_unknown_file') );
            add_action( 'wp_ajax_sn_core_unignore_file', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'unignore_unknown_file') );
        }
    }

    /**
     * Load Core Scanner utils class when needed (conditional load).
     *
     * @return void
     */
    public static function load_utils() {
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Cs_Utils' ) ) {
            require_once WF_SN_PLUGIN_DIR . 'modules/core-scanner/class-wf-sn-cs-utils.php';
        }
    }

    /**
     * Build the meta-string values (last_scan, files_checked, wp_version) from data arrays.
     *
     * @param array $results Data-only results array with last_run, total, run_time.
     * @return array Associative array with keys last_scan, files_checked, wp_version.
     */
    public static function build_meta_strings( $results ) {
        $last_scan = '';
        if ( !empty( $results['last_run'] ) ) {
            $last_scan = sprintf( 
                /* translators: %1$s: formatted date/time of last scan */
                esc_html__( 'Last scan at %1$s', 'security-ninja' ),
                date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['last_run'] )
             );
        }
        $files_checked = '';
        if ( isset( $results['total'] ) ) {
            $run_time = ( isset( $results['run_time'] ) ? $results['run_time'] : '0' );
            $root_scanned = ( isset( $results['root_files_scanned'] ) ? (int) $results['root_files_scanned'] : 0 );
            $files_checked = sprintf(
                /* translators: 1: number of checksum files, 2: seconds (run time), 3: number of root files scanned */
                esc_html__( '%1$s core checksum files verified in %2$s sec (%3$s root files scanned)', 'security-ninja' ),
                number_format( $results['total'] ),
                number_format( (float) $run_time, 2 ),
                number_format( $root_scanned )
            );
        }
        $version = get_bloginfo( 'version' );
        $locale = get_locale();
        $wp_version = sprintf( 
            /* translators: 1: WordPress version, 2: locale code */
            esc_html__( 'WordPress version %1$s %2$s', 'security-ninja' ),
            $version,
            $locale
         );
        return array(
            'last_scan'     => $last_scan,
            'files_checked' => $files_checked,
            'wp_version'    => $wp_version,
        );
    }

    /**
     * Attach severity metadata for unknown files.
     *
     * @param array $results Scan results (by reference).
     * @return void
     */
    public static function enrich_results_with_findings( &$results ) {
        self::load_utils();
        if ( !empty( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            $results['unknown_findings'] = Wf_Sn_Cs_Utils::build_unknown_findings( $results['unknown_bad'] );
        } else {
            $results['unknown_findings'] = array();
        }
    }

    /**
     * Count badge-worthy issues in stored results.
     *
     * @param array $results Scan results.
     * @return int
     */
    public static function get_issue_count( $results ) {
        if ( !is_array( $results ) ) {
            return 0;
        }
        $total = 0;
        foreach ( array('missing_bad', 'changed_bad') as $key ) {
            if ( empty( $results[$key] ) || !is_array( $results[$key] ) ) {
                continue;
            }
            foreach ( $results[$key] as $file ) {
                if ( !self::is_file_ignored( $file ) ) {
                    ++$total;
                }
            }
        }
        $findings = ( isset( $results['unknown_findings'] ) && is_array( $results['unknown_findings'] ) ? $results['unknown_findings'] : array() );
        if ( !empty( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            foreach ( $results['unknown_bad'] as $file ) {
                if ( self::is_file_ignored( $file ) ) {
                    continue;
                }
                $severity = ( isset( $findings[$file]['severity'] ) ? $findings[$file]['severity'] : 'warning' );
                if ( Wf_Sn_Cs_Utils::severity_counts_in_badge( $severity ) ) {
                    ++$total;
                }
            }
        }
        return $total;
    }

    /**
     * Whether results contain any findings worth showing or reporting.
     *
     * @param array $results Scan results.
     * @return bool
     */
    public static function has_any_findings( $results ) {
        if ( !is_array( $results ) ) {
            return false;
        }
        return !empty( $results['changed_bad'] ) || !empty( $results['missing_bad'] ) || !empty( $results['unknown_bad'] );
    }

    /**
     * Build standardized AJAX payload for Core Scanner UI updates.
     *
     * @param array $results Scan results.
     * @return array
     */
    public static function build_ajax_payload( $results ) {
        self::enrich_results_with_findings( $results );
        $meta = self::build_meta_strings( $results );
        $has_findings = self::has_any_findings( $results );
        $issue_count = self::get_issue_count( $results );
        $report_url = ( $has_findings ? admin_url( 'admin-post.php?action=sn_core_scan_report&_wpnonce=' . wp_create_nonce( 'sn_core_scan_report' ) ) : '' );
        return array(
            'out'           => self::build_results_output( $results ),
            'last_scan'     => $meta['last_scan'],
            'files_checked' => $meta['files_checked'],
            'wp_version'    => $meta['wp_version'],
            'next_scan'     => self::get_next_scan_string(),
            'has_issues'    => $has_findings,
            'issue_count'   => $issue_count,
            'report_url'    => $report_url,
        );
    }

    /**
     * Banner class and copy for the summary strip.
     *
     * @param array $results Scan results.
     * @return array{class:string,text:string}
     */
    private static function get_banner_copy( $results ) {
        self::enrich_results_with_findings( $results );
        $stats = self::get_results_stats( $results );
        $issue_count = self::get_issue_count( $results );
        if ( $issue_count > 0 ) {
            return array(
                'class' => 'sn-cs-banner-issues',
                'text'  => sprintf( 
                    /* translators: %d: number of issues requiring attention */
                    _n(
                        '%d issue needs your attention',
                        '%d issues need your attention',
                        $issue_count,
                        'security-ninja'
                    ),
                    number_format_i18n( $issue_count )
                 ),
            );
        }
        if ( $stats['unknown'] > 0 ) {
            return array(
                'class' => 'sn-cs-banner-clean',
                'text'  => sprintf( 
                    /* translators: %s: formatted count of extra files */
                    _n(
                        'Core files check out — 1 extra file is noted below (likely intentional)',
                        'Core files check out — %s extra files are noted below (likely intentional)',
                        $stats['unknown'],
                        'security-ninja'
                    ),
                    number_format_i18n( $stats['unknown'] )
                 ),
            );
        }
        return array(
            'class' => 'sn-cs-banner-clean',
            'text'  => __( 'Core WordPress files look good', 'security-ninja' ),
        );
    }

    /**
     * CSS class for the findings list wrapper (left-edge accent, no nested card).
     *
     * @param array $results Scan results.
     * @return string
     */
    private static function get_findings_wrap_class( $results ) {
        $issue_count = self::get_issue_count( $results );
        $class = 'sn-cs-findings-wrap';
        if ( $issue_count > 0 ) {
            $class .= ' sn-cs-findings-actionable';
        } elseif ( !empty( $results['unknown_bad'] ) ) {
            $class .= ' sn-cs-findings-notices';
        }
        return $class;
    }

    /**
     * Summary counts for the results strip and row-action AJAX payloads.
     *
     * @param array $results Scan results.
     * @return array{modified:int,missing:int,unknown:int,verified:int}
     */
    private static function get_results_stats( $results ) {
        return array(
            'modified' => ( !empty( $results['changed_bad'] ) && is_array( $results['changed_bad'] ) ? count( $results['changed_bad'] ) : 0 ),
            'missing'  => ( !empty( $results['missing_bad'] ) && is_array( $results['missing_bad'] ) ? count( $results['missing_bad'] ) : 0 ),
            'unknown'  => ( !empty( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ? count( $results['unknown_bad'] ) : 0 ),
            'verified' => ( isset( $results['total'] ) ? (int) $results['total'] : 0 ),
        );
    }

    /**
     * Slim AJAX payload for delete/restore row actions (no HTML, no rescan).
     *
     * @param array        $results     Patched scan results.
     * @param string|array $file_shorts Relative path(s) removed from the UI.
     * @return array
     */
    public static function build_row_action_payload( $results, $file_shorts, $include_section_html = false ) {
        if ( !is_array( $file_shorts ) ) {
            $file_shorts = array($file_shorts);
        }
        self::enrich_results_with_findings( $results );
        $stats = self::get_results_stats( $results );
        $has_issues = self::has_any_findings( $results );
        $banner = self::get_banner_copy( $results );
        $payload = array(
            'file_shorts'         => array_values( $file_shorts ),
            'stats'               => $stats,
            'issue_count'         => self::get_issue_count( $results ),
            'has_issues'          => $has_issues,
            'report_url'          => ( $has_issues ? admin_url( 'admin-post.php?action=sn_core_scan_report&_wpnonce=' . wp_create_nonce( 'sn_core_scan_report' ) ) : '' ),
            'banner_class'        => $banner['class'],
            'banner_text'         => $banner['text'],
            'findings_wrap_class' => self::get_findings_wrap_class( $results ),
        );
        if ( $include_section_html ) {
            $payload['ignored_html'] = self::build_ignored_files_section_html( $results );
            $payload['unknown_html'] = self::build_unknown_files_sections( $results );
        }
        return $payload;
    }

    /**
     * Remove path(s) from cached scan results without rescanning.
     *
     * @param string|array $relative_paths Path(s) relative to ABSPATH.
     * @return array Updated results.
     */
    private static function remove_paths_from_cached_results( $relative_paths ) {
        $results = get_option( 'wf_sn_cs_results', array() );
        if ( !is_array( $results ) ) {
            return array();
        }
        if ( !is_array( $relative_paths ) ) {
            $relative_paths = array($relative_paths);
        }
        $remove = array_flip( $relative_paths );
        foreach ( array('unknown_bad', 'changed_bad', 'missing_bad') as $key ) {
            if ( empty( $results[$key] ) || !is_array( $results[$key] ) ) {
                continue;
            }
            $results[$key] = array_values( array_filter( $results[$key], function ( $file ) use($remove) {
                return !isset( $remove[$file] );
            } ) );
        }
        self::enrich_results_with_findings( $results );
        update_option( 'wf_sn_cs_results', $results, false );
        return $results;
    }

    /**
     * Whether a relative path is in cached scan unknown_bad results.
     *
     * @param string $relative_path Normalized relative path.
     * @return bool
     */
    private static function is_path_in_cached_unknown_bad( $relative_path ) {
        $results = get_option( 'wf_sn_cs_results', array() );
        if ( !is_array( $results ) || empty( $results['unknown_bad'] ) || !is_array( $results['unknown_bad'] ) ) {
            return false;
        }
        return in_array( $relative_path, $results['unknown_bad'], true );
    }

    /**
     * Patch cached results after a user ignores an unknown file.
     *
     * @param string $relative_path Normalized relative path.
     * @return array Updated results.
     */
    private static function patch_cached_results_after_ignore( $relative_path ) {
        $results = get_option( 'wf_sn_cs_results', array() );
        if ( !is_array( $results ) ) {
            return array();
        }
        if ( !empty( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            $results['unknown_bad'] = array_values( array_filter( $results['unknown_bad'], function ( $file ) use($relative_path) {
                return $file !== $relative_path;
            } ) );
        }
        if ( empty( $results['ignored_files'] ) || !is_array( $results['ignored_files'] ) ) {
            $results['ignored_files'] = array();
        }
        $exists = false;
        foreach ( $results['ignored_files'] as $ignored ) {
            if ( isset( $ignored['file'] ) && $ignored['file'] === $relative_path ) {
                $exists = true;
                break;
            }
        }
        if ( !$exists ) {
            $results['ignored_files'][] = array(
                'file'   => $relative_path,
                'reason' => 'user',
            );
        }
        self::enrich_results_with_findings( $results );
        update_option( 'wf_sn_cs_results', $results, false );
        return $results;
    }

    /**
     * Patch cached results after a user stops ignoring a file.
     *
     * @param string $relative_path Normalized relative path.
     * @return array Updated results.
     */
    private static function patch_cached_results_after_unignore( $relative_path ) {
        $results = get_option( 'wf_sn_cs_results', array() );
        if ( !is_array( $results ) ) {
            return array();
        }
        if ( !empty( $results['ignored_files'] ) && is_array( $results['ignored_files'] ) ) {
            $results['ignored_files'] = array_values( array_filter( $results['ignored_files'], function ( $ignored ) use($relative_path) {
                return !(isset( $ignored['file'], $ignored['reason'] ) && $ignored['file'] === $relative_path && 'user' === $ignored['reason']);
            } ) );
        }
        $abs_path = trailingslashit( ABSPATH ) . $relative_path;
        if ( file_exists( $abs_path ) ) {
            self::load_utils();
            $filehashes = self::get_file_hashes();
            if ( is_array( $filehashes ) && !isset( $filehashes[$relative_path] ) ) {
                if ( empty( $results['unknown_bad'] ) || !is_array( $results['unknown_bad'] ) ) {
                    $results['unknown_bad'] = array();
                }
                if ( !in_array( $relative_path, $results['unknown_bad'], true ) ) {
                    $results['unknown_bad'][] = $relative_path;
                }
            }
        }
        self::enrich_results_with_findings( $results );
        update_option( 'wf_sn_cs_results', $results, false );
        return $results;
    }

    /**
     * Human-readable next scheduled scan string.
     *
     * @return string
     */
    public static function get_next_scan_string() {
        $next_scan_ts = wp_next_scheduled( 'secnin_run_core_scanner' );
        if ( !$next_scan_ts ) {
            return __( 'No core scan currently scheduled.', 'security-ninja' );
        }
        return sprintf( 
            /* translators: 1: formatted date/time of next scan, 2: human time until next scan */
            esc_html__( '%1$s (%2$s from now)', 'security-ninja' ),
            date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan_ts ),
            human_time_diff( time(), $next_scan_ts )
         );
    }

    /**
     * WordPress version and next scheduled scan line for the scan summary.
     *
     * @return string
     */
    private static function build_scan_context_meta_html() {
        $meta = self::build_meta_strings( array() );
        $out = '<div class="sn-cs-scan-meta">';
        $out .= '<div class="sn-cs-meta-items">';
        $out .= '<span class="sn-cs-meta-item">' . esc_html__( 'WordPress Version', 'security-ninja' ) . ': <strong id="wp_version">' . esc_html( $meta['wp_version'] ) . '</strong></span>';
        $out .= '<span class="sn-cs-meta-item">' . esc_html__( 'Next Scheduled Scan', 'security-ninja' ) . ': <strong id="next_scan">' . esc_html( self::get_next_scan_string() ) . '</strong></span>';
        $out .= '</div>';
        $out .= '</div>';
        return $out;
    }

    /**
     * Group unknown file paths by location bucket.
     *
     * @param array $files Relative paths.
     * @return array<string, string[]>
     */
    public static function group_unknown_files_by_location( $files ) {
        $groups = array(
            'root'        => array(),
            'wp_admin'    => array(),
            'wp_includes' => array(),
            'other'       => array(),
        );
        if ( !is_array( $files ) ) {
            return $groups;
        }
        foreach ( $files as $file ) {
            if ( 0 === strpos( $file, 'wp-admin/' ) ) {
                $groups['wp_admin'][] = $file;
            } elseif ( 0 === strpos( $file, 'wp-includes/' ) ) {
                $groups['wp_includes'][] = $file;
            } elseif ( false === strpos( $file, '/' ) ) {
                $groups['root'][] = $file;
            } else {
                $groups['other'][] = $file;
            }
        }
        return $groups;
    }

    /**
     * Render a severity badge for findings tables.
     *
     * @param string $severity Severity key.
     * @return string
     */
    public static function render_severity_badge( $severity ) {
        $labels = array(
            'critical' => __( 'Critical', 'security-ninja' ),
            'warning'  => __( 'Warning', 'security-ninja' ),
            'notice'   => __( 'Notice', 'security-ninja' ),
        );
        $label = ( isset( $labels[$severity] ) ? $labels[$severity] : ucfirst( (string) $severity ) );
        return '<span class="sn-cs-severity sn-cs-severity-' . esc_attr( $severity ) . '">' . esc_html( $label ) . '</span>';
    }

    /**
     * Render file size and modification time beneath a findings path.
     *
     * @param string $relative_path Path relative to ABSPATH.
     * @return string
     */
    private static function get_file_meta_html( $relative_path ) {
        $path = ABSPATH . ltrim( str_replace( '\\', '/', (string) $relative_path ), '/' );
        if ( !is_file( $path ) ) {
            return '';
        }
        $size = size_format( (int) filesize( $path ) );
        $time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) filemtime( $path ) );
        return '<div class="sn-cs-file-meta">' . esc_html( sprintf( 
            /* translators: 1: file size, 2: file modification date/time */
            __( '%1$s · Modified %2$s', 'security-ninja' ),
            $size,
            $time
         ) ) . '</div>';
    }

    /**
     * Render findings as a WordPress admin table.
     *
     * @param array $rows Each row: type (file|group_header), file, severity, guidance, view, restore, delete.
     * @return string
     */
    public static function render_findings_table( $rows ) {
        if ( empty( $rows ) ) {
            return '';
        }
        $out = '<table class="widefat striped sn-cs-findings-table"><thead><tr>';
        $out .= '<th scope="col">' . esc_html__( 'File', 'security-ninja' ) . '</th>';
        $out .= '<th scope="col">' . esc_html__( 'Severity', 'security-ninja' ) . '</th>';
        $out .= '<th scope="col">' . esc_html__( 'Guidance', 'security-ninja' ) . '</th>';
        $out .= '<th scope="col">' . esc_html__( 'Actions', 'security-ninja' ) . '</th>';
        $out .= '</tr></thead><tbody>';
        foreach ( $rows as $row ) {
            $type = ( isset( $row['type'] ) ? (string) $row['type'] : 'file' );
            if ( 'group_header' === $type ) {
                $label = ( isset( $row['label'] ) ? (string) $row['label'] : '' );
                $out .= '<tr class="sn-cs-group-header"><td colspan="4"><strong>' . esc_html( $label ) . '</strong></td></tr>';
                continue;
            }
            $file = ( isset( $row['file'] ) ? (string) $row['file'] : '' );
            $severity = ( isset( $row['severity'] ) ? (string) $row['severity'] : 'warning' );
            $guidance = ( isset( $row['guidance'] ) ? (string) $row['guidance'] : '' );
            $out .= '<tr data-file-short="' . esc_attr( $file ) . '">';
            $out .= '<td><code class="sn-cs-file-path">' . esc_html( $file ) . '</code>' . self::get_file_meta_html( $file ) . '</td>';
            $out .= '<td>' . self::render_severity_badge( $severity ) . '</td>';
            $out .= '<td class="sn-cs-guidance">' . esc_html( $guidance ) . '</td>';
            $out .= '<td class="sn-cs-actions">' . self::render_file_action_buttons( $file, $row ) . '</td>';
            $out .= '</tr>';
        }
        $out .= '</tbody></table>';
        return $out;
    }

    /**
     * Build action buttons for a findings table row.
     *
     * @param string $file Relative file path.
     * @param array  $row  Row options: view, restore, delete booleans.
     * @return string
     */
    private static function render_file_action_buttons( $file, $row ) {
        $view = !empty( $row['view'] );
        $restore = !empty( $row['restore'] );
        $delete = !empty( $row['delete'] );
        $ignore = !empty( $row['ignore'] );
        $out = '';
        if ( $view ) {
            $file_path = ABSPATH . $file;
            if ( \WPSecurityNinja\Plugin\FileViewer::can_view_file( $file_path ) ) {
                $file_view_url = \WPSecurityNinja\Plugin\FileViewer::generate_file_view_url( $file_path );
                $out .= '<button type="button" class="button button-small input-button gray sn-cs-view-file" data-href="' . esc_attr( $file_view_url ) . '">' . esc_html__( 'View File', 'security-ninja' ) . '</button> ';
            }
            if ( $restore ) {
                $diff_url = \WPSecurityNinja\Plugin\FileViewer::generate_diff_view_url( $file_path );
                $out .= '<button type="button" class="button button-small input-button gray sn-cs-view-file" data-href="' . esc_attr( $diff_url ) . '">' . esc_html__( 'Diff', 'security-ninja' ) . '</button> ';
            }
        }
        if ( $restore ) {
            $file_path = ABSPATH . $file;
            $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'restore_file' );
            $out .= '<button type="button" class="button button-small input-button gray sn-restore-source" data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( $file_path ) . '">' . esc_html__( 'Restore', 'security-ninja' ) . '</button> ';
        }
        if ( $ignore ) {
            $file_path = ABSPATH . $file;
            $severity = ( isset( $row['severity'] ) ? (string) $row['severity'] : 'warning' );
            $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'ignore_file' );
            $out .= '<button type="button" class="button button-small input-button gray sn-cs-ignore-file" data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '" data-severity="' . esc_attr( $severity ) . '">' . esc_html__( 'Ignore', 'security-ninja' ) . '</button> ';
        }
        if ( $delete ) {
            $file_path = ABSPATH . $file;
            $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'delete_file' );
            $out .= '<button type="button" class="button button-small input-button gray sn-delete-source" data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( $file_path ) . '">' . esc_html__( 'Delete', 'security-ninja' ) . '</button>';
        }
        if ( '' === trim( $out ) ) {
            return '';
        }
        return '<span class="malactions">' . trim( $out ) . '</span>';
    }

    /**
     * Build summary stat strip HTML.
     *
     * @param array $results Scan results.
     * @return string
     */
    private static function build_summary_strip( $results ) {
        $stats = self::get_results_stats( $results );
        $banner = self::get_banner_copy( $results );
        $meta = self::build_meta_strings( $results );
        $scan_details = array();
        if ( !empty( $meta['last_scan'] ) ) {
            $scan_details[] = $meta['last_scan'];
        }
        if ( !empty( $meta['files_checked'] ) ) {
            $scan_details[] = $meta['files_checked'];
        }
        $out = '<div class="sn-cs-summary">';
        if ( !empty( $scan_details ) ) {
            $out .= '<p class="description sn-cs-scan-context" id="sn-cs-scan-details">' . esc_html( implode( ' · ', $scan_details ) ) . '</p>';
        }
        $out .= self::build_scan_context_meta_html();
        $out .= '<div class="sn-cs-banner ' . esc_attr( $banner['class'] ) . '"><strong>' . esc_html( $banner['text'] ) . '</strong></div>';
        $out .= '<div class="sn-cs-stats">';
        $out .= '<div class="sn-cs-stat" data-stat="modified"><span class="sn-cs-stat-count">' . esc_html( number_format_i18n( $stats['modified'] ) ) . '</span><span class="sn-cs-stat-label">' . esc_html__( 'Modified', 'security-ninja' ) . '</span></div>';
        $out .= '<div class="sn-cs-stat" data-stat="missing"><span class="sn-cs-stat-count">' . esc_html( number_format_i18n( $stats['missing'] ) ) . '</span><span class="sn-cs-stat-label">' . esc_html__( 'Missing', 'security-ninja' ) . '</span></div>';
        $out .= '<div class="sn-cs-stat" data-stat="unknown"><span class="sn-cs-stat-count">' . esc_html( number_format_i18n( $stats['unknown'] ) ) . '</span><span class="sn-cs-stat-label">' . esc_html__( 'Unknown', 'security-ninja' ) . '</span></div>';
        $out .= '<div class="sn-cs-stat sn-cs-stat-verified" data-stat="verified"><span class="sn-cs-stat-count">' . esc_html( number_format_i18n( $stats['verified'] ) ) . '</span><span class="sn-cs-stat-label">' . esc_html__( 'Verified', 'security-ninja' ) . '</span></div>';
        $out .= '</div>';
        $out .= '</div>';
        return $out;
    }

    /**
     * Contextual Pro bridge card for free users.
     *
     * @param array $results Scan results.
     * @return string
     */
    private static function build_pro_bridge_card( $results ) {
        if ( !function_exists( 'secnin_fs' ) || secnin_fs()->is_premium() ) {
            return '';
        }
        $pricing_url = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'core_scanner_upsell', '/upgrade/' );
        $changed = !empty( $results['changed_bad'] );
        $unknown = !empty( $results['unknown_bad'] );
        if ( $changed ) {
            $text = __( 'Modified core files should be treated seriously. Pro adds scheduled scans, email alerts, and Events Logger audit trail.', 'security-ninja' );
        } elseif ( $unknown ) {
            $text = __( 'Core Scanner found extra files WordPress did not ship. Malware Scanner (Pro) can inspect plugins and themes where most infections hide.', 'security-ninja' );
        } else {
            $text = __( 'Core WordPress files look good. Malware Scanner (Pro) checks plugins, themes, and uploads for malware signatures and suspicious folder structure.', 'security-ninja' );
        }
        $out = '<div class="sncard infobox sn-cs-pro-bridge">';
        $out .= '<p>' . esc_html( $text ) . '</p>';
        $out .= '<p><a href="#sn_malware" class="button button-secondary">' . esc_html__( 'Explore Malware Scanner', 'security-ninja' ) . '</a> ';
        $out .= '<a href="' . esc_url( $pricing_url ) . '" class="button-link" target="_blank" rel="noopener noreferrer">' . esc_html__( 'View Pro features', 'security-ninja' ) . '</a></p>';
        $out .= '</div>';
        return $out;
    }

    /**
     * Build table rows for unknown files grouped by location.
     *
     * @param array $results Scan results.
     * @return string
     */
    private static function build_unknown_files_sections( $results ) {
        if ( empty( $results['unknown_bad'] ) || !is_array( $results['unknown_bad'] ) ) {
            return '';
        }
        $findings = ( isset( $results['unknown_findings'] ) && is_array( $results['unknown_findings'] ) ? $results['unknown_findings'] : array() );
        $groups = self::group_unknown_files_by_location( $results['unknown_bad'] );
        $labels = array(
            'root'        => __( 'Site root', 'security-ninja' ),
            'wp_admin'    => __( 'wp-admin', 'security-ninja' ),
            'wp_includes' => __( 'wp-includes', 'security-ninja' ),
            'other'       => __( 'Other', 'security-ninja' ),
        );
        $out = '<div class="sn-cs-section" data-section="unknown">';
        $out .= '<h4>' . esc_html__( 'Unknown files', 'security-ninja' ) . ' (' . esc_html( number_format_i18n( count( $results['unknown_bad'] ) ) ) . ')</h4>';
        $out .= '<p class="description">' . esc_html__( 'These files are not part of the official WordPress package for your version. Severity indicates urgency; notices are often intentional custom files.', 'security-ninja' ) . '</p>';
        $rows = array();
        foreach ( $groups as $key => $files ) {
            if ( empty( $files ) ) {
                continue;
            }
            $rows[] = array(
                'type'  => 'group_header',
                'label' => $labels[$key],
            );
            foreach ( $files as $file ) {
                $meta = ( isset( $findings[$file] ) ? $findings[$file] : Wf_Sn_Cs_Utils::classify_unknown_file( $file ) );
                $rows[] = array(
                    'type'     => 'file',
                    'file'     => $file,
                    'severity' => $meta['severity'],
                    'guidance' => $meta['guidance'],
                    'view'     => true,
                    'ignore'   => true,
                    'delete'   => true,
                );
            }
        }
        $out .= self::render_findings_table( $rows );
        $out .= '<p class="sn-cs-delete-all-wrap"><button type="button" class="sn-delete-all-files button button-secondary button-small">' . esc_html__( 'Delete critical & warning unknowns', 'security-ninja' ) . '</button></p>';
        $out .= '</div>';
        return $out;
    }

    /**
     * Build the full HTML output from a data-only results array.
     * Every call generates fresh tokens so links never expire.
     *
     * @param array $results Data-only results with changed_bad, missing_bad, unknown_bad, ignored_files.
     * @return string HTML for the Core Scanner results area.
     */
    private static function build_results_output( $results ) {
        self::enrich_results_with_findings( $results );
        if ( empty( $results['last_run'] ) ) {
            return self::build_empty_state();
        }
        $issue_count = self::get_issue_count( $results );
        $out = self::build_summary_strip( $results );
        if ( 0 === $issue_count && empty( $results['unknown_bad'] ) ) {
            $out .= '<div class="sncard noerrorsfound">' . esc_html__( 'No problems found', 'security-ninja' ) . '</div>';
            $out .= self::build_pro_bridge_card( $results );
            return $out;
        }
        $out .= '<div id="sn-cs-results" class="' . esc_attr( self::get_findings_wrap_class( $results ) ) . '">';
        $unknown_html = self::build_unknown_files_sections( $results );
        if ( $unknown_html ) {
            $out .= $unknown_html;
        }
        if ( !empty( $results['changed_bad'] ) ) {
            $rows = array();
            foreach ( $results['changed_bad'] as $file ) {
                $rows[] = array(
                    'file'     => $file,
                    'severity' => 'critical',
                    'guidance' => __( 'Core file checksum does not match the official WordPress package. If you did not modify this file, treat it as a potential infection.', 'security-ninja' ),
                    'view'     => true,
                    'restore'  => true,
                );
            }
            $out .= '<div class="sn-cs-section">';
            $out .= '<h4>' . esc_html__( 'Modified core files', 'security-ninja' ) . ' (' . esc_html( number_format_i18n( count( $results['changed_bad'] ) ) ) . ')</h4>';
            $out .= self::render_findings_table( $rows );
            $out .= '</div>';
        }
        if ( !empty( $results['missing_bad'] ) ) {
            $rows = array();
            foreach ( $results['missing_bad'] as $file ) {
                $rows[] = array(
                    'file'     => $file,
                    'severity' => 'critical',
                    'guidance' => __( 'Expected core file is missing. Restore from the official WordPress source if there is no legitimate reason for it to be absent.', 'security-ninja' ),
                    'restore'  => true,
                );
            }
            $out .= '<div class="sn-cs-section">';
            $out .= '<h4>' . esc_html__( 'Missing core files', 'security-ninja' ) . ' (' . esc_html( number_format_i18n( count( $results['missing_bad'] ) ) ) . ')</h4>';
            $out .= self::render_findings_table( $rows );
            $out .= '</div>';
        }
        $out .= '</div>';
        $out .= self::build_ignored_files_section_html( $results );
        $out .= self::build_pro_bridge_card( $results );
        return $out;
    }

    /**
     * Build the Ignored files section HTML.
     *
     * @param array $results Scan results.
     * @return string Empty string when no ignored files.
     */
    private static function build_ignored_files_section_html( $results ) {
        if ( empty( $results['ignored_files'] ) || !is_array( $results['ignored_files'] ) ) {
            return '';
        }
        $out = '<div id="sn-cs-ignored-files" class="sn-cs-section sn-cs-ignored-files">';
        $out .= '<h4>' . esc_html__( 'Ignored files', 'security-ninja' ) . '</h4>';
        $out .= '<p class="description">' . esc_html__( 'The following files are ignored by filter settings or your choices.', 'security-ninja' ) . '</p>';
        $grouped = array();
        foreach ( $results['ignored_files'] as $ignored ) {
            $reason = ( isset( $ignored['reason'] ) ? $ignored['reason'] : 'unknown' );
            if ( !isset( $grouped[$reason] ) ) {
                $grouped[$reason] = array();
            }
            $grouped[$reason][] = $ignored['file'];
        }
        foreach ( $grouped as $reason => $files ) {
            $reason_label = '';
            switch ( $reason ) {
                case 'user':
                    $reason_label = __( 'Ignored by you', 'security-ninja' );
                    break;
                case 'unknown':
                    $reason_label = __( 'Unknown files', 'security-ninja' );
                    break;
                case 'changed':
                    $reason_label = __( 'Modified files', 'security-ninja' );
                    break;
                case 'missing':
                    $reason_label = __( 'Missing files', 'security-ninja' );
                    break;
            }
            if ( $reason_label ) {
                $out .= '<h5>' . esc_html( $reason_label ) . '</h5>';
                if ( 'user' === $reason ) {
                    $out .= self::render_user_ignored_file_list( $files );
                } else {
                    $out .= self::list_files(
                        $files,
                        false,
                        false,
                        false
                    );
                }
            }
        }
        $out .= '</div>';
        return $out;
    }

    /**
     * Render user-ignored files with Stop ignoring actions.
     *
     * @param string[] $files Relative file paths.
     * @return string
     */
    private static function render_user_ignored_file_list( $files ) {
        if ( empty( $files ) || !is_array( $files ) ) {
            return '';
        }
        $out = '<ul class="sn-file-list">';
        foreach ( $files as $file ) {
            $file_path = ABSPATH . $file;
            $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'revert_ignore_file' );
            $out .= '<li>';
            $out .= '<span class="sn-file">' . esc_html( $file ) . '</span>';
            $out .= '<span class="malactions">';
            $out .= '<button type="button" class="button button-small input-button gray sn-cs-unignore-file" data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '">' . esc_html__( 'Stop ignoring', 'security-ninja' ) . '</button>';
            $out .= '</span>';
            $out .= '</li>';
        }
        $out .= '</ul>';
        return $out;
    }

    /**
     * First-run / no scan empty state.
     *
     * @return string
     */
    private static function build_empty_state() {
        $out = '<div class="sncard sn-cs-empty-state">';
        $out .= '<h3>' . esc_html__( 'Run your first core scan', 'security-ninja' ) . '</h3>';
        $out .= '<ul class="sn-cs-empty-list">';
        $out .= '<li>' . esc_html__( 'Verifies wp-admin, wp-includes, the site root, and hidden files in core folders.', 'security-ninja' ) . '</li>';
        $out .= '<li>' . esc_html__( 'Compares files against official WordPress.org checksums for your version.', 'security-ninja' ) . '</li>';
        $out .= '<li>' . esc_html__( 'Free: runs locally on your server; no file contents are uploaded.', 'security-ninja' ) . '</li>';
        $out .= '</ul>';
        $out .= '</div>';
        return $out;
    }

    /**
     * Run the core scanner
     *
     * @return void
     */
    public static function do_action_secnin_run_core_scanner() {
        // Running the core scanner
        self::do_action_core_run_scan( true );
    }

    /**
     * Schedule cron jobs for core scanning
     *
     * @return void
     */
    public static function schedule_cron_jobs() {
        if ( !wp_next_scheduled( 'secnin_run_core_scanner' ) ) {
            wp_schedule_event( time(), 'daily', 'secnin_run_core_scanner' );
        }
    }

    /**
     * Delete all unknown files in core WordPress folders
     *
     * @return void
     */
    public static function do_action_delete_all_unknowns() {
        if ( !check_ajax_referer( 'wf-cs-delete-all-unknown-nonce', false, false ) ) {
            wp_send_json_error( __( 'Invalid nonce', 'security-ninja' ) );
        }
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        global $wp_filesystem;
        // Initialize the WordPress filesystem, if not already.
        if ( empty( $wp_filesystem ) ) {
            include_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        // DELETE critical & warning unknown files (notices require explicit per-file delete).
        $results = get_option( 'wf_sn_cs_results' );
        self::enrich_results_with_findings( $results );
        if ( isset( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            $deleted_files = 0;
            $deleted_paths = array();
            $failed_deletions = array();
            $findings = ( isset( $results['unknown_findings'] ) && is_array( $results['unknown_findings'] ) ? $results['unknown_findings'] : array() );
            foreach ( $results['unknown_bad'] as $ub ) {
                $severity = ( isset( $findings[$ub]['severity'] ) ? $findings[$ub]['severity'] : 'warning' );
                if ( !Wf_Sn_Cs_Utils::severity_counts_in_badge( $severity ) ) {
                    continue;
                }
                $filepath = ABSPATH . $ub;
                // Use WP filesystem method to delete files.
                if ( $wp_filesystem->exists( $filepath ) ) {
                    if ( $wp_filesystem->delete( $filepath ) ) {
                        ++$deleted_files;
                        $deleted_paths[] = $ub;
                    } else {
                        $failed_deletions[] = $filepath;
                    }
                }
            }
            if ( $deleted_files > 0 ) {
                /* translators: %d: number of deleted files */
                $message = sprintf( esc_html__( 'Deleted %d unknown files in Core WordPress folders', 'security-ninja' ), $deleted_files );
                $results = self::remove_paths_from_cached_results( $deleted_paths );
                wp_send_json_success( array_merge( self::build_row_action_payload( $results, $deleted_paths ), array(
                    'deleted' => $deleted_files,
                    'failed'  => $failed_deletions,
                ) ) );
            } else {
                wp_send_json_error( array(
                    'message' => __( 'No files were deleted.', 'security-ninja' ),
                    'failed'  => $failed_deletions,
                ) );
            }
        } else {
            wp_send_json_error( array(
                'message' => __( 'No unknown files found to delete.', 'security-ninja' ),
            ) );
        }
    }

    /**
     * Enqueue CSS and JS scripts for the Core Scanner
     *
     * @return void
     */
    public static function enqueue_scripts() {
        if ( wf_sn::is_plugin_page() ) {
            $plugin_url = plugin_dir_url( __FILE__ );
            wp_register_script(
                'sn-core-js',
                $plugin_url . 'js/wf-sn-core.js',
                array('jquery', 'sn-dialog'),
                \WPSecurityNinja\Plugin\Utils::get_plugin_version(),
                true
            );
            $js_vars = array(
                'nonce'            => wp_create_nonce( 'wf_sn_cs' ),
                'run_scan_nonce'   => wp_create_nonce( 'wf-cs-run-scan-nonce' ),
                'delete_all_nonce' => wp_create_nonce( 'wf-cs-delete-all-unknown-nonce' ),
                'strings'          => array(
                    'error_occurred'          => __( 'An error occurred', 'security-ninja' ),
                    'undocumented_error'      => __( 'An undocumented error occurred. The page will reload.', 'security-ninja' ),
                    'file_source'             => __( 'File source', 'security-ninja' ),
                    'confirm_restore'         => __( 'Are you sure you want to restore this file?', 'security-ninja' ),
                    'confirm_delete'          => __( 'Are you sure you want to delete this file?', 'security-ninja' ),
                    'confirm_delete_all'      => __( 'Delete all critical and warning unknown files? Notice-level custom files will be kept.', 'security-ninja' ),
                    'confirm_ignore_notice'   => __( 'Ignore this file? It will be hidden from Core Scanner findings on future scans.', 'security-ninja' ),
                    'confirm_ignore_warning'  => __( 'Ignore this file? Only do this if you are certain it is intentional. Ignoring may hide a real security risk.', 'security-ninja' ),
                    'confirm_ignore_critical' => __( 'Ignore this critical unknown file? Unexpected files in core locations are often malware. Only ignore if you are absolutely certain this file is safe and intentional.', 'security-ninja' ),
                    'confirm_unignore'        => __( 'Stop ignoring this file? It will reappear in the unknown files list.', 'security-ninja' ),
                    'ajax_error'              => __( 'An error occurred during the AJAX request.', 'security-ninja' ),
                    'please_wait'             => __( 'Please wait.', 'security-ninja' ),
                    'no_scan_yet'             => __( 'No scan made yet. Click "Scan Core Files" to run a scan.', 'security-ninja' ),
                    'loading'                 => __( 'Loading...', 'security-ninja' ),
                    'no_problems_found'       => __( 'No problems found', 'security-ninja' ),
                    'report_disabled'         => __( 'Available when issues are detected.', 'security-ninja' ),
                ),
            );
            wp_localize_script( 'sn-core-js', 'wf_sn_cs', $js_vars );
            wp_enqueue_script( 'sn-core-js' );
            wp_enqueue_style(
                'sn-core-css',
                $plugin_url . 'css/wf-sn-core.css',
                array(),
                wf_sn::$version
            );
        }
    }

    /**
     * AJAX response for viewing file source
     *
     * @return void
     */
    public static function get_file_source() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        $out = array();
        if ( !isset( $_POST['filename'] ) ) {
            $error = new \WP_Error('001', __( 'Filename not set', 'security-ninja' ));
            wp_send_json_error( $error );
        }
        $filename = sanitize_text_field( wp_unslash( $_POST['filename'] ) );
        // Validate that the file is within WordPress core directories
        if ( !self::is_core_file( $filename ) ) {
            $error = new \WP_Error('003', __( 'Access denied: File is not within WordPress core directories.', 'security-ninja' ));
            wp_send_json_error( $error );
        }
        // Validate the secure token
        if ( !isset( $_POST['hash'] ) || !isset( $_POST['nonce'] ) || !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $filename,
            wp_unslash( $_POST['hash'] ),
            wp_unslash( $_POST['nonce'] ),
            'view_file'
        ) ) {
            $error = new \WP_Error('002', __( 'Invalid file access token.', 'security-ninja' ));
            wp_send_json_error( $error );
        }
        $out['ext'] = pathinfo( $filename, PATHINFO_EXTENSION );
        $out['source'] = '';
        if ( is_readable( $filename ) ) {
            $content = file_get_contents( $filename );
            if ( false !== $content ) {
                $out['err'] = 0;
                $out['source'] = wp_kses_post( $content );
            } else {
                $out['err'] = __( 'File is empty.', 'security-ninja' );
            }
        } else {
            $out['err'] = __( 'File does not exist or is not readable.', 'security-ninja' );
        }
        die( wp_json_encode( $out ) );
    }

    /**
     * AJAX: Return cached Core Scanner results only (no scan).
     * Used when the Core Scanner tab is focused to lazy-load last results.
     *
     * @return void
     */
    public static function get_cached_results() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'You do not have sufficient permissions.', 'security-ninja' ),
            ) );
        }
        $results = get_option( 'wf_sn_cs_results', array() );
        self::load_utils();
        if ( !Wf_Sn_Cs_Utils::is_valid_results( $results ) ) {
            wp_send_json_success( array(
                'no_results' => true,
                'message'    => __( 'No scan made yet. Click "Scan Core Files" to run a scan.', 'security-ninja' ),
            ) );
        }
        wp_send_json_success( self::build_ajax_payload( $results ) );
    }

    /**
     * Output printable Core Scanner report (admin_post handler).
     * Only outputs when the last scan had issues.
     *
     * @return void
     */
    public static function render_scan_report() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        if ( !isset( $_GET['_wpnonce'] ) || !wp_verify_nonce( sanitize_key( wp_unslash( $_GET['_wpnonce'] ) ), 'sn_core_scan_report' ) ) {
            wp_die( 'Security check failed.' );
        }
        $results = get_option( 'wf_sn_cs_results', array() );
        $has_issues = !empty( $results['changed_bad'] ) || !empty( $results['missing_bad'] ) || !empty( $results['unknown_bad'] );
        if ( !$has_issues || empty( $results['last_run'] ) ) {
            wp_die( 'No issues to report. Run a scan from the Core Scanner tab when issues are detected to print a report.' );
        }
        $meta = self::build_meta_strings( $results );
        $last_scan = $meta['last_scan'];
        $files_checked = $meta['files_checked'];
        $wp_version = $meta['wp_version'];
        $title = __( 'Core Scanner Report', 'security-ninja' );
        ?>
		<!DOCTYPE html>
		<html <?php 
        language_attributes();
        ?>>

		<head>
			<meta charset="<?php 
        bloginfo( 'charset' );
        ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title><?php 
        echo esc_html( $title );
        ?></title>
			<style>
				body {
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
					margin: 1rem 2rem;
					color: #1d2327;
				}

				h1 {
					font-size: 1.5rem;
					margin-bottom: 0.5rem;
				}

				.meta {
					color: #646970;
					font-size: 0.875rem;
					margin-bottom: 1.5rem;
				}

				section {
					margin-bottom: 1.5rem;
				}

				section h2 {
					font-size: 1.1rem;
					margin-bottom: 0.5rem;
				}

				ul {
					margin: 0;
					padding-left: 1.5rem;
				}

				@media print {
					body {
						margin: 0.5in;
					}

					.no-print {
						display: none;
					}
				}
			</style>
		</head>

		<body>
			<h1><?php 
        echo esc_html( $title );
        ?></h1>
			<p class="meta"><?php 
        echo esc_html( $last_scan );
        ?> &bull; <?php 
        echo esc_html( $files_checked );
        ?> &bull; <?php 
        echo esc_html( $wp_version );
        ?></p>
			<?php 
        if ( !empty( $results['changed_bad'] ) ) {
            ?>
				<section>
					<h2><?php 
            esc_html_e( 'Modified core files', 'security-ninja' );
            ?></h2>
					<ul>
						<?php 
            foreach ( $results['changed_bad'] as $f ) {
                echo '<li>' . esc_html( $f ) . '</li>';
            }
            ?>
					</ul>
				</section>
			<?php 
        }
        ?>
			<?php 
        if ( !empty( $results['missing_bad'] ) ) {
            ?>
				<section>
					<h2><?php 
            esc_html_e( 'Missing core files', 'security-ninja' );
            ?></h2>
					<ul>
						<?php 
            foreach ( $results['missing_bad'] as $f ) {
                echo '<li>' . esc_html( $f ) . '</li>';
            }
            ?>
					</ul>
				</section>
			<?php 
        }
        ?>
			<?php 
        if ( !empty( $results['unknown_bad'] ) ) {
            ?>
				<section>
					<h2><?php 
            esc_html_e( 'Unknown files in core folders, site root, or hidden core files', 'security-ninja' );
            ?></h2>
					<p><?php 
            esc_html_e( 'These files are not part of the official WordPress package. Custom root files can be allowlisted via securityninja_core_scanner_ignore_files or securityninja_core_scanner_root_allowlist.', 'security-ninja' );
            ?></p>
					<ul>
						<?php 
            foreach ( $results['unknown_bad'] as $f ) {
                echo '<li>' . esc_html( $f ) . '</li>';
            }
            ?>
					</ul>
				</section>
			<?php 
        }
        ?>
			<p class="no-print"><small><?php 
        esc_html_e( 'You can print this page or save as PDF from your browser.', 'security-ninja' );
        ?></small></p>
		</body>

		</html>
		<?php 
        exit;
    }

    /**
     * Returns the number of problems with files currently detected
     * Excludes ignored files from the count
     *
     * @return int|false Number of problems or false if no problems
     */
    private static function return_problem_count() {
        $results = get_option( 'wf_sn_cs_results' );
        if ( !$results || !is_array( $results ) ) {
            return false;
        }
        $total = self::get_issue_count( $results );
        if ( $total > 0 ) {
            return $total;
        }
        return false;
    }

    /**
     * Add this module tab
     *
     * @param  array $tabs Array of tabs.
     * @return array Modified array of tabs.
     */
    public static function sn_tabs( $tabs ) {
        $core_tab = array(
            'id'       => 'sn_core',
            'class'    => '',
            'label'    => __( 'Core Scanner', 'security-ninja' ),
            'callback' => array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'core_page'),
        );
        $done = 0;
        $total = count( $tabs );
        $problems = self::return_problem_count();
        if ( $problems ) {
            $core_tab['count'] = $problems;
        }
        for ($i = 0; $i < $total; $i++) {
            if ( 'sn_core' === $tabs[$i]['id'] ) {
                $tabs[$i] = $core_tab;
                $done = 1;
                break;
            }
        }
        if ( !$done ) {
            $tabs[] = $core_tab;
        }
        return $tabs;
    }

    /**
     * Generate a list of files to scan in a folder
     *
     * @param  string     $path          Path to the folder.
     * @param  array|null $extensions    Array of file extensions to include or null for all files.
     * @param  int        $depth         Depth to scan.
     * @param  string     $relative_path    Relative path.
     * @param  bool       $include_dotfiles Include hidden dotfiles (except . and ..).
     * @return array|false Array of files or false if the path is not a directory.
     */
    public static function scan_folder(
        $path,
        $extensions = null,
        $depth = 3,
        $relative_path = '',
        $include_dotfiles = false
    ) {
        if ( !is_dir( $path ) ) {
            return false;
        }
        $_extensions = '';
        if ( $extensions ) {
            $extensions = (array) $extensions;
            $_extensions = implode( '|', $extensions );
        }
        $relative_path = trailingslashit( $relative_path );
        if ( '/' === $relative_path ) {
            $relative_path = '';
        }
        $results = scandir( $path );
        $files = array();
        foreach ( $results as $result ) {
            if ( '.' === $result || '..' === $result ) {
                continue;
            }
            if ( !$include_dotfiles && '.' === $result[0] ) {
                continue;
            }
            if ( is_dir( $path . '/' . $result ) ) {
                if ( $depth > 0 && 'CVS' !== $result ) {
                    $found = self::scan_folder(
                        $path . '/' . $result,
                        $extensions,
                        $depth - 1,
                        $relative_path . $result,
                        $include_dotfiles
                    );
                    if ( is_array( $found ) ) {
                        $files = array_merge( $files, $found );
                    }
                }
            } elseif ( !$extensions || preg_match( '~\\.(' . $_extensions . ')$~', $result ) ) {
                $files[$relative_path . $result] = $path . '/' . $result;
            }
        }
        return $files;
    }

    /**
     * Collect unknown files in core directories, site root, and ignored entries.
     *
     * @param array $filehashes Checksum map from get_file_hashes().
     * @return array{unknown_bad: string[], ignored_files: array, root_files_scanned: int}
     */
    public static function collect_unknown_core_files( $filehashes ) {
        self::load_utils();
        $unknown_bad = array();
        $ignored_files = array();
        $root_scanned = 0;
        $files = self::scan_folder(
            ABSPATH . WPINC,
            null,
            9,
            WPINC,
            true
        );
        $all_files = ( is_array( $files ) ? $files : array() );
        $files = self::scan_folder(
            ABSPATH . 'wp-admin',
            null,
            9,
            'wp-admin',
            true
        );
        if ( is_array( $files ) ) {
            $all_files = array_merge( $all_files, $files );
        }
        foreach ( $all_files as $key => $af ) {
            if ( !isset( $filehashes[$key] ) ) {
                if ( self::is_file_ignored( $key ) ) {
                    $ignored_files[] = array(
                        'file'   => $key,
                        'reason' => self::get_unknown_ignore_reason( $key ),
                    );
                } else {
                    $unknown_bad[] = $key;
                }
            }
        }
        $root_scan = Wf_Sn_Cs_Utils::scan_root_for_unknown_files( $filehashes );
        $root_scanned = ( isset( $root_scan['root_files_scanned'] ) ? (int) $root_scan['root_files_scanned'] : 0 );
        if ( !empty( $root_scan['unknown'] ) && is_array( $root_scan['unknown'] ) ) {
            foreach ( $root_scan['unknown'] as $root_file ) {
                if ( self::is_file_ignored( $root_file ) ) {
                    $ignored_files[] = array(
                        'file'   => $root_file,
                        'reason' => self::get_unknown_ignore_reason( $root_file ),
                    );
                } else {
                    $unknown_bad[] = $root_file;
                }
            }
        }
        return array(
            'unknown_bad'        => $unknown_bad,
            'ignored_files'      => $ignored_files,
            'root_files_scanned' => $root_scanned,
        );
    }

    /**
     * Retrieve file hashes from the WordPress.org API (delegates to utils).
     *
     * @return array|false List of checksums or false on error.
     */
    public static function get_file_hashes() {
        self::load_utils();
        return Wf_Sn_Cs_Utils::get_file_hashes();
    }

    /**
     * Get list of files/folders to ignore (delegates to utils).
     *
     * @return array Array of file patterns to ignore.
     */
    public static function get_ignored_files() {
        self::load_utils();
        return Wf_Sn_Cs_Utils::get_ignored_files();
    }

    /**
     * Check if a file should be ignored (delegates to utils).
     *
     * @param string $file_path Relative file path.
     * @return bool True if file should be ignored.
     */
    public static function is_file_ignored( $file_path ) {
        self::load_utils();
        return Wf_Sn_Cs_Utils::is_file_ignored( $file_path );
    }

    /**
     * Reason key for an ignored unknown file (user vs filter/pattern).
     *
     * @param string $file_path Relative file path.
     * @return string 'user' or 'unknown'.
     */
    private static function get_unknown_ignore_reason( $file_path ) {
        self::load_utils();
        return ( Wf_Sn_Cs_Utils::is_user_ignored_file( $file_path ) ? 'user' : 'unknown' );
    }

    /**
     * Find a match in an array from a list of needles
     *
     * ref: https://stackoverflow.com/questions/27816105/php-in-array-wildcard-match
     *
     * @param  string $haystack String to search in.
     * @param  array  $needles  Array of needles to search for.
     * @return bool|int False if no match, or the position of the match.
     */
    public static function stripos_array( $haystack, $needles ) {
        foreach ( $needles as $needle ) {
            $res = stripos( $haystack, $needle );
            if ( false !== $res ) {
                return $res;
            }
        }
        return false;
    }

    /**
     * Handles AJAX response - scan files and handles response
     *
     * @param  bool $internal Whether the scan is internal or not.
     * @return void
     */
    public static function do_action_core_run_scan( $internal = false ) {
        // Cron / scheduled runs pass $internal = true (no logged-in admin). AJAX still requires manage_options.
        if ( !$internal ) {
            check_ajax_referer( 'wf_sn_cs' );
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'message' => __( 'You do not have sufficient permissions to access this page.', 'security-ninja' ),
                    'code'    => 'insufficient_permissions',
                ) );
                wp_die();
            }
        }
        $start_time = microtime( true );
        $results = array(
            'missing_ok'         => array(),
            'changed_ok'         => array(),
            'missing_bad'        => array(),
            'changed_bad'        => array(),
            'unknown_bad'        => array(),
            'ok'                 => array(),
            'ignored_files'      => array(),
            'last_run'           => time(),
            'total'              => 0,
            'root_files_scanned' => 0,
            'run_time'           => 0,
        );
        $ver = get_bloginfo( 'version' );
        $missing_ok = array(
            'readme.html',
            'license.txt',
            'wp-config-sample.php',
            'wp-admin/install.php',
            'wp-admin/upgrade.php',
            'wp-config.php',
            'plugins/hello.php',
            'licens.html',
            '/languages/plugins/akismet-'
        );
        $changed_ok = array(
            'wp-config.php',
            'wp-config-sample.php',
            'readme.html',
            'license.txt',
            'wp-includes/version.php'
        );
        $filehashes = self::get_file_hashes();
        if ( $filehashes ) {
            $unknown_collect = self::collect_unknown_core_files( $filehashes );
            $results['unknown_bad'] = $unknown_collect['unknown_bad'];
            $results['ignored_files'] = array_merge( $results['ignored_files'], $unknown_collect['ignored_files'] );
            $results['root_files_scanned'] = $unknown_collect['root_files_scanned'];
            $results['total'] = count( $filehashes );
            foreach ( $filehashes as $file => $hash ) {
                clearstatcache();
                if ( file_exists( ABSPATH . $file ) ) {
                    if ( md5_file( ABSPATH . $file ) === $hash ) {
                        // File matches; list as ok.
                        $results['ok'][] = $file;
                    } elseif ( in_array( $file, $changed_ok, true ) ) {
                        $results['changed_ok'][] = $file;
                    } elseif ( strpos( $file, 'wp-content/' ) === 0 || strpos( $file, '/languages/themes/' ) !== false ) {
                        $results['ok'][] = $file;
                    } elseif ( self::is_file_ignored( $file ) ) {
                        $results['ignored_files'][] = array(
                            'file'   => $file,
                            'reason' => 'changed',
                        );
                    } else {
                        $results['changed_bad'][] = $file;
                    }
                } elseif ( in_array( $file, $missing_ok, true ) || strpos( $file, 'wp-content/themes/' ) === 0 || strpos( $file, 'wp-content/plugins/' ) === 0 || strpos( $file, '/languages/themes/' ) !== false ) {
                    $results['missing_ok'][] = $file;
                } elseif ( self::is_file_ignored( $file ) ) {
                    $results['ignored_files'][] = array(
                        'file'   => $file,
                        'reason' => 'missing',
                    );
                } else {
                    $results['missing_bad'][] = $file;
                }
            }
            do_action( 'security_ninja_core_scanner_done_scanning', $results, microtime( true ) - $start_time );
            $results['run_time'] = number_format( microtime( true ) - $start_time, 2 );
            unset($results['missing_ok'], $results['changed_ok'], $results['ok']);
            self::enrich_results_with_findings( $results );
            update_option( 'wf_sn_cs_results', $results, false );
            if ( $internal ) {
                return;
            }
            wp_send_json_success( self::build_ajax_payload( $results ) );
        } else {
            $ver = get_bloginfo( 'version' );
            $locale = get_locale();
            $error_message = sprintf( 
                /* translators: 1: WordPress version, 2: locale code */
                __( 'Error - hashes not found. Version: %1$s, Locale: %2$s', 'security-ninja' ),
                esc_html( $ver ),
                esc_html( $locale )
             );
            wp_send_json_error( array(
                'message' => $error_message,
                'code'    => 'hashes_not_found',
                'data'    => array(
                    'wp_version' => $ver,
                    'locale'     => $locale,
                ),
            ) );
        }
    }

    /**
     * Perform the actual scanning of core files
     * This method checks for modified, missing, and unknown files in the WordPress core.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, July 23rd, 2025.
     * @access  public static
     * @param   boolean $returnresults  Whether to return the results or update the option.
     * @return  void
     */
    public static function scan_files( $returnresults = false ) {
        $local_time = current_datetime();
        $current_time = $local_time->getTimestamp() + $local_time->getOffset();
        // No nonce check, can be run via scheduled scanner also
        $results['missing_ok'] = array();
        $results['changed_ok'] = array();
        $results['missing_bad'] = array();
        $results['changed_bad'] = array();
        $results['unknown_bad'] = array();
        $results['ok'] = array();
        $results['ignored_files'] = array();
        $results['last_run'] = $current_time;
        $results['total'] = 0;
        $results['run_time'] = 0;
        $start_time = microtime( true );
        $i = 0;
        $ver = get_bloginfo( 'version' );
        // Files ok to be missing
        $missing_ok = array(
            'readme.html',
            'license.txt',
            'wp-config-sample.php',
            'wp-admin/install.php',
            'wp-admin/upgrade.php',
            'wp-config.php',
            'plugins/hello.php',
            'licens.html',
            '/languages/plugins/akismet-'
        );
        // Files ok to be modified
        $changed_ok = array(
            'index.php',
            'wp-config.php',
            'wp-config-sample.php',
            'readme.html',
            'license.txt',
            'wp-includes/version.php'
        );
        $filehashes = self::get_file_hashes();
        if ( $filehashes ) {
            // ** Checking for unknown files
            $unknown_collect = self::collect_unknown_core_files( $filehashes );
            $results['unknown_bad'] = $unknown_collect['unknown_bad'];
            $results['ignored_files'] = array_merge( $results['ignored_files'], $unknown_collect['ignored_files'] );
            $results['root_files_scanned'] = $unknown_collect['root_files_scanned'];
            // Checking if core has been modified
            $results['total'] = count( $filehashes );
            foreach ( $filehashes as $file => $hash ) {
                clearstatcache();
                if ( file_exists( ABSPATH . $file ) ) {
                    if ( md5_file( ABSPATH . $file ) === $hash ) {
                        // File matches; no action needed. Listed in $results by default.
                        $results['ok'][] = $file;
                    } elseif ( in_array( $file, $changed_ok, true ) ) {
                        $results['changed_ok'][] = $file;
                    } elseif ( strpos( $file, 'wp-content/' ) === 0 || strpos( $file, '/languages/themes/' ) !== false ) {
                        // Treat as non-critical for the core scan
                        $results['ok'][] = $file;
                    } elseif ( self::is_file_ignored( $file ) ) {
                        $results['ignored_files'][] = array(
                            'file'   => $file,
                            'reason' => 'changed',
                        );
                    } else {
                        $results['changed_bad'][] = $file;
                    }
                } elseif ( in_array( $file, $missing_ok, true ) || strpos( $file, 'wp-content/themes/' ) === 0 || strpos( $file, 'wp-content/plugins/' ) === 0 || strpos( $file, '/languages/themes/' ) !== false ) {
                    $results['missing_ok'][] = $file;
                } elseif ( self::is_file_ignored( $file ) ) {
                    $results['ignored_files'][] = array(
                        'file'   => $file,
                        'reason' => 'missing',
                    );
                } else {
                    $results['missing_bad'][] = $file;
                }
            }
            do_action( 'security_ninja_core_scanner_done_scanning', $results, microtime( true ) - $start_time );
            $results['run_time'] = number_format( microtime( true ) - $start_time, 2 );
            unset($results['missing_ok'], $results['changed_ok'], $results['ok']);
            self::enrich_results_with_findings( $results );
            if ( $returnresults ) {
                return $results;
            }
            update_option( 'wf_sn_cs_results', $results, false );
            die( '1' );
        } else {
            // no file definitions for this version of WP
            if ( $returnresults ) {
                return null;
            }
            update_option( 'wf_sn_cs_results', null, false );
            die( '0' );
        }
    }

    /**
     * The page displayed in the tabs
     *
     * @return void
     */
    public static function core_page() {
        self::load_utils();
        $cached_results = get_option( 'wf_sn_cs_results', array() );
        $has_cached = Wf_Sn_Cs_Utils::is_valid_results( $cached_results );
        $report_url = ( $has_cached && self::has_any_findings( $cached_results ) ? admin_url( 'admin-post.php?action=sn_core_scan_report&_wpnonce=' . wp_create_nonce( 'sn_core_scan_report' ) ) : '' );
        $issue_count = ( $has_cached ? self::get_issue_count( $cached_results ) : 0 );
        $show_report = $has_cached && self::has_any_findings( $cached_results );
        $is_whitelabel_active = false;
        if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Wl' ) ) {
            $is_whitelabel_active = \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active();
        }
        ?>
		<div class="submit-test-container sncard settings-card">
			<h2><span class="dashicons dashicons-text"></span> <?php 
        echo esc_html__( 'Scan Core WordPress Files', 'security-ninja' );
        ?></h2>
			<p><?php 
        esc_html_e( 'Verifies wp-admin, wp-includes, the site root, and hidden files in core folders against official WordPress checksums. Scans run automatically every 24 hours, and you can start a scan anytime with the button below.', 'security-ninja' );
        ?></p>

			<div class="sn-cs-primary-actions">
				<input type="button" value="<?php 
        echo esc_attr__( 'Scan Core Files', 'security-ninja' );
        ?>" id="sn-run-core-scan" class="button button-primary button-large button-hero sn-cs-run-scan" data-issue-count="<?php 
        echo esc_attr( (string) $issue_count );
        ?>" />
				<span class="spinner sn-cs-scan-spinner"></span>
			</div>

			<?php 
        if ( !$has_cached ) {
            ?>
				<div id="sn-cs-scan-meta-static">
					<?php 
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built via internal helper.
            echo self::build_scan_context_meta_html();
            ?>
				</div>
			<?php 
        }
        ?>

			<div id="wf-sn-core-scanner-response" <?php 
        echo ( $has_cached ? 'data-sn-cs-loaded="1"' : '' );
        ?>>
				<?php 
        if ( $has_cached ) {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built via internal helpers.
            echo self::build_results_output( $cached_results );
        } else {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built via internal helpers.
            echo self::build_empty_state();
        }
        ?>
			</div>

			<div id="wf-sn-core-scan-details" class="sn-cs-meta-row">
				<span id="sn-cs-report-link-wrap" class="<?php 
        echo ( $show_report ? 'is-visible' : 'is-hidden' );
        ?>">
					<a id="sn-cs-report-link" href="<?php 
        echo ( $show_report ? esc_url( $report_url ) : '#' );
        ?>" class="button-link" target="_blank" rel="noopener noreferrer" <?php 
        echo ( $show_report ? '' : 'aria-disabled="true"' );
        ?>><?php 
        esc_html_e( 'Print report', 'security-ninja' );
        ?></a>
				</span>
			</div>

			<?php 
        if ( !$is_whitelabel_active ) {
            ?>
				<?php 
            $doc_link = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'core_scanner_ignore_notice', '/docs/core-scanner/how-to-ignore-files/' );
            ?>
				<p class="description">
					<?php 
            printf( 
                /* translators: %s: link to documentation (e.g. "Learn how") */
                esc_html__( 'You can ignore specific files from Core Scanner results. %s', 'security-ninja' ),
                '<a href="' . esc_url( $doc_link ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Learn how', 'security-ninja' ) . '</a>'
             );
            ?>
				</p>
			<?php 
        }
        ?>
		</div>
		<?php 
    }

    /**
     * Restore a file - AJAX
     *
     * @since   v0.0.1
     * @version v1.0.1  Friday, March 15th, 2024.
     * @access  public static
     * @return  void
     */
    public static function restore_file() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'You do not have sufficient permissions to access this page.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['filename'] ) || empty( $_POST['filename'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'No filename provided.', 'security-ninja' ),
            ) );
        }
        $file = sanitize_text_field( wp_unslash( $_POST['filename'] ) );
        // Validate that the file is within WordPress core directories
        if ( !self::is_core_file( $file ) ) {
            wp_send_json_error( array(
                'message' => __( 'Access denied: File is not within WordPress core directories.', 'security-ninja' ),
            ) );
        }
        // Validate the secure token if provided
        if ( isset( $_POST['hash'] ) && isset( $_POST['nonce'] ) && !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $file,
            wp_unslash( $_POST['hash'] ),
            wp_unslash( $_POST['nonce'] ),
            'restore_file'
        ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid file access token.', 'security-ninja' ),
            ) );
        }
        $file = str_replace( ABSPATH, '', $file );
        $url = wp_nonce_url( 'options.php?page=wf-sn', 'wf-sn-cs' );
        $creds = request_filesystem_credentials(
            $url,
            '',
            false,
            false,
            null
        );
        if ( !WP_Filesystem( $creds ) ) {
            wp_send_json_error( array(
                'message' => __( 'Unable to access the filesystem.', 'security-ninja' ),
            ) );
        }
        self::load_utils();
        $org_body = Wf_Sn_Cs_Utils::get_original_core_file_content( $file );
        if ( is_wp_error( $org_body ) ) {
            $error_message = $org_body->get_error_message();
            wp_send_json_error( array(
                'message' => $error_message,
            ) );
        }
        global $wp_filesystem;
        // Initialize the WordPress filesystem, if not already.
        if ( empty( $wp_filesystem ) ) {
            include_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        if ( !$wp_filesystem->put_contents( trailingslashit( ABSPATH ) . $file, $org_body, FS_CHMOD_FILE ) ) {
            wp_send_json_error( array(
                'message' => __( 'Error writing file.', 'security-ninja' ),
            ) );
        }
        $results = self::remove_paths_from_cached_results( $file );
        wp_send_json_success( array_merge( array(
            'message' => __( 'File restored successfully.', 'security-ninja' ),
        ), self::build_row_action_payload( $results, $file ) ) );
    }

    /**
     * Delete a file - AJAX call
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, December 18th, 2020.
     * @version v1.0.1  Monday, February 6th, 2023.
     * @version v1.0.2  Friday, November 17th, 2023.
     * @access  public static
     * @return  void
     */
    public static function delete_file() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        // Sanitize the filename
        $file = ( isset( $_POST['filename'] ) ? sanitize_text_field( wp_unslash( $_POST['filename'] ) ) : '' );
        // Validate the filename
        if ( empty( $file ) || !is_string( $file ) || strpos( $file, '..' ) !== false ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid filename.', 'security-ninja' ),
            ) );
        }
        // Validate that the file is within WordPress core directories
        if ( !self::is_core_file( $file ) ) {
            wp_send_json_error( array(
                'message' => __( 'Access denied: File is not within WordPress core directories.', 'security-ninja' ),
            ) );
        }
        // Validate the secure token if provided
        if ( isset( $_POST['hash'] ) && isset( $_POST['nonce'] ) && !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $file,
            wp_unslash( $_POST['hash'] ),
            wp_unslash( $_POST['nonce'] ),
            'delete_file'
        ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid file access token.', 'security-ninja' ),
            ) );
        }
        $file = str_replace( ABSPATH, '', $file );
        $url = wp_nonce_url( 'options.php?page=wf-sn', 'wf-sn-cs' );
        $creds = request_filesystem_credentials(
            $url,
            '',
            false,
            false,
            null
        );
        if ( !WP_Filesystem( $creds ) ) {
            wp_send_json_error( array(
                'message' => sprintf( __( 'Cannot delete %s', 'security-ninja' ), $file ),
            ) );
        }
        global $wp_filesystem;
        if ( !$wp_filesystem->delete( trailingslashit( ABSPATH ) . $file, false ) ) {
            wp_send_json_error( array(
                'message' => sprintf( __( 'Unknown error deleting %s', 'security-ninja' ), esc_html( $file ) ),
            ) );
        }
        $results = self::remove_paths_from_cached_results( $file );
        wp_send_json_success( self::build_row_action_payload( $results, $file ) );
    }

    /**
     * Ignore an unknown core file — AJAX handler.
     *
     * @return void
     */
    public static function ignore_unknown_file() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        self::load_utils();
        $file_short = ( isset( $_POST['file_short'] ) ? sanitize_text_field( wp_unslash( $_POST['file_short'] ) ) : '' );
        $file_short = Wf_Sn_Cs_Utils::normalize_relative_path( $file_short );
        if ( false === $file_short ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid filename.', 'security-ninja' ),
            ) );
        }
        $abs_path = ABSPATH . $file_short;
        if ( !isset( $_POST['hash'], $_POST['nonce'] ) || !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $abs_path,
            wp_unslash( $_POST['hash'] ),
            wp_unslash( $_POST['nonce'] ),
            'ignore_file'
        ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid file access token.', 'security-ninja' ),
            ) );
        }
        if ( !self::is_core_file( $abs_path ) ) {
            wp_send_json_error( array(
                'message' => __( 'Access denied: File is not within WordPress core directories.', 'security-ninja' ),
            ) );
        }
        if ( !self::is_path_in_cached_unknown_bad( $file_short ) ) {
            wp_send_json_error( array(
                'message' => __( 'This file is not in the current unknown files list.', 'security-ninja' ),
            ) );
        }
        $added = Wf_Sn_Cs_Utils::add_user_ignored_file( $file_short );
        if ( is_wp_error( $added ) ) {
            wp_send_json_error( array(
                'message' => $added->get_error_message(),
            ) );
        }
        $results = self::patch_cached_results_after_ignore( $file_short );
        wp_send_json_success( array_merge( array(
            'message' => __( 'File ignored successfully.', 'security-ninja' ),
        ), self::build_row_action_payload( $results, $file_short, true ) ) );
    }

    /**
     * Stop ignoring a user-ignored core file — AJAX handler.
     *
     * @return void
     */
    public static function unignore_unknown_file() {
        check_ajax_referer( 'wf_sn_cs' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        self::load_utils();
        $file_short = ( isset( $_POST['file_short'] ) ? sanitize_text_field( wp_unslash( $_POST['file_short'] ) ) : '' );
        $file_short = Wf_Sn_Cs_Utils::normalize_relative_path( $file_short );
        if ( false === $file_short ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid filename.', 'security-ninja' ),
            ) );
        }
        $abs_path = ABSPATH . $file_short;
        if ( !isset( $_POST['hash'], $_POST['nonce'] ) || !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $abs_path,
            wp_unslash( $_POST['hash'] ),
            wp_unslash( $_POST['nonce'] ),
            'revert_ignore_file'
        ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid file access token.', 'security-ninja' ),
            ) );
        }
        if ( !Wf_Sn_Cs_Utils::is_user_ignored_file( $file_short ) ) {
            wp_send_json_error( array(
                'message' => __( 'File is not in your ignore list.', 'security-ninja' ),
            ) );
        }
        $removed = Wf_Sn_Cs_Utils::remove_user_ignored_file( $file_short );
        if ( is_wp_error( $removed ) ) {
            wp_send_json_error( array(
                'message' => $removed->get_error_message(),
            ) );
        }
        $results = self::patch_cached_results_after_unignore( $file_short );
        wp_send_json_success( array_merge( array(
            'message' => __( 'File is no longer ignored.', 'security-ninja' ),
        ), self::build_row_action_payload( $results, array(), true ) ) );
    }

    /**
     * Helper function for listing files with optional action buttons.
     *
     * @since   0.0.1
     * @version 1.0.1  Friday, April 30th, 2024.
     *
     * @param string|array $files   File or array of files to list.
     * @param bool         $view    Whether to show the view button. Default false.
     * @param bool         $restore Whether to show the restore button. Default false.
     * @param bool         $delete  Whether to show the delete button. Default false.
     *
     * @return string HTML output of the file list.
     */
    public static function list_files(
        $files,
        $view = false,
        $restore = false,
        $delete = false
    ) {
        if ( !is_array( $files ) ) {
            $files = array($files);
        }
        $out = '<ul class="sn-file-list">';
        foreach ( $files as $file ) {
            $out .= '<li>';
            $out .= '<span class="sn-file">' . esc_html( $file ) . '</span>';
            $out .= '<span class="sn-action-buttons">';
            if ( $view ) {
                $file_path = ABSPATH . $file;
                if ( \WPSecurityNinja\Plugin\FileViewer::can_view_file( $file_path ) ) {
                    $file_view_url = \WPSecurityNinja\Plugin\FileViewer::generate_file_view_url( $file_path );
                    $out .= ' <a href="' . esc_url( $file_view_url ) . '" class="button button-small" target="_blank">' . esc_html__( 'View File', 'security-ninja' ) . '</a>';
                }
                if ( $restore ) {
                    $diff_url = \WPSecurityNinja\Plugin\FileViewer::generate_diff_view_url( $file_path );
                    $out .= ' <a href="' . esc_url( $diff_url ) . '" class="button button-small" target="_blank">' . esc_html__( 'View differences', 'security-ninja' ) . '</a>';
                }
            }
            if ( $restore ) {
                $file_path = ABSPATH . $file;
                $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'restore_file' );
                $out .= ' <a data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( $file_path ) . '" href="#restore-dialog" class="sn-restore-source button button-small">' . esc_html__( 'Restore', 'security-ninja' ) . '</a>';
            }
            if ( $delete ) {
                $file_path = ABSPATH . $file;
                $token = \WPSecurityNinja\Plugin\Wf_Sn_Crypto::generate_secure_file_token( $file_path, 'delete_file' );
                $out .= ' <a data-hash="' . esc_attr( $token['hash'] ) . '" data-nonce="' . esc_attr( $token['nonce'] ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( $file_path ) . '" href="#delete-dialog" class="sn-delete-source button button-small">' . esc_html__( 'Delete', 'security-ninja' ) . '</a>';
            }
            $out .= '</span>';
            $out .= '</li>';
        }
        $out .= '</ul>';
        return $out;
    }

    /**
     * Clean-up when deactivated
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, December 18th, 2020.
     * @access  public static
     * @return  void
     */
    public static function deactivate() {
        $centraloptions = Wf_Sn::get_options();
        if ( !isset( $centraloptions['remove_settings_deactivate'] ) ) {
            return;
        }
        if ( $centraloptions['remove_settings_deactivate'] ) {
            wp_clear_scheduled_hook( 'secnin_run_core_scanner' );
            delete_option( 'wf_sn_cs_results' );
        }
    }

}

add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\wf_sn_cs', 'init') );
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\wf_sn_cs', 'deactivate') );