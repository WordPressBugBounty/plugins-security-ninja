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
            $files_checked = sprintf( 
                /* translators: 1: number of files, 2: seconds (run time) */
                esc_html__( '%1$s files were checked in %2$s sec', 'security-ninja' ),
                number_format( $results['total'] ),
                number_format( (float) $run_time, 2 )
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
     * Build the full HTML output from a data-only results array.
     * Every call generates fresh tokens so links never expire.
     *
     * @param array $results Data-only results with changed_bad, missing_bad, unknown_bad, ignored_files.
     * @return string HTML for the Core Scanner results area.
     */
    private static function build_results_output( $results ) {
        $out = '';
        $allisgood = true;
        if ( !empty( $results['unknown_bad'] ) ) {
            $allisgood = false;
            $out .= '<div class="sn-cs-changed-bad">';
            $out .= '<div class="core-title"><h4>' . __( 'The following files are unknown and should not be in your core folders', 'security-ninja' ) . '</h4></div>';
            $out .= '<div class="changedcont"><p class="description">' . __( 'These are files not included with WordPress default installation and should not be in your core WordPress folders.', 'security-ninja' ) . '</p>';
            $out .= '<p class="description">' . __( 'These files can be leftovers from older WordPress installations, and are no longer needed.', 'security-ninja' ) . '</p>';
            $out .= self::list_files(
                $results['unknown_bad'],
                true,
                false,
                true
            );
            $out .= '<div class="deletealldialogtrigger"><button href="#delete-all-dialog" class="sn-delete-all-files alignright button button-secondary button-small alignright">' . __( 'Delete all', 'security-ninja' ) . '</button></div>';
            $out .= '</div></div>';
        }
        if ( !empty( $results['changed_bad'] ) ) {
            $allisgood = false;
            $out .= '<div class="sn-cs-changed-bad"><div class="core-title">';
            $out .= '<h4>' . __( 'The following WordPress core files have been modified', 'security-ninja' ) . '</h4>';
            $out .= '</div>';
            $out .= '<div class="">';
            $out .= '<p>' . __( 'If you did not modify the following files yourself, this could indicate an infection on your website.', 'security-ninja' ) . '</p>';
            $out .= self::list_files( $results['changed_bad'], true, true );
            $out .= '</div></div>';
        }
        if ( !empty( $results['missing_bad'] ) ) {
            $allisgood = false;
            $out .= '<div class="sn-cs-missing-bad"><div class="core-title">';
            $out .= '<h4>' . __( 'Following core files are missing.', 'security-ninja' ) . '</h4>';
            $out .= '</div>';
            $out .= '<div class="changedcont">';
            $out .= '<p class="description">' . esc_html__( 'Missing core files might indicate a bad auto-update or they simply were not copied on the server when the site was setup.', 'security-ninja' ) . '</p>';
            $out .= '<p class="description">' . esc_html__( 'If there is no legitimate reason for the files to be missing use the restore action to create them.', 'security-ninja' ) . '</p>';
            $out .= self::list_files( $results['missing_bad'], false, true );
            $out .= '</div></div>';
        }
        if ( $allisgood ) {
            $out .= '<div class="sncard noerrorsfound">' . esc_html__( 'No problems found', 'security-ninja' ) . '</div>';
        } else {
            $out = '<div id="sn-cs-results" class="sncard snerror">' . $out;
        }
        $out .= '</div><!-- #sn-cs-results -->';
        if ( !empty( $results['ignored_files'] ) ) {
            $out .= '<div class="sn-cs-ignored-files sncard">';
            $out .= '<div class="core-title">';
            $out .= '<h4>' . esc_html__( 'Ignored Files', 'security-ninja' ) . '</h4>';
            $out .= '</div>';
            $out .= '<div class="changedcont">';
            $out .= '<p class="description">' . esc_html__( 'The following files are being ignored based on your filter settings. Add filters in your theme\'s functions.php file using the securityninja_core_scanner_ignore_files filter.', 'security-ninja' ) . '</p>';
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
                    $out .= self::list_files(
                        $files,
                        false,
                        false,
                        false
                    );
                }
            }
            $out .= '<p>' . esc_html__( 'How to add ignore filters:', 'security-ninja' ) . '</p>';
            $out .= '<div class="sn-cs-filter-example" style="margin-top: 20px; padding: 15px; background: #f5f5f5; border-left: 4px solid #2271b1;">';
            $out .= '<pre>// Add to your theme\'s functions.php file:
add_filter(\'securityninja_core_scanner_ignore_files\', function($ignored) {
    $ignored[] = \'wp-includes/SimplePie/src/Core.php\';
    $ignored[] = \'*/error_log\'; // Ignore all error_log files
    $ignored[] = \'wp-includes/SimplePie/*\'; // Ignore entire directory
    return $ignored;
});</pre>';
            $out .= '</div>';
            $out .= '</div></div>';
        }
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
        // DELETE ALL UNKNOWN FILES
        $results = get_option( 'wf_sn_cs_results' );
        if ( isset( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            $deleted_files = 0;
            $failed_deletions = array();
            foreach ( $results['unknown_bad'] as $ub ) {
                $filepath = ABSPATH . $ub;
                // Use WP filesystem method to delete files.
                if ( $wp_filesystem->exists( $filepath ) ) {
                    if ( $wp_filesystem->delete( $filepath ) ) {
                        ++$deleted_files;
                    } else {
                        $failed_deletions[] = $filepath;
                    }
                }
            }
            if ( $deleted_files > 0 ) {
                /* translators: %d: number of deleted files */
                $message = sprintf( esc_html__( 'Deleted %d unknown files in Core WordPress folders', 'security-ninja' ), $deleted_files );
                $newresults = self::scan_files( true );
                if ( $newresults ) {
                    update_option( 'wf_sn_cs_results', $newresults, false );
                }
                wp_send_json_success( array(
                    'deleted' => $deleted_files,
                    'failed'  => $failed_deletions,
                ) );
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
            wp_enqueue_style( 'wp-jquery-ui-dialog' );
            wp_enqueue_script( 'jquery-ui-dialog' );
            wp_register_script(
                'sn-core-js',
                $plugin_url . 'js/wf-sn-core.js',
                array('jquery'),
                \WPSecurityNinja\Plugin\Utils::get_plugin_version(),
                true
            );
            $js_vars = array(
                'nonce'            => wp_create_nonce( 'wf_sn_cs' ),
                'run_scan_nonce'   => wp_create_nonce( 'wf-cs-run-scan-nonce' ),
                'delete_all_nonce' => wp_create_nonce( 'wf-cs-delete-all-unknown-nonce' ),
                'strings'          => array(
                    'error_occurred'     => __( 'An error occurred', 'security-ninja' ),
                    'undocumented_error' => __( 'An undocumented error occurred. The page will reload.', 'security-ninja' ),
                    'file_source'        => __( 'File source', 'security-ninja' ),
                    'confirm_restore'    => __( 'Are you sure you want to restore this file?', 'security-ninja' ),
                    'confirm_delete'     => __( 'Are you sure you want to delete this file?', 'security-ninja' ),
                    'confirm_delete_all' => __( 'Are you sure you want to delete all unknown files?', 'security-ninja' ),
                    'ajax_error'         => __( 'An error occurred during the AJAX request.', 'security-ninja' ),
                    'please_wait'        => __( 'Please wait.', 'security-ninja' ),
                    'no_scan_yet'        => __( 'No scan made yet. Click "Scan Core Files" to run a scan.', 'security-ninja' ),
                    'loading'            => __( 'Loading...', 'security-ninja' ),
                    'report_disabled'    => __( 'Available when issues are detected.', 'security-ninja' ),
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
        $hash = ( isset( $_POST['hash'] ) ? sanitize_text_field( wp_unslash( $_POST['hash'] ) ) : '' );
        $nonce = ( isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '' );
        if ( '' === $hash || '' === $nonce || !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $filename,
            $hash,
            $nonce,
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
        $meta = self::build_meta_strings( $results );
        $has_issues = !empty( $results['changed_bad'] ) || !empty( $results['missing_bad'] ) || !empty( $results['unknown_bad'] );
        $report_url = ( $has_issues ? admin_url( 'admin-post.php?action=sn_core_scan_report&_wpnonce=' . wp_create_nonce( 'sn_core_scan_report' ) ) : '' );
        $next_scan_ts = wp_next_scheduled( 'secnin_run_core_scanner' );
        if ( $next_scan_ts ) {
            $next_scan = sprintf( 
                /* translators: 1: formatted date/time of next scan, 2: human time until next scan */
                esc_html__( '%1$s (%2$s from now)', 'security-ninja' ),
                date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan_ts ),
                human_time_diff( time(), $next_scan_ts )
             );
        } else {
            $next_scan = __( 'No core scan currently scheduled.', 'security-ninja' );
        }
        wp_send_json_success( array(
            'out'           => self::build_results_output( $results ),
            'last_scan'     => $meta['last_scan'],
            'files_checked' => $meta['files_checked'],
            'wp_version'    => $meta['wp_version'],
            'next_scan'     => $next_scan,
            'has_issues'    => $has_issues,
            'report_url'    => $report_url,
        ) );
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
            esc_html_e( 'Unknown files in core folders', 'security-ninja' );
            ?></h2>
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
        $total = 0;
        // Count missing_bad files (excluding ignored ones)
        if ( isset( $results['missing_bad'] ) && is_array( $results['missing_bad'] ) ) {
            foreach ( $results['missing_bad'] as $file ) {
                if ( !self::is_file_ignored( $file ) ) {
                    ++$total;
                }
            }
        }
        // Count changed_bad files (excluding ignored ones)
        if ( isset( $results['changed_bad'] ) && is_array( $results['changed_bad'] ) ) {
            foreach ( $results['changed_bad'] as $file ) {
                if ( !self::is_file_ignored( $file ) ) {
                    ++$total;
                }
            }
        }
        // Count unknown_bad files (excluding ignored ones)
        if ( isset( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ) {
            foreach ( $results['unknown_bad'] as $file ) {
                if ( !self::is_file_ignored( $file ) ) {
                    ++$total;
                }
            }
        }
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
     * @param  string     $relative_path Relative path.
     * @return array|false Array of files or false if the path is not a directory.
     */
    public static function scan_folder(
        $path,
        $extensions = null,
        $depth = 3,
        $relative_path = ''
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
            if ( '.' === $result[0] ) {
                continue;
            }
            if ( is_dir( $path . '/' . $result ) ) {
                if ( $depth > 0 && 'CVS' !== $result ) {
                    $found = self::scan_folder(
                        $path . '/' . $result,
                        $extensions,
                        $depth - 1,
                        $relative_path . $result
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
        if ( !$internal ) {
            check_ajax_referer( 'wf_sn_cs' );
        }
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'You do not have sufficient permissions to access this page.', 'security-ninja' ),
                'code'    => 'insufficient_permissions',
            ) );
            wp_die();
        }
        $start_time = microtime( true );
        $results = array(
            'missing_ok'    => array(),
            'changed_ok'    => array(),
            'missing_bad'   => array(),
            'changed_bad'   => array(),
            'unknown_bad'   => array(),
            'ok'            => array(),
            'ignored_files' => array(),
            'last_run'      => time(),
            'total'         => 0,
            'run_time'      => 0,
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
            $files = self::scan_folder(
                ABSPATH . WPINC,
                null,
                9,
                WPINC
            );
            $all_files = $files;
            $files = self::scan_folder(
                ABSPATH . 'wp-admin',
                null,
                9,
                'wp-admin'
            );
            $all_files = array_merge( $all_files, $files );
            foreach ( $all_files as $key => $af ) {
                if ( !isset( $filehashes[$key] ) ) {
                    if ( self::is_file_ignored( $key ) ) {
                        $results['ignored_files'][] = array(
                            'file'   => $key,
                            'reason' => 'unknown',
                        );
                    } else {
                        $results['unknown_bad'][] = $key;
                    }
                }
            }
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
            update_option( 'wf_sn_cs_results', $results, false );
            $meta = self::build_meta_strings( $results );
            $has_issues = !empty( $results['changed_bad'] ) || !empty( $results['missing_bad'] ) || !empty( $results['unknown_bad'] );
            $report_url = ( $has_issues ? admin_url( 'admin-post.php?action=sn_core_scan_report&_wpnonce=' . wp_create_nonce( 'sn_core_scan_report' ) ) : '' );
            $next_scan_ts = wp_next_scheduled( 'secnin_run_core_scanner' );
            $next_scan = '';
            if ( $next_scan_ts ) {
                $next_scan = sprintf( 
                    /* translators: 1: formatted date/time of next scan, 2: human time until next scan */
                    esc_html__( '%1$s (%2$s from now)', 'security-ninja' ),
                    date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan_ts ),
                    human_time_diff( time(), $next_scan_ts )
                 );
            } else {
                $next_scan = __( 'No core scan currently scheduled.', 'security-ninja' );
            }
            wp_send_json_success( array(
                'out'           => self::build_results_output( $results ),
                'last_scan'     => $meta['last_scan'],
                'files_checked' => $meta['files_checked'],
                'wp_version'    => $meta['wp_version'],
                'next_scan'     => $next_scan,
                'has_issues'    => $has_issues,
                'report_url'    => $report_url,
            ) );
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
            $files = self::scan_folder(
                ABSPATH . WPINC,
                null,
                9,
                WPINC
            );
            $all_files = $files;
            $files = self::scan_folder(
                ABSPATH . 'wp-admin',
                null,
                9,
                'wp-admin'
            );
            $all_files = array_merge( $all_files, $files );
            foreach ( $all_files as $key => $af ) {
                if ( !isset( $filehashes[$key] ) ) {
                    // Check if file should be ignored
                    if ( self::is_file_ignored( $key ) ) {
                        $results['ignored_files'][] = array(
                            'file'   => $key,
                            'reason' => 'unknown',
                        );
                    } else {
                        $results['unknown_bad'][] = $key;
                    }
                }
            }
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
        ?>
		<div class="submit-test-container sncard settings-card">
			<h2><span class="dashicons dashicons-text"></span> <?php 
        echo esc_html__( 'Scan Core WordPress Files', 'security-ninja' );
        ?></h2>

			<p><?php 
        esc_html_e( 'Check for modified files in WordPress itself and detect extra files that should not be there.', 'security-ninja' );
        ?></p>

			<?php 
        // Show notice about ignoring files (only if whitelabel is not active)
        $is_whitelabel_active = false;
        if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Wl' ) ) {
            $is_whitelabel_active = \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active();
        }
        ?>
			<div id="wf-sn-core-scanner-response">
				<!-- <p class="spinner"></p> -->

			</div>


			<div id="wf-sn-core-scan-details">
				<p><?php 
        esc_html_e( 'Last Scan', 'security-ninja' );
        ?>: <span id="last_scan"></span></p>
				<p><?php 
        esc_html_e( 'Files Checked', 'security-ninja' );
        ?>: <span id="files_checked"></span></p>
				<p><?php 
        esc_html_e( 'WordPress Version', 'security-ninja' );
        ?>: <span id="wp_version"></span></p>

				<?php 
        $next_scan = wp_next_scheduled( 'secnin_run_core_scanner' );
        if ( $next_scan ) {
            $time_until_next_scan = human_time_diff( time(), $next_scan );
            echo '<p>' . esc_html__( 'Next Scheduled Scan', 'security-ninja' ) . ': <span id="next_scan">' . sprintf( 
                /* translators: %1$s is the date/time of next scan, %2$s is the time until next scan */
                esc_html__( '%1$s (%2$s from now)', 'security-ninja' ),
                esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan ) ),
                esc_html( $time_until_next_scan )
             ) . '</span></p>';
        } else {
            echo '<p id="next_scan">' . esc_html__( 'No core scan currently scheduled.', 'security-ninja' ) . '</p>';
        }
        if ( !$is_whitelabel_active ) {
            $doc_link = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'core_scanner_ignore_notice', '/docs/core-scanner/how-to-ignore-files/' );
            ?>
					<p>
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
				<p id="sn-cs-report-link-wrap" style="margin-bottom: 1.5em;">
					<a id="sn-cs-report-link" href="#" class="button button-secondary" target="_blank" rel="noopener noreferrer" aria-disabled="true"><?php 
        esc_html_e( 'Print / Download report', 'security-ninja' );
        ?></a>
					<span id="sn-cs-report-notice" class="description" style="margin-left: 8px;"><?php 
        esc_html_e( 'Available when issues are detected.', 'security-ninja' );
        ?></span>
				</p>
			</div>
			<?php 
        echo '<input type="button" value="' . esc_html__( 'Scan Core Files', 'security-ninja' ) . '" id="sn-run-core-scan" class="button snbtn button-secondary button-large" />';
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
        $hash = ( isset( $_POST['hash'] ) ? sanitize_text_field( wp_unslash( $_POST['hash'] ) ) : '' );
        $nonce = ( isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '' );
        if ( '' !== $hash && '' !== $nonce && !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $file,
            $hash,
            $nonce,
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
        self::scan_files();
        wp_send_json_success( array(
            'message' => __( 'File restored successfully.', 'security-ninja' ),
        ) );
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
        $hash = ( isset( $_POST['hash'] ) ? sanitize_text_field( wp_unslash( $_POST['hash'] ) ) : '' );
        $nonce = ( isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] ) ) : '' );
        if ( '' !== $hash && '' !== $nonce && !\WPSecurityNinja\Plugin\Wf_Sn_Crypto::validate_secure_file_token(
            $file,
            $hash,
            $nonce,
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
                'message' => sprintf( 
                    /* translators: %s: File name. */
                    __( 'Cannot delete %s', 'security-ninja' ),
                    $file
                 ),
            ) );
        }
        global $wp_filesystem;
        if ( !$wp_filesystem->delete( trailingslashit( ABSPATH ) . $file, false ) ) {
            wp_send_json_error( array(
                'message' => sprintf( 
                    /* translators: %s: File name. */
                    __( 'Unknown error deleting %s', 'security-ninja' ),
                    esc_html( $file )
                 ),
            ) );
        }
        wp_send_json_success();
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
                $file_view_url = \WPSecurityNinja\Plugin\FileViewer::generate_file_view_url( $file_path );
                $out .= ' <a href="' . esc_url( $file_view_url ) . '" class="button button-small" target="_blank">' . esc_html__( 'View File', 'security-ninja' ) . '</a>';
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