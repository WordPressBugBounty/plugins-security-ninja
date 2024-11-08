<?php

namespace WPSecurityNinja\Plugin;

use FileViewer;
if ( !function_exists( 'add_action' ) ) {
    die( 'Please don\'t open this file directly!' );
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
     * Salt used for hashing purposes.
     *
     * @var string
     */
    private static $salt = 'wf_sn_cs_salt';

    /**
     * Initialize the Core Scanner module
     *
     * @return void
     */
    public static function init() {
        add_action( 'secnin_run_core_scanner', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_secnin_run_core_scanner') );
        add_action( 'init', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'schedule_cron_jobs') );
        if ( current_user_can( 'manage_options' ) ) {
            // add tab to Security Ninja tabs
            add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'sn_tabs') );
            // enqueue scripts
            add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'enqueue_scripts') );
            // register ajax endpoints
            add_action( 'wp_ajax_sn_core_get_file_source', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'get_file_source') );
            add_action( 'wp_ajax_sn_core_delete_file_do', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'delete_file') );
            add_action( 'wp_ajax_sn_core_restore_file_do', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'restore_file') );
            add_action( 'wp_ajax_sn_core_run_scan', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_core_run_scan') );
            add_action( 'wp_ajax_sn_core_delete_all_unknowns', array(__NAMESPACE__ . '\\Wf_Sn_Cs', 'do_action_delete_all_unknowns') );
        }
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
                // translators: %d: Number of deleted files.
                $message = '<p>' . sprintf( esc_html__( 'Deleted %d unknown files in Core WordPress folders', 'security-ninja' ), $deleted_files ) . '</p>';
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
                $plugin_url . 'js/wf-sn-core-min.js',
                array('jquery'),
                wf_sn::get_plugin_version(),
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
                ),
            );
            wp_localize_script( 'sn-core-js', 'wf_sn_cs', $js_vars );
            wp_enqueue_script( 'sn-core-js' );
            wp_enqueue_style(
                'sn-core-css',
                $plugin_url . 'css/wf-sn-core-min.css',
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
        // check the checksum
        if ( md5( self::$salt . stripslashes( $_POST['filename'] ) ) !== $_POST['hash'] ) {
            $error = new \WP_Error('002', __( 'Cheating, eh?', 'security-ninja' ));
            wp_send_json_error( $error );
        }
        $out['ext'] = pathinfo( $_POST['filename'], PATHINFO_EXTENSION );
        $out['source'] = '';
        if ( is_readable( $_POST['filename'] ) ) {
            $content = file_get_contents( $_POST['filename'] );
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
     * Returns the number of problems with files currently detected
     *
     * @return int|false Number of problems or false if no problems
     */
    private static function return_problem_count() {
        $results = get_option( 'wf_sn_cs_results' );
        $total = 0;
        if ( isset( $results['missing_bad'] ) ) {
            $total = $total + count( $results['missing_bad'] );
        }
        if ( isset( $results['changed_bad'] ) ) {
            $total = $total + count( $results['changed_bad'] );
        }
        if ( isset( $results['unknown_bad'] ) ) {
            $total = $total + count( $results['unknown_bad'] );
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
     * Retrieve file hashes from the WordPress.org API
     *
     * This method fetches and caches the checksums for the current WordPress version.
     *
     * @return array|false List of checksums or false on error.
     */
    public static function get_file_hashes() {
        $ver = get_bloginfo( 'version' );
        $locale = get_locale();
        // Making sure we have the necessary functionality loaded.
        if ( !function_exists( 'get_core_checksums' ) ) {
            include_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $cs = get_core_checksums( $ver, ( isset( $locale ) ? $locale : 'en_US' ) );
        if ( empty( $cs['checksums'] ) ) {
            $details = array(
                'ver'    => $ver,
                'locale' => $locale,
            );
            $cs = get_core_checksums( $ver, 'en_US' );
        }
        if ( $cs ) {
            $cleaned = array();
            $themes_url = trailingslashit( content_url( 'themes' ) );
            $plugins_url = trailingslashit( content_url( 'plugins' ) );
            $themes_path = str_replace( site_url(), '', $themes_url );
            $plugins_path = str_replace( site_url(), '', $plugins_url );
            // Remove left trailing slash
            $themes_path = ltrim( $themes_path, '/' );
            $plugins_path = ltrim( $plugins_path, '/' );
            foreach ( $cs as $path => $hash ) {
                if ( strpos( $path, $themes_path ) !== false || strpos( $path, $plugins_path ) !== false || strpos( $path, '/plugins/akismet/' ) !== false || strpos( $path, '/languages/themes/' ) !== false ) {
                } else {
                    $cleaned[$path] = $hash;
                }
            }
            $tmp = array(
                'version'   => $ver,
                'checksums' => $cleaned,
            );
            set_transient( 'wf_sn_hashes_' . $ver . '_' . $locale, $cleaned, MINUTE_IN_SECONDS * 15 );
            // cached for 5 mins
            return $cleaned;
        }
        return false;
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
        }
        $start_time = microtime( true );
        $results = get_option( 'wf_sn_cs_results', array() );
        $doupdate = $internal || isset( $_POST['doupdate'] ) && $_POST['doupdate'];
        if ( !$doupdate && !empty( $results ) ) {
            $results['run_time'] = number_format( microtime( true ) - $start_time, 2 );
            wp_send_json_success( $results );
        }
        $results['missing_ok'] = array();
        $results['changed_ok'] = array();
        $results['missing_bad'] = array();
        $results['changed_bad'] = array();
        $results['unknown_bad'] = array();
        $results['ok'] = array();
        $results['last_run'] = current_time( 'timestamp' );
        $results['total'] = 0;
        $results['run_time'] = 0;
        $i = 0;
        $ver = get_bloginfo( 'version' );
        // Files ok to be missing
        $missing_ok = array(
            'index.php',
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
                    $results['unknown_bad'][] = $key;
                }
            }
            // Checking if core has been modified
            $results['total'] = count( $filehashes );
            foreach ( $filehashes as $file => $hash ) {
                clearstatcache();
                if ( file_exists( ABSPATH . $file ) ) {
                    if ( md5_file( ABSPATH . $file ) === $hash ) {
                    } elseif ( in_array( $file, $changed_ok, true ) ) {
                        $results['changed_ok'][] = $file;
                    } else {
                        $results['changed_bad'][] = $file;
                    }
                } elseif ( in_array( $file, $missing_ok, true ) ) {
                    $results['missing_ok'][] = $file;
                } else {
                    $results['missing_bad'][] = $file;
                }
            }
            // foreach file
            do_action( 'security_ninja_core_scanner_done_scanning', $results, microtime( true ) - $start_time );
            $results['out'] = '';
            if ( isset( $results['last_run'] ) && $results['last_run'] ) {
                $allisgood = true;
                $results['out'] .= '<div id="sn-cs-results">';
                if ( $results['unknown_bad'] ) {
                    $allisgood = false;
                    $results['out'] .= '<div class="sn-cs-changed-bad">';
                    $results['out'] .= '<div class="core-title"><h4>' . __( 'The following files are unknown and should not be in your core folders', 'security-ninja' ) . '</h4></div>';
                    $results['out'] .= '<div class="changedcont"><p class="description">' . __( 'These are files not included with WordPress default installation and should not be in your core WordPress folders.', 'security-ninja' ) . '</p>';
                    $results['out'] .= '<p class="description">' . __( 'These files can be leftovers from older WordPress installations, and are no longer needed.', 'security-ninja' ) . '</p>';
                    $results['out'] .= self::list_files(
                        $results['unknown_bad'],
                        true,
                        false,
                        true
                    );
                    $results['out'] .= ' <button href="#delete-all-dialog" class="sn-delete-all-files button button-secondary button-small alignright">' . __( 'Delete all', 'security-ninja' ) . '</button>';
                    $results['out'] .= '</div></div>';
                }
                if ( $results['changed_bad'] ) {
                    $allisgood = false;
                    $results['out'] .= '<div class="sn-cs-changed-bad"><div class="core-title">';
                    $results['out'] .= '<h4>' . __( 'The following WordPress core files have been modified', 'security-ninja' ) . '</h4>';
                    $results['out'] .= '</div>';
                    $results['out'] .= '<div class="changedcont">';
                    $results['out'] .= '<p>' . __( 'If you did not modify the following files yourself, this could indicate an infection on your website.', 'security-ninja' ) . '</p>';
                    $results['out'] .= self::list_files( $results['changed_bad'], true, true );
                    $results['out'] .= '</div></div>';
                }
                if ( $results['missing_bad'] ) {
                    $allisgood = false;
                    $results['out'] .= '<div class="sn-cs-missing-bad"><div class="core-title">';
                    $results['out'] .= '<h4>' . __( 'Following core files are missing.', 'security-ninja' ) . '</h4>';
                    $results['out'] .= '</div>';
                    $results['out'] .= '<div class="changedcont">';
                    $results['out'] .= '<p class="description">' . esc_html__( 'Missing core files might indicate a bad auto-update or they simply were not copied on the server when the site was setup.', 'security-ninja' ) . '</p>';
                    $results['out'] .= '<p class="description">' . esc_html__( 'If there is no legitimate reason for the files to be missing use the restore action to create them.', 'security-ninja' ) . '</p>';
                    $results['out'] .= self::list_files( $results['missing_bad'], false, true );
                    $results['out'] .= '</div></div>';
                }
                if ( $allisgood ) {
                    $results['out'] .= '<p>' . esc_html__( 'No problems found', 'security-ninja' ) . '</p>';
                }
                $results['out'] .= '</div><!-- #sn-cs-results -->';
            }
            if ( isset( $results['missing_ok'] ) ) {
                unset($results['missing_ok']);
            }
            if ( isset( $results['changed_ok'] ) ) {
                unset($results['changed_ok']);
            }
            // No need storing the OK files.
            if ( isset( $results['ok'] ) ) {
                unset($results['ok']);
            }
            if ( $start_time ) {
                $spenttime = microtime( true ) - $start_time;
                $results['run_time'] = number_format( $spenttime, 2 );
            }
            $version = get_bloginfo( 'version' );
            $locale = get_locale();
            $results['last_scan'] = sprintf(
                // translators: %1$s: Date and time of the last scan, %2$s: Number of files checked, %3$s: Time taken for the scan in seconds, %4$s: WordPress version, %5$s: Locale
                esc_html__( 'Last scan at %1$s. %2$s files were checked in %3$s sec. WordPress version %4$s %5$s', 'security-ninja' ),
                gmdate( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $results['last_run'] ),
                number_format( $results['total'] ),
                number_format( $results['run_time'], 2 ),
                $version,
                $locale
            );
            update_option( 'wf_sn_cs_results', $results, false );
            wp_send_json_success( $results );
        } else {
            $ver = get_bloginfo( 'version' );
            $locale = get_locale();
            $error_message = sprintf( __( 'Error - hashes not found. Version: %s, Locale: %s', 'security-ninja' ), esc_html( $ver ), esc_html( $locale ) );
            // Send detailed error response
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
     *
     * This method checks for modified, missing, and unknown files in the WordPress core.
     *
     * @param  bool $return Whether to return the results or update the option.
     * @return array|null Array of scan results or null if no file definitions for this WP version.
     */
    public static function scan_files( $return = false ) {
        $local_time = current_datetime();
        $current_time = $local_time->getTimestamp() + $local_time->getOffset();
        // No nonce check, can be run via scheduled scanner also
        $results['missing_ok'] = array();
        $results['changed_ok'] = array();
        $results['missing_bad'] = array();
        $results['changed_bad'] = array();
        $results['unknown_bad'] = array();
        $results['ok'] = array();
        $results['last_run'] = $current_time;
        $results['total'] = 0;
        $results['run_time'] = 0;
        $start_time = microtime( true );
        $i = 0;
        $ver = get_bloginfo( 'version' );
        // Files ok to be missing
        $missing_ok = array(
            'index.php',
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
                    $results['unknown_bad'][] = $key;
                }
            }
            // Checking if core has been modified
            $results['total'] = count( $filehashes );
            foreach ( $filehashes as $file => $hash ) {
                clearstatcache();
                if ( file_exists( ABSPATH . $file ) ) {
                    if ( $hash === md5_file( ABSPATH . $file ) ) {
                    } elseif ( in_array( $file, $changed_ok, true ) ) {
                        $results['changed_ok'][] = $file;
                    } else {
                        $results['changed_bad'][] = $file;
                    }
                } elseif ( in_array( $file, $missing_ok, true ) ) {
                    $results['missing_ok'][] = $file;
                } else {
                    $results['missing_bad'][] = $file;
                }
            }
            do_action( 'security_ninja_core_scanner_done_scanning', $results, microtime( true ) - $start_time );
            $results['run_time'] = microtime( true ) - $start_time;
            if ( $return ) {
                return $results;
            } else {
                update_option( 'wf_sn_cs_results', $results, false );
                die( '1' );
            }
        } else {
            // no file definitions for this version of WP
            if ( $return ) {
                return null;
            } else {
                update_option( 'wf_sn_cs_results', null, false );
                die( '0' );
            }
        }
    }

    /**
     * The page displayed in the tabs
     *
     * @return void
     */
    public static function core_page() {
        ?>
        <div class="submit-test-container card">

            <h3><?php 
        echo esc_html__( 'Scan core WordPress files and folders', 'security-ninja' );
        ?></h3>

            <p><?php 
        esc_html_e( 'Check for modified files in WordPress itself and detect extra files that should not be there.', 'security-ninja' );
        ?></p>

            <div id="wf-sn-core-scanner-response">
                <p class="spinner"></p>
                <p id="last_scan"></p>
            </div>
        <?php 
        echo '<input type="button" value="' . esc_html__( 'Scan core files', 'security-ninja' ) . '" id="sn-run-core-scan" class="button button-secondary button-small" />';
        ?>
        </div>

        <?php 
        $next_scan = wp_next_scheduled( 'secnin_run_core_scanner' );
        if ( $next_scan ) {
            $time_until_next_scan = human_time_diff( current_time( 'timestamp' ), $next_scan );
            echo '<p>' . sprintf( 
                /* translators: %1$s is the date/time of next scan, %2$s is the time until next scan */
                esc_html__( 'Next scheduled scan: %1$s (%2$s from now)', 'security-ninja' ),
                esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_scan ) ),
                esc_html( $time_until_next_scan )
             ) . '</p>';
        } else {
            echo '<p>' . esc_html__( 'No core scan currently scheduled.', 'security-ninja' ) . '</p>';
        }
    }

    /**
     * Check if files can be restored
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, December 18th, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function check_file_write() {
        $url = wp_nonce_url( 'options.php?page=wf-sn', 'wf-sn-cs' );
        ob_start();
        $creds = request_filesystem_credentials(
            $url,
            '',
            false,
            false,
            null
        );
        ob_end_clean();
        return (bool) $creds;
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
        $file = str_replace( ABSPATH, '', sanitize_text_field( wp_unslash( $_POST['filename'] ) ) );
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
        $url = 'https://core.trac.wordpress.org/browser/tags/' . get_bloginfo( 'version' ) . '/src/' . $file . '?format=txt';
        $org_file = wp_remote_get( $url );
        if ( is_wp_error( $org_file ) || 404 === wp_remote_retrieve_response_code( $org_file ) || empty( $org_file['body'] ) ) {
            $error_message = ( is_wp_error( $org_file ) ? $org_file->get_error_message() : __( 'Unable to download remote file source.', 'security-ninja' ) );
            if ( secnin_fs()->is__premium_only() && secnin_fs()->can_use_premium_code() ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'core_scanner',
                    'Cannot download file',
                    array(
                        'file'  => $file,
                        'url'   => $url,
                        'error' => $error_message,
                    )
                );
            }
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
        if ( !$wp_filesystem->put_contents( trailingslashit( ABSPATH ) . $file, $org_file['body'], FS_CHMOD_FILE ) ) {
            wp_send_json_error( array(
                'message' => __( 'Error writing file.', 'security-ninja' ),
            ) );
        }
        self::scan_files();
        if ( secnin_fs()->is__premium_only() && secnin_fs()->can_use_premium_code() ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'core_scanner',
                __( 'Restored file', 'security-ninja' ),
                array(
                    'name' => $file,
                )
            );
        }
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
            $file = esc_html( $file );
            $out .= '<li>';
            $out .= '<span class="sn-file">' . $file . '</span>';
            if ( $view ) {
                $file_view_url = \WPSecurityNinja\Plugin\FileViewer::generate_file_view_url( ABSPATH . $file );
                $out .= ' <a href="' . esc_url( $file_view_url ) . '" class="button button-small" target="_blank">' . esc_html__( 'View File', 'security-ninja' ) . '</a>';
            }
            if ( $restore ) {
                $out .= ' <button data-hash="' . esc_attr( wp_hash( ABSPATH . $file ) ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( ABSPATH . $file ) . '" href="#restore-dialog" class="sn-restore-source button button-small">' . esc_html__( 'Restore', 'security-ninja' ) . '</button>';
            }
            if ( $delete ) {
                $out .= ' <button data-hash="' . esc_attr( wp_hash( ABSPATH . $file ) ) . '" data-file-short="' . esc_attr( $file ) . '" data-file="' . esc_attr( ABSPATH . $file ) . '" href="#delete-dialog" class="sn-delete-source button button-small">' . esc_html__( 'Delete', 'security-ninja' ) . '</button>';
            }
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