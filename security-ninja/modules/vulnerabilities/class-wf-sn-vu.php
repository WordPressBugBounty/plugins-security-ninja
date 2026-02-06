<?php

namespace WPSecurityNinja\Plugin;

if ( !function_exists( 'add_action' ) ) {
    die( 'Please don\'t open this file directly!' );
}
define( 'WF_SN_VU_OPTIONS_NAME', 'wf_sn_vu_settings_group' );
define( 'WF_SN_VU_OPTIONS_KEY', 'wf_sn_vu_settings' );
define( 'WF_SN_VU_OUTDATED', 'wf_sn_vu_outdated' );
class Wf_Sn_Vu {
    public static $options = null;

    public static $api_urls = array(
        'plugins'   => 'https://wpsecurityninja.sfo2.cdn.digitaloceanspaces.com/plugin_vulns.jsonl',
        'themes'    => 'https://wpsecurityninja.sfo2.cdn.digitaloceanspaces.com/theme_vulns.jsonl',
        'wordpress' => 'https://wpsecurityninja.sfo2.cdn.digitaloceanspaces.com/wp_vulns.jsonl',
    );

    /**
     * init plugin
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 12th, 2021.
     * @return  void
     */
    public static function init() {
        self::$options = self::get_options();
        add_action( 'admin_init', array(__NAMESPACE__ . '\\wf_sn_vu', 'admin_init') );
        add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\wf_sn_vu', 'sn_tabs'), 2 );
        add_action( 'admin_notices', array(__NAMESPACE__ . '\\wf_sn_vu', 'admin_notice_vulnerabilities') );
        add_action( 'init', array(__NAMESPACE__ . '\\wf_sn_vu', 'schedule_cron_jobs') );
        add_action( 'secnin_update_vuln_list', array(__NAMESPACE__ . '\\wf_sn_vu', 'update_vuln_list') );
        add_action( 'secnin_daily_vulnerability_warning_check', array(__NAMESPACE__ . '\\wf_sn_vu', 'daily_vulnerability_check') );
        add_action(
            'upgrader_process_complete',
            array(__NAMESPACE__ . '\\wf_sn_vu', 'do_action_upgrader_process_complete'),
            10,
            2
        );
        add_action( 'delete_theme', array(__NAMESPACE__ . '\\wf_sn_vu', 'do_action_upgrader_process_complete') );
        add_action( 'delete_plugin', array(__NAMESPACE__ . '\\wf_sn_vu', 'do_action_upgrader_process_complete') );
        // Add AJAX handlers for manual vulnerability scan
        add_action( 'wp_ajax_secnin_manual_vuln_scan', array(__NAMESPACE__ . '\\wf_sn_vu', 'handle_manual_vuln_scan') );
        add_action( 'wp_ajax_nopriv_secnin_manual_vuln_scan', array(__NAMESPACE__ . '\\wf_sn_vu', 'handle_manual_vuln_scan_denied') );
        // Add admin scripts for manual scan functionality
        add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\wf_sn_vu', 'enqueue_admin_scripts') );
    }

    /**
     * daily_vulnerability_check.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, June 7th, 2024.
     * @return  void
     */
    public static function daily_vulnerability_check() {
        $enable_email_notice = self::$options['enable_email_notice'];
        if ( !$enable_email_notice ) {
            return;
        }
        // *** EMAIL WARNINGS - CHECK if an email should be sent...
        $vulns = self::return_vulnerabilities();
        if ( $vulns && (!empty( $vulns['plugins'] ) || !empty( $vulns['wordpress'] ) || !empty( $vulns['themes'] )) ) {
            self::send_vulnerability_email( $vulns );
        }
    }

    /**
     * do_action_upgrader_process_complete.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @return  void
     */
    public static function do_action_upgrader_process_complete() {
        if ( self::$options['enable_vulns'] ) {
            // deletes the transient before checking again
            delete_transient( 'wf_sn_return_vulnerabilities' );
            // Updates the vuln list
            self::return_vulnerabilities();
        }
    }

    /**
     * Get options.
     *
     * @since   v0.0.1
     * @return  array The options array.
     */
    public static function get_options() {
        // Return cached options if available
        if ( !is_null( self::$options ) ) {
            return self::$options;
        }
        // Fetch options from the database or any other storage
        $options = get_option( 'wf_sn_vu_settings_group' );
        $defaults = array(
            'enable_vulns'              => true,
            'enable_outdated'           => false,
            'enable_admin_notification' => true,
            'enable_email_notice'       => false,
            'email_notice_recipient'    => '',
            'ignored_plugin_slugs'      => '',
        );
        // Ensure $options is an array
        if ( !is_array( $options ) ) {
            $options = array();
        }
        // Merge defaults with the actual options, prioritizing actual options
        self::$options = array_merge( $defaults, $options );
        // Return the merged options
        return self::$options;
    }

    /**
     * Get stored file validators (ETag, Last-Modified) for a vulnerability file type.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 23rd, 2026.
     * @param   string  $type File type: 'plugins', 'themes', or 'wordpress'.
     * @return  array|false Array with validators or false if not found.
     */
    public static function get_file_validators( $type ) {
        // Validate type against allowed values.
        if ( !isset( self::$api_urls[$type] ) ) {
            return false;
        }
        $option_key = 'wf_sn_vu_file_validators_' . sanitize_key( $type );
        $validators = get_option( $option_key, false );
        if ( false === $validators || !is_array( $validators ) ) {
            return false;
        }
        return $validators;
    }

    /**
     * Save file validators (ETag, Last-Modified) for a vulnerability file type.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 23rd, 2026.
     * @param   string  $type           File type: 'plugins', 'themes', or 'wordpress'.
     * @param   string  $etag           ETag string (preserve quotes/W/ prefix).
     * @param   string  $last_modified  Last-Modified string.
     * @param   int     $last_checked   Timestamp of last check attempt.
     * @param   int     $last_success   Timestamp of last successful update (0 if not set).
     * @param   string  $last_error     Last error message/status code (empty if none).
     * @return  boolean True on success, false on failure.
     */
    public static function save_file_validators(
        $type,
        $etag = '',
        $last_modified = '',
        $last_checked = 0,
        $last_success = 0,
        $last_error = ''
    ) {
        // Validate type against allowed values.
        if ( !isset( self::$api_urls[$type] ) ) {
            return false;
        }
        $option_key = 'wf_sn_vu_file_validators_' . sanitize_key( $type );
        $data = array(
            'stored_etag'          => sanitize_text_field( $etag ),
            'stored_last_modified' => sanitize_text_field( $last_modified ),
            'last_checked_ts'      => absint( $last_checked ),
            'last_success_ts'      => absint( $last_success ),
            'last_error'           => sanitize_text_field( $last_error ),
        );
        // Use false as third parameter to prevent autoloading.
        return update_option( $option_key, $data, false );
    }

    /**
     * Check if content is likely valid JSONL format.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 23rd, 2026.
     * @param   string  $content Content to check.
     * @return  boolean True if likely JSONL, false otherwise.
     */
    public static function is_likely_jsonl( $content ) {
        if ( empty( $content ) || strlen( $content ) === 0 ) {
            return false;
        }
        // Check if contains at least one newline.
        if ( strpos( $content, "\n" ) !== false ) {
            return true;
        }
        // Check if first non-whitespace character is '{'.
        $trimmed = ltrim( $content );
        if ( !empty( $trimmed ) && $trimmed[0] === '{' ) {
            return true;
        }
        return false;
    }

    /**
     * Register settings on admin init
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @return  void
     */
    public static function admin_init() {
        register_setting( 'wf_sn_vu_settings_group', 'wf_sn_vu_settings_group', array(__NAMESPACE__ . '\\wf_sn_vu', 'sanitize_settings') );
        // Add AJAX handlers
        add_action( 'wp_ajax_secnin_download_all_vuln_files', array(__NAMESPACE__ . '\\wf_sn_vu', 'handle_download_all_vuln_files') );
    }

    /**
     * Schedule cron jobs on 'init'
     *
     * @since   v0.0.1
     * @return  void
     */
    public static function schedule_cron_jobs() {
        if ( !wp_next_scheduled( 'secnin_daily_vulnerability_warning_check' ) ) {
            wp_schedule_event( time() + 10, 'daily', 'secnin_daily_vulnerability_warning_check' );
        }
        $scheduled_event = wp_next_scheduled( 'secnin_update_vuln_list' );
        // Free version logic, executed only if the premium block above did not run
        if ( !$scheduled_event ) {
            wp_schedule_event( time(), 'weekly', 'secnin_update_vuln_list' );
        } else {
            $current_schedule = wp_get_schedule( 'secnin_update_vuln_list' );
            if ( 'weekly' !== $current_schedule ) {
                wp_clear_scheduled_hook( 'secnin_update_vuln_list' );
                wp_schedule_event( time(), 'weekly', 'secnin_update_vuln_list' );
            }
        }
    }

    /**
     * Tab filter
     *
     * @since   v0.0.1
     * @param   array $tabs The existing tabs.
     * @return  array The modified tabs array.
     */
    public static function sn_tabs( $tabs ) {
        $vuln_tab = array(
            'id'       => 'sn_vuln',
            'class'    => '',
            'label'    => __( 'Vulnerabilities', 'security-ninja' ),
            'callback' => array(__NAMESPACE__ . '\\wf_sn_vu', 'render_vuln_page'),
        );
        // Check if notification bubles enabled.
        if ( self::$options['enable_admin_notification'] ) {
            try {
                $return_vuln_count = self::return_vuln_count();
                if ( $return_vuln_count ) {
                    $vuln_tab['count'] = $return_vuln_count;
                }
            } catch ( \Exception $e ) {
                // Leave count unset so tab renders without badge.
            }
        }
        $done = 0;
        $tabcount = count( $tabs );
        for ($i = 0; $i < $tabcount; $i++) {
            if ( 'sn_vuln' === $tabs[$i]['id'] ) {
                $tabs[$i] = $vuln_tab;
                $done = 1;
                break;
            }
        }
        if ( !$done ) {
            $tabs[] = $vuln_tab;
        }
        return $tabs;
    }

    /**
     * Strips http:// or https://
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @param   string  $url    Default: ''
     * @return  mixed
     */
    public static function remove_http( $url = '' ) {
        if ( strpos( $url, 'http://' ) === 0 ) {
            $url = substr( $url, 7 );
        } elseif ( strpos( $url, 'https://' ) === 0 ) {
            $url = substr( $url, 8 );
        }
        return $url;
    }

    /**
     * Function to get the file and save it locally.
     * Uses atomic writes to prevent corruption.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, July 25th, 2023.
     * @version v1.0.1  Friday, October 13th, 2023.
     * @version v1.0.2  Friday, January 23rd, 2026.
     * @param   mixed   $file_content
     * @param   mixed   $filename
     * @return  boolean
     */
    public static function get_file_and_save( $file_content, $filename ) {
        if ( empty( $file_content ) || empty( $filename ) ) {
            return false;
        }
        // Sanity check: ensure content looks like JSONL.
        if ( !self::is_likely_jsonl( $file_content ) ) {
            return false;
        }
        // Sanitize filename to prevent directory traversal.
        $filename = sanitize_file_name( $filename );
        $upload_dir = wp_upload_dir();
        $sn_dir = trailingslashit( $upload_dir['basedir'] ) . 'security-ninja/vulns/';
        // Create directory without trying to chown
        if ( !file_exists( $sn_dir ) ) {
            wp_mkdir_p( $sn_dir );
            // Set directory permissions but don't try to chown
            chmod( $sn_dir, 0755 );
            // Create .htaccess to prevent direct access
            $htaccess_content = "deny from all\n";
            file_put_contents( $sn_dir . '.htaccess', $htaccess_content );
        }
        // Atomic write: write to temp file first.
        $temp_filename = $filename . '.tmp';
        $temp_path = $sn_dir . $temp_filename;
        $final_path = $sn_dir . $filename;
        // Defense-in-depth: Validate paths stay within intended directory.
        $real_sn_dir = realpath( $sn_dir );
        $real_temp_path = realpath( dirname( $temp_path ) );
        $real_final_path = realpath( dirname( $final_path ) );
        if ( false === $real_sn_dir || false === $real_temp_path || false === $real_final_path ) {
            return false;
        }
        // Ensure paths are within the intended directory (prevent directory traversal).
        if ( 0 !== strpos( $real_temp_path, $real_sn_dir ) || 0 !== strpos( $real_final_path, $real_sn_dir ) ) {
            return false;
        }
        // Write to temp file with lock.
        $temp_written = file_put_contents( $temp_path, $file_content, LOCK_EX );
        if ( false === $temp_written ) {
            return false;
        }
        // Verify temp file is valid (lightweight check).
        if ( !self::is_likely_jsonl( file_get_contents( $temp_path ) ) ) {
            @unlink( $temp_path );
            // Clean up temp file.
            return false;
        }
        // Atomically rename temp to final (rename is atomic on same filesystem).
        $renamed = @rename( $temp_path, $final_path );
        if ( !$renamed ) {
            @unlink( $temp_path );
            // Clean up temp file on failure.
            return false;
        }
        return true;
    }

    /**
     * Download vulnerability file using conditional GET (ETag/Last-Modified).
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 23rd, 2026.
     * @param   string  $type File type: 'plugins', 'themes', or 'wordpress'.
     * @param   string  $url  Base URL for the vulnerability file.
     * @return  array|false Array with result info on success, false on failure.
     */
    public static function download_vuln_file_with_conditional_get( $type, $url ) {
        // Validate type against allowed values.
        if ( !isset( self::$api_urls[$type] ) ) {
            return false;
        }
        // Validate URL is from whitelisted API URLs (security: prevent arbitrary URL downloads).
        if ( !isset( self::$api_urls[$type] ) || self::$api_urls[$type] !== $url ) {
            return false;
        }
        // Retrieve stored validators for this file type.
        $validators = self::get_file_validators( $type );
        $stored_etag = false;
        $stored_last_modified = false;
        if ( $validators ) {
            $stored_etag = ( !empty( $validators['stored_etag'] ) ? $validators['stored_etag'] : false );
            $stored_last_modified = ( !empty( $validators['stored_last_modified'] ) ? $validators['stored_last_modified'] : false );
        }
        // Build conditional GET headers.
        $conditional_headers = array();
        if ( $stored_etag ) {
            // Sanitize ETag header value (preserve quotes/W/ prefix but escape any dangerous characters).
            $conditional_headers['If-None-Match'] = sanitize_text_field( $stored_etag );
        }
        if ( $stored_last_modified ) {
            // Sanitize Last-Modified header value.
            $conditional_headers['If-Modified-Since'] = sanitize_text_field( $stored_last_modified );
        }
        // Prepare request arguments.
        $request_url = esc_url_raw( $url . '.gz' );
        $args = array(
            'headers'   => $conditional_headers,
            'timeout'   => 30,
            'sslverify' => true,
        );
        // Make conditional GET request (use wp_remote_get to allow custom headers).
        $response = wp_remote_get( $request_url, $args );
        $current_time = time();
        $result_info = array(
            'success'            => false,
            'status_code'        => 0,
            'conditional_sent'   => !empty( $conditional_headers ),
            'etag_sent'          => !empty( $stored_etag ),
            'last_modified_sent' => !empty( $stored_last_modified ),
            'bytes_downloaded'   => 0,
            'gzip_detected'      => false,
            'decode_succeeded'   => false,
            'file_written'       => false,
        );
        // Handle network errors.
        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            // Don't overwrite file, don't clear validators, record error.
            if ( $validators ) {
                self::save_file_validators(
                    $type,
                    ( $stored_etag ? $stored_etag : '' ),
                    ( $stored_last_modified ? $stored_last_modified : '' ),
                    $current_time,
                    ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                    $error_message
                );
            } else {
                self::save_file_validators(
                    $type,
                    '',
                    '',
                    $current_time,
                    0,
                    $error_message
                );
            }
            return false;
        }
        // Get response code and headers.
        $response_code = wp_remote_retrieve_response_code( $response );
        $headers = wp_remote_retrieve_headers( $response );
        $result_info['status_code'] = $response_code;
        // Handle 304 Not Modified.
        if ( 304 === $response_code ) {
            // No body processing needed, don't touch file, don't update validators.
            if ( $validators ) {
                self::save_file_validators(
                    $type,
                    ( $stored_etag ? $stored_etag : '' ),
                    ( $stored_last_modified ? $stored_last_modified : '' ),
                    $current_time,
                    ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                    ''
                );
            } else {
                self::save_file_validators(
                    $type,
                    '',
                    '',
                    $current_time,
                    0,
                    ''
                );
            }
            $result_info['success'] = true;
            return $result_info;
        }
        // Handle 200 OK.
        if ( 200 === $response_code ) {
            $body = wp_remote_retrieve_body( $response );
            $content_length = ( isset( $headers['content-length'] ) ? (int) $headers['content-length'] : strlen( $body ) );
            $result_info['bytes_downloaded'] = $content_length;
            // Extract ETag and Last-Modified from response headers.
            // Sanitize header values before storing.
            $received_etag = ( isset( $headers['etag'] ) ? sanitize_text_field( $headers['etag'] ) : '' );
            $received_last_modified = ( isset( $headers['last-modified'] ) ? sanitize_text_field( $headers['last-modified'] ) : '' );
            // Robust gzip detection: check Content-Encoding header and magic bytes.
            $content_encoding = ( isset( $headers['content-encoding'] ) ? strtolower( $headers['content-encoding'] ) : '' );
            $is_gzipped = false;
            if ( 'gzip' === $content_encoding ) {
                $is_gzipped = true;
            } elseif ( strlen( $body ) >= 2 ) {
                // Check magic bytes: 0x1f 0x8b indicates gzip.
                $magic_bytes = unpack( 'C2', substr( $body, 0, 2 ) );
                if ( 0x1f === $magic_bytes[1] && 0x8b === $magic_bytes[2] ) {
                    $is_gzipped = true;
                }
            }
            $result_info['gzip_detected'] = $is_gzipped;
            // Decode if gzipped.
            $decoded_content = $body;
            if ( $is_gzipped ) {
                $decoded = gzdecode( $body );
                if ( false !== $decoded && strlen( $decoded ) > 0 ) {
                    $decoded_content = $decoded;
                    $result_info['decode_succeeded'] = true;
                } elseif ( self::is_likely_jsonl( $body ) ) {
                    // Already decoded, use as-is (fallback).
                    $decoded_content = $body;
                    $result_info['decode_succeeded'] = true;
                } else {
                    // Failed decode, treat as error - don't overwrite file.
                    $error_msg = sprintf( 
                        /* translators: %s: Vulnerability type */
                        __( 'Failed to decompress %s vulnerability file.', 'security-ninja' ),
                        $type
                     );
                    if ( $validators ) {
                        self::save_file_validators(
                            $type,
                            ( $stored_etag ? $stored_etag : '' ),
                            ( $stored_last_modified ? $stored_last_modified : '' ),
                            $current_time,
                            ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                            $error_msg
                        );
                    } else {
                        self::save_file_validators(
                            $type,
                            '',
                            '',
                            $current_time,
                            0,
                            $error_msg
                        );
                    }
                    return false;
                }
            } else {
                // Not gzipped, treat as plain text JSONL.
                $result_info['decode_succeeded'] = true;
            }
            // Sanity check: ensure decoded content is valid JSONL.
            if ( !self::is_likely_jsonl( $decoded_content ) ) {
                $error_msg = sprintf( 
                    /* translators: %s: Vulnerability type */
                    __( 'Downloaded %s vulnerability file does not appear to be valid JSONL.', 'security-ninja' ),
                    sanitize_text_field( $type )
                 );
                if ( $validators ) {
                    self::save_file_validators(
                        $type,
                        ( $stored_etag ? $stored_etag : '' ),
                        ( $stored_last_modified ? $stored_last_modified : '' ),
                        $current_time,
                        ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                        $error_msg
                    );
                } else {
                    self::save_file_validators(
                        $type,
                        '',
                        '',
                        $current_time,
                        0,
                        $error_msg
                    );
                }
                return false;
            }
            // Atomic write to file.
            $write_result = self::get_file_and_save( $decoded_content, "{$type}_vulns.jsonl" );
            if ( $write_result ) {
                $result_info['file_written'] = true;
                $result_info['success'] = true;
                // Only if write succeeds: update validators and last_success_ts.
                self::save_file_validators(
                    $type,
                    $received_etag,
                    $received_last_modified,
                    $current_time,
                    $current_time,
                    ''
                );
            } else {
                // Write failed - don't update validators.
                $error_msg = sprintf( 
                    /* translators: %s: Vulnerability type */
                    __( 'Failed to save %s vulnerability file.', 'security-ninja' ),
                    $type
                 );
                if ( $validators ) {
                    self::save_file_validators(
                        $type,
                        ( $stored_etag ? $stored_etag : '' ),
                        ( $stored_last_modified ? $stored_last_modified : '' ),
                        $current_time,
                        ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                        $error_msg
                    );
                } else {
                    self::save_file_validators(
                        $type,
                        '',
                        '',
                        $current_time,
                        0,
                        $error_msg
                    );
                }
                return false;
            }
            return $result_info;
        }
        // Handle other HTTP status codes (4xx/5xx).
        $error_msg = sprintf( 
            /* translators: %1$s: Vulnerability type, %2$d: HTTP status code */
            __( 'HTTP error %2$d downloading %1$s vulnerabilities.', 'security-ninja' ),
            sanitize_text_field( $type ),
            absint( $response_code )
         );
        // Don't overwrite file, don't clear validators, record error with status code.
        if ( $validators ) {
            self::save_file_validators(
                $type,
                ( $stored_etag ? $stored_etag : '' ),
                ( $stored_last_modified ? $stored_last_modified : '' ),
                $current_time,
                ( !empty( $validators['last_success_ts'] ) ? $validators['last_success_ts'] : 0 ),
                $error_msg
            );
        } else {
            self::save_file_validators(
                $type,
                '',
                '',
                $current_time,
                0,
                $error_msg
            );
        }
        return false;
    }

    /**
     * Function to recursively create directories
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Thursday, October 12th, 2023.
     * @version v1.0.1  Monday, April 1st, 2024.
     * @param   mixed   $dir
     * @param   mixed   $wp_filesystem
     * @param   mixed   $mode           Default: FS_CHMOD_DIR
     * @return  boolean
     */
    public static function recursive_mkdir( $dir, $wp_filesystem, $mode = FS_CHMOD_DIR ) {
        $dir = rtrim( str_replace( '\\', '/', $dir ), '/' );
        if ( $wp_filesystem->is_dir( $dir ) ) {
            return true;
            // Directory already exists
        }
        $parent_dir = dirname( $dir );
        if ( !$wp_filesystem->is_dir( $parent_dir ) ) {
            // Recursively try to create the parent directory
            if ( !self::recursive_mkdir( $parent_dir, $wp_filesystem, $mode ) ) {
                return false;
                // Failed to create parent directory
            }
        }
        // Now create the directory since parent exists
        if ( !$wp_filesystem->mkdir( $dir, $mode ) ) {
            return false;
            // Failed to make directory
        }
        return true;
    }

    /**
     * Function to read the content of the file.
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v5.160
     * @version v1.0.0  Tuesday, July 25th, 2023.
     * @version v1.0.1  Monday, April 1st, 2024.
     * @return  mixed
     */
    public static function load_vulnerabilities() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        // More efficient to require_once at the top if not already included elsewhere
        global $wp_filesystem;
        if ( empty( $wp_filesystem ) && !WP_Filesystem() ) {
            return false;
            // Early return if filesystem initialization fails
        }
        $upload_dir = wp_upload_dir();
        $data = array(
            'wordpress' => array(),
            'plugins'   => array(),
            'themes'    => array(),
        );
        foreach ( $data as $type => &$data_for_type ) {
            $file_path = $upload_dir['basedir'] . "/security-ninja/vulns/{$type}_vulns.jsonl";
            if ( $wp_filesystem->exists( $file_path ) ) {
                $file_lines = $wp_filesystem->get_contents_array( $file_path );
                if ( $file_lines ) {
                    foreach ( $file_lines as $line ) {
                        $decoded_line = json_decode( $line, true );
                        if ( is_array( $decoded_line ) ) {
                            // Ensure decoding was successful and resulted in an array
                            $data_for_type[] = $decoded_line;
                        }
                    }
                }
            }
        }
        return (object) $data;
        // Convert back to object if needed for compatibility
    }

    /**
     * Ensure the vulnerability JSONL directory exists and is writable.
     *
     * @since   v5.265
     * @return  bool True if directory exists and is writable, false otherwise.
     */
    private static function ensure_vulns_directory() {
        $upload_dir = wp_upload_dir();
        if ( empty( $upload_dir['basedir'] ) ) {
            return false;
        }
        $sn_dir = trailingslashit( $upload_dir['basedir'] ) . 'security-ninja/vulns/';
        if ( !file_exists( $sn_dir ) ) {
            wp_mkdir_p( $sn_dir );
            if ( is_dir( $sn_dir ) ) {
                chmod( $sn_dir, 0755 );
                $htaccess_content = "deny from all\n";
                file_put_contents( $sn_dir . '.htaccess', $htaccess_content );
            }
        }
        return is_dir( $sn_dir ) && is_writable( $sn_dir );
    }

    /**
     * Get local path to a vulnerability JSONL file in uploads.
     *
     * @since   v5.263
     * @param   string $type File type: 'plugins', 'themes', or 'wordpress'.
     * @return  string|false Local file path on success, false on invalid type.
     */
    private static function get_vuln_jsonl_file_path( $type ) {
        $type = sanitize_key( $type );
        $filenames = array(
            'plugins'   => 'plugins_vulns.jsonl',
            'themes'    => 'themes_vulns.jsonl',
            'wordpress' => 'wordpress_vulns.jsonl',
        );
        if ( !isset( $filenames[$type] ) ) {
            return false;
        }
        $upload_dir = wp_upload_dir();
        if ( empty( $upload_dir['basedir'] ) ) {
            return false;
        }
        return trailingslashit( $upload_dir['basedir'] ) . 'security-ninja/vulns/' . $filenames[$type];
    }

    /**
     * Stream vulnerability JSONL records line-by-line.
     *
     * This avoids loading large files into memory. Intended for local files in the uploads directory.
     * Yields nothing if the file path is invalid, the file is missing, or the file is not readable.
     *
     * @since   v5.263
     * @param   string $file_path Absolute local file path.
     * @return  \Generator Yields each decoded JSON object as an array.
     */
    private static function stream_jsonl_records( $file_path ) {
        if ( empty( $file_path ) || !is_string( $file_path ) ) {
            return;
        }
        if ( !is_file( $file_path ) || !is_readable( $file_path ) ) {
            return;
        }
        $handle = fopen( $file_path, 'rb' );
        if ( false === $handle ) {
            return;
        }
        try {
            while ( ($line = fgets( $handle )) !== false ) {
                $line = trim( $line );
                if ( '' === $line ) {
                    continue;
                }
                $decoded = json_decode( $line, true );
                if ( is_array( $decoded ) ) {
                    (yield $decoded);
                }
            }
        } finally {
            if ( is_resource( $handle ) ) {
                fclose( $handle );
            }
        }
    }

    /**
     * Count valid JSONL records in a file without loading it into memory.
     *
     * @since   v5.263
     * @param   string $file_path Absolute local file path.
     * @return  int Count of valid JSONL records.
     */
    private static function count_jsonl_records( $file_path ) {
        $count = 0;
        try {
            foreach ( self::stream_jsonl_records( $file_path ) as $record ) {
                ++$count;
            }
        } catch ( \Throwable $e ) {
            return 0;
        }
        return $count;
    }

    /**
     * Get the last modification time of vulnerability files.
     *
     * @since   v5.209
     * @version v1.0.1 Sunday, September 15th, 2024.
     * @access  public
     * @global  WP_Filesystem_Base $wp_filesystem WordPress filesystem subclass.
     * @return  array|false An array of last modified timestamps for each vulnerability type, or false on failure.
     */
    public static function get_vulnerabilities_last_modified() {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;
        if ( empty( $wp_filesystem ) && !WP_Filesystem() ) {
            return false;
            // Early return if filesystem initialization fails.
        }
        $upload_dir = wp_upload_dir();
        $last_modified = array(
            'wordpress' => false,
            'plugins'   => false,
            'themes'    => false,
        );
        foreach ( $last_modified as $type => &$timestamp ) {
            $file_path = $upload_dir['basedir'] . "/security-ninja/vulns/{$type}_vulns.jsonl";
            if ( $wp_filesystem->exists( $file_path ) ) {
                $timestamp = $wp_filesystem->mtime( $file_path );
            }
        }
        return $last_modified;
    }

    /**
     * set_html_content_type.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Sunday, October 29th, 2023.
     * @return  mixed
     */
    public static function set_html_content_type() {
        return 'text/html';
    }

    /**
     * Updates the vulnerability list.
     * Creates the folder if necessary.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Sunday, September 4th, 2022.
     * @return  void
     */
    public static function update_vuln_list() {
        // No update if feature disabled
        self::get_options();
        if ( !isset( self::$options ) || !is_array( self::$options ) || !isset( self::$options['enable_vulns'] ) || !self::$options['enable_vulns'] ) {
            return false;
        }
        self::ensure_vulns_directory();
        $oldcount = false;
        $newcount = false;
        $old_data = self::load_vulnerabilities();
        $oldcount = 0;
        if ( $old_data ) {
            $oldcount = self::return_known_vuln_count();
        }
        foreach ( self::$api_urls as $type => $url ) {
            // Use conditional GET to download file.
            $result = self::download_vuln_file_with_conditional_get( $type, $url );
            // Result is handled within download_vuln_file_with_conditional_get().
            // Continue to next file regardless of result.
        }
        $newcount = self::return_known_vuln_count();
        if ( $oldcount && $newcount ) {
            $diff = $newcount - $oldcount;
            if ( 0 === $oldcount ) {
                $diff = 1;
                // Just in case the difference was 0
            }
            if ( 0 < $diff ) {
                $message = '';
                if ( $oldcount > 0 && $diff > 0 ) {
                    // Translators: How many new vulnerabilities were downloaded
                    $diff_text = sprintf( _n(
                        'Downloaded %s new vulnerability.',
                        'Downloaded %s new vulnerabilities.',
                        $diff,
                        'security-ninja'
                    ), number_format_i18n( $diff ) );
                } else {
                    $diff_text = __( 'No new vulnerabilities detected.', 'security-ninja' );
                }
                // Base message
                $message = esc_html( $diff_text );
                if ( isset( $old_data->timestamp ) ) {
                    // Include the update with a focus on action if there's an increase
                    $message .= ( $diff > 0 ? ' ' . sprintf( 
                        // Translators: Explaining how many vulnerabilities are tracked by the plugin
                        esc_html__( 'Now tracking a total of %1$s known vulnerabilities. Last checked: %2$s. Update or replace vulnerable plugins promptly.', 'security-ninja' ),
                        esc_html( number_format_i18n( $newcount ) ),
                        esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $old_data->timestamp ) )
                     ) : '' );
                } else {
                    // If no timestamp is available, keep it simple but informative
                    $message .= ' ' . sprintf( 
                        // Translators:
                        esc_html__( 'Now tracking a total of %1$s known vulnerabilities. Ensure your plugins are secure.', 'security-ninja' ),
                        esc_html( number_format_i18n( $newcount ) )
                     );
                }
                update_option( 'wf_sn_vu_vulns_notice', $message, false );
            }
        }
    }

    /**
     * send_vulnerability_email.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, May 28th, 2024.
     * @param   mixed   $vulns
     * @return  void
     */
    public static function send_vulnerability_email( $vulns ) {
        if ( !$vulns ) {
            return;
        }
        // Ready to send email
        $email_notice_recipient = self::$options['email_notice_recipient'];
        $recipients = array_map( 'trim', explode( ',', $email_notice_recipient ) );
        $message_content_html = '';
        $message_content_html .= '<p>' . sprintf( 
            // translators: %1$s is the site name
            esc_html__( 'Security Ninja has detected vulnerabilities on your website, %1$s.', 'security-ninja' ),
            wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES )
         ) . '</p>';
        if ( isset( $vulns['plugins'] ) ) {
            foreach ( $vulns['plugins'] as $vu ) {
                $message_content_html .= '<p><strong>' . esc_html__( 'Plugin', 'security-ninja' ) . ':</strong> ' . esc_html( $vu['name'] ) . '<br>';
                $message_content_html .= '<em>' . esc_html( $vu['desc'] ) . '</em><br>';
                if ( $vu['CVE_ID'] ) {
                    $message_content_html .= 'ID: ' . esc_html( $vu['CVE_ID'] ) . '<br>';
                }
                $message_content_html .= '</p>';
            }
        }
        if ( isset( $vulns['themes'] ) ) {
            foreach ( $vulns['themes'] as $vu ) {
                $message_content_html .= '<p><strong>' . esc_html__( 'Theme', 'security-ninja' ) . ':</strong> ' . esc_html( $vu['name'] ) . '<br>';
                $message_content_html .= esc_html( $vu['desc'] ) . '<br>';
                if ( $vu['CVE_ID'] ) {
                    $message_content_html .= 'ID: ' . esc_html( $vu['CVE_ID'] ) . '<br>';
                }
                $message_content_html .= '</p>';
            }
        }
        $message_content_html .= '<p>' . esc_html__( 'View all vulnerabilities:', 'security-ninja' ) . ' <a href="' . esc_url( admin_url( 'admin.php?page=wf-sn#sn_vuln' ) ) . '" target="_blank">' . esc_html__( 'here', 'security-ninja' ) . '</a></p>';
        $message_content_html .= '<p>' . esc_html__( 'You are receiving this email because you have activated email warnings for the vulnerability scanner.', 'security-ninja' ) . '</p>';
        $message_content_html .= '<hr>';
        $url = Utils::generate_sn_web_link( 'email_vuln_warning_footer', '/' );
        $message_content_html .= '<p>' . esc_html__( 'Thank you for using WP Security Ninja', 'security-ninja' ) . ' - <a href="' . esc_url( $url ) . '" target="_blank">' . esc_html__( 'WP Security Ninja', 'security-ninja' ) . '</a></p>';
        // Additional security advice
        $message_content_html .= '<p>' . esc_html__( 'For enhanced security, please ensure that all your plugins, themes, and WordPress itself are always up-to-date. Regular updates help protect your website from known vulnerabilities.', 'security-ninja' ) . '</p>';
        $site_url = site_url();
        $parsed_url = wp_parse_url( $site_url );
        $domain = ( isset( $parsed_url['host'] ) ? $parsed_url['host'] : '' );
        $subject = esc_html__( 'Vulnerabilities detected on', 'security-ninja' ) . ' ' . $domain;
        $headers = array('Content-Type: text/html; charset=UTF-8');
        add_filter( 'wp_mail_content_type', array(__CLASS__, 'set_html_content_type') );
        foreach ( $recipients as $recipient ) {
            $sendresult = wp_mail(
                $recipient,
                $subject,
                $message_content_html,
                $headers
            );
            if ( !$sendresult ) {
                // Log the event that the email was not sent
                $last_error = error_get_last();
                $error_message = ( isset( $last_error['message'] ) ? $last_error['message'] : __( 'Unknown error', 'security-ninja' ) );
                Wf_Sn_El_Modules::log_event( 'security_ninja', 'vulnerabilities', sprintf( __( 'Email not sent to %1$s. Error: %2$s', 'security-ninja' ), esc_html( $recipient ), esc_html( $error_message ) ) );
            } else {
                Wf_Sn_El_Modules::log_event( 'security_ninja', 'vulnerabilities', sprintf( __( 'Vulnerabilities detected - Email warning sent to %s', 'security-ninja' ), esc_html( $recipient ) ) );
            }
        }
        remove_filter( 'wp_mail_content_type', array(__CLASS__, 'set_html_content_type') );
        update_option( 'wf_sn_vu_last_email', current_time( 'mysql' ), false );
    }

    /**
     * Check if an array is a multidimensional array.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @param   mixed   $x
     * @return  boolean
     */
    public static function is_multi_array( $x ) {
        if ( count( array_filter( $x, 'is_array' ) ) > 0 ) {
            return true;
        }
        return false;
    }

    /**
     * Convert an object to an array.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @param   mixed   $object The object to convert
     * @return  mixed
     */
    public static function object_to_array_map( $object_var ) {
        if ( !is_object( $object_var ) && !is_array( $object_var ) ) {
            return $object_var;
        }
        return array_map( array(__NAMESPACE__ . '\\wf_sn_vu', 'object_to_array'), (array) $object_var );
    }

    /**
     * Check if a value exists in the array/object.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @param   mixed   $needle     The value that you are searching for
     * @param   mixed   $haystack   The array/object to search
     * @param   boolean $strict     Whether to use strict search or not
     * @return  boolean
     */
    public static function search_for_value( $needle, $haystack, $strict = true ) {
        $haystack = self::object_to_array( $haystack );
        if ( is_array( $haystack ) ) {
            if ( self::is_multi_array( $haystack ) ) {
                // Multidimensional array
                foreach ( $haystack as $subhaystack ) {
                    if ( self::search_for_value( $needle, $subhaystack, $strict ) ) {
                        return true;
                    }
                }
            } elseif ( array_keys( $haystack ) !== range( 0, count( $haystack ) - 1 ) ) {
                // Associative array
                foreach ( $haystack as $key => $val ) {
                    if ( $needle === $val && !$strict ) {
                        return true;
                    } elseif ( $needle === $val && $strict ) {
                        return true;
                    }
                }
                return false;
            } elseif ( $needle === $haystack && !$strict ) {
                // Normal array
                return true;
            } elseif ( $needle === $haystack && $strict ) {
                return true;
            }
        }
        return false;
    }

    /**
     * object_to_array.
     * Ref: https://stackoverflow.com/questions/4345554/convert-a-php-object-to-an-associative-array
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Thursday, July 22nd, 2021.
     * @param   mixed   $data
     * @return  mixed
     */
    public static function object_to_array( $data ) {
        if ( is_array( $data ) || is_object( $data ) ) {
            $result = array();
            foreach ( $data as $key => $value ) {
                $result[$key] = ( is_array( $data ) || is_object( $data ) ? self::object_to_array( $value ) : $value );
            }
            return $result;
        }
        return $data;
    }

    /**
     * Return list of known vulnerabilities from the website, checking installed plugins and WordPress version against list from API.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Friday, May 13th, 2022.
     * @return  array
     */
    public static function return_vulnerabilities() {
        // Use persistent storage instead of transients for better reliability
        $found_vulnerabilities = get_option( 'wf_sn_vulnerabilities_cache', false );
        $cache_timestamp = get_option( 'wf_sn_vulnerabilities_cache_timestamp', 0 );
        $cache_expiry = 24 * HOUR_IN_SECONDS;
        // 24 hours instead of 1 hour
        // Check if cache is still valid
        if ( $found_vulnerabilities && time() - $cache_timestamp < $cache_expiry ) {
            return $found_vulnerabilities;
        }
        global $wp_version;
        $found_vulnerabilities = array();
        $installed_plugins = false;
        // Initialize scan_summary outside the conditional to ensure it always exists.
        $scan_summary = array(
            'plugins'                     => array(),
            'themes'                      => array(),
            'wordpress'                   => array(),
            'total_vulnerabilities_found' => 0,
        );
        if ( self::$options['enable_vulns'] ) {
            self::ensure_vulns_directory();
            // Ensure vulnerability files exist (first run / missing files).
            $needs_update = false;
            foreach ( array('plugins', 'themes', 'wordpress') as $type ) {
                $file_path = self::get_vuln_jsonl_file_path( $type );
                if ( empty( $file_path ) || !file_exists( $file_path ) ) {
                    $needs_update = true;
                    break;
                }
            }
            if ( $needs_update ) {
                self::update_vuln_list();
            }
            $installed_plugins = get_plugins();
            // Use memory-efficient plugin vulnerability checking
            if ( $installed_plugins ) {
                try {
                    $plugin_scan_result = self::check_plugin_vulnerabilities_memory_efficient( $installed_plugins );
                    if ( !empty( $plugin_scan_result['vulnerabilities'] ) ) {
                        $found_vulnerabilities['plugins'] = $plugin_scan_result['vulnerabilities'];
                        $scan_summary['plugins'] = $plugin_scan_result['stats'] ?? array();
                        $scan_summary['total_vulnerabilities_found'] += $plugin_scan_result['stats']['vulnerabilities_found'] ?? 0;
                    } else {
                        $scan_summary['plugins'] = $plugin_scan_result['stats'] ?? array();
                    }
                } catch ( \Exception $e ) {
                    // Use original method as fallback
                    $vulns = self::load_vulnerabilities();
                    if ( !$vulns ) {
                        self::update_vuln_list();
                        $vulns = self::load_vulnerabilities();
                    }
                    if ( $vulns && isset( $vulns->plugins ) ) {
                        $vuln_plugin_arr = self::object_to_array( $vulns->plugins );
                        $plugin_vulnerabilities = self::check_plugin_vulnerabilities_legacy( $installed_plugins, $vuln_plugin_arr );
                        if ( !empty( $plugin_vulnerabilities ) ) {
                            $found_vulnerabilities['plugins'] = $plugin_vulnerabilities;
                            $scan_summary['total_vulnerabilities_found'] += count( $plugin_vulnerabilities );
                        }
                    }
                }
            }
            // Memory-efficient theme vulnerability checking
            $all_themes = wp_get_themes();
            $themes = array();
            // Build theme data manually
            foreach ( $all_themes as $theme ) {
                $themes[$theme->stylesheet] = array(
                    'Name'      => $theme->get( 'Name' ),
                    'Author'    => $theme->get( 'Author' ),
                    'AuthorURI' => $theme->get( 'AuthorURI' ),
                    'Version'   => $theme->get( 'Version' ),
                    'Template'  => $theme->get( 'Template' ),
                    'Status'    => $theme->get( 'Status' ),
                );
            }
            if ( $themes ) {
                try {
                    $theme_scan_result = self::check_theme_vulnerabilities_memory_efficient( $themes );
                    if ( !empty( $theme_scan_result['vulnerabilities'] ) ) {
                        $found_vulnerabilities['themes'] = $theme_scan_result['vulnerabilities'];
                        $scan_summary['themes'] = $theme_scan_result['stats'];
                        $scan_summary['total_vulnerabilities_found'] += $theme_scan_result['stats']['vulnerabilities_found'];
                    } else {
                        $scan_summary['themes'] = $theme_scan_result['stats'];
                    }
                } catch ( \Exception $e ) {
                    // Use original theme scanning method as fallback
                    $vuln_theme_arr = false;
                    $vulns = self::load_vulnerabilities();
                    if ( !$vulns ) {
                        self::update_vuln_list();
                        $vulns = self::load_vulnerabilities();
                    }
                    if ( $vulns && isset( $vulns->themes ) ) {
                        $vuln_theme_arr = self::object_to_array( $vulns->themes );
                    }
                    // Get ignored slugs (plugins & themes)
                    $ignored_slugs = array();
                    if ( !empty( self::$options['ignored_plugin_slugs'] ) ) {
                        $ignored_slugs = array_map( 'trim', explode( "\n", self::$options['ignored_plugin_slugs'] ) );
                        $ignored_slugs = array_filter( $ignored_slugs );
                    }
                    if ( $themes && $vuln_theme_arr ) {
                        $theme_vulnerabilities = array();
                        $themes_checked = 0;
                        $themes_ignored = 0;
                        foreach ( $themes as $key => $ap ) {
                            // Skip if this theme is in the ignored list
                            if ( in_array( $key, $ignored_slugs, true ) ) {
                                ++$themes_ignored;
                                continue;
                            }
                            ++$themes_checked;
                            $findtheme = array_search( $key, array_column( $vuln_theme_arr, 'slug' ), true );
                            if ( false !== $findtheme ) {
                                $matched = $vuln_theme_arr[$findtheme];
                                if ( isset( $matched['versionEndExcluding'] ) && '' !== $vuln_theme_arr[$findtheme]['versionEndExcluding'] ) {
                                    $matched['versionEndExcluding'] = rtrim( $matched['versionEndExcluding'], '.0' );
                                    if ( version_compare( $ap['Version'], $matched['versionEndExcluding'], '<' ) ) {
                                        $desc = '';
                                        if ( isset( $matched['description'] ) ) {
                                            $desc = $matched['description'];
                                        }
                                        $theme_vulnerabilities[$key] = array(
                                            'name'                => $ap['Name'],
                                            'desc'                => $desc,
                                            'installedVersion'    => $ap['Version'],
                                            'versionEndExcluding' => $matched['versionEndExcluding'],
                                            'CVE_ID'              => $matched['CVE_ID'],
                                            'refs'                => $matched['refs'],
                                        );
                                    }
                                }
                            }
                        }
                        if ( !empty( $theme_vulnerabilities ) ) {
                            $found_vulnerabilities['themes'] = $theme_vulnerabilities;
                            $scan_summary['total_vulnerabilities_found'] += count( $theme_vulnerabilities );
                        }
                        $scan_summary['themes'] = array(
                            'themes_checked'         => $themes_checked,
                            'themes_ignored'         => $themes_ignored,
                            'vulnerabilities_found'  => count( $theme_vulnerabilities ),
                            'total_themes_installed' => count( $themes ),
                        );
                    }
                }
            }
        }
        // ------------ Find WordPress vulnerabilities ------------
        $wp_vulnerabilities_found = 0;
        $lookup_id = 0;
        try {
            $wp_file_path = self::get_vuln_jsonl_file_path( 'wordpress' );
            if ( empty( $wp_file_path ) || !is_file( $wp_file_path ) || !is_readable( $wp_file_path ) ) {
                self::ensure_vulns_directory();
                wp_schedule_single_event( time(), 'secnin_update_vuln_list' );
            } else {
                foreach ( self::stream_jsonl_records( $wp_file_path ) as $wpvuln ) {
                    if ( empty( $wpvuln['versionEndExcluding'] ) || empty( $wpvuln['CVE_ID'] ) ) {
                        continue;
                    }
                    $version_end_excluding = rtrim( $wpvuln['versionEndExcluding'], '.0' );
                    // Trim trailing .0s for comparing.
                    if ( version_compare( $wp_version, $version_end_excluding, '<' ) ) {
                        $found_vulnerabilities['wordpress'][$lookup_id] = array(
                            'desc'                => ( isset( $wpvuln['description'] ) ? $wpvuln['description'] : '' ),
                            'versionEndExcluding' => $version_end_excluding,
                            'CVE_ID'              => $wpvuln['CVE_ID'],
                        );
                        if ( isset( $wpvuln['recommendation'] ) ) {
                            $found_vulnerabilities['wordpress'][$lookup_id]['recommendation'] = $wpvuln['recommendation'];
                        }
                        ++$lookup_id;
                        ++$wp_vulnerabilities_found;
                    }
                }
            }
        } catch ( \Exception $e ) {
            $vulns = self::load_vulnerabilities();
            if ( !$vulns ) {
                self::update_vuln_list();
                $vulns = self::load_vulnerabilities();
            }
            $wordpressarr = false;
            if ( $vulns && isset( $vulns->wordpress ) ) {
                $wordpressarr = self::object_to_array( $vulns->wordpress );
            }
            if ( $wordpressarr ) {
                foreach ( $wordpressarr as $key => $wpvuln ) {
                    if ( empty( $wpvuln['versionEndExcluding'] ) || empty( $wpvuln['CVE_ID'] ) ) {
                        continue;
                    }
                    $wpvuln['versionEndExcluding'] = rtrim( $wpvuln['versionEndExcluding'], '.0' );
                    // Trim trailing .0s for comparing.
                    if ( version_compare( $wp_version, $wpvuln['versionEndExcluding'], '<' ) ) {
                        $found_vulnerabilities['wordpress'][$lookup_id] = array(
                            'desc'                => ( isset( $wpvuln['description'] ) ? $wpvuln['description'] : '' ),
                            'versionEndExcluding' => $wpvuln['versionEndExcluding'],
                            'CVE_ID'              => $wpvuln['CVE_ID'],
                        );
                        if ( isset( $wpvuln['recommendation'] ) ) {
                            $found_vulnerabilities['wordpress'][$lookup_id]['recommendation'] = $wpvuln['recommendation'];
                        }
                        ++$lookup_id;
                        ++$wp_vulnerabilities_found;
                    }
                }
            }
        }
        // Add WordPress scan summary
        $scan_summary['wordpress'] = array(
            'wordpress_checked'     => 1,
            'vulnerabilities_found' => $wp_vulnerabilities_found,
            'current_version'       => $wp_version,
        );
        $scan_summary['total_vulnerabilities_found'] += $wp_vulnerabilities_found;
        // Store results persistently instead of using transients
        if ( isset( $found_vulnerabilities ) ) {
            // Store scan summary in a separate option for reporting
            update_option( 'wf_sn_scan_summary', $scan_summary, false );
            // Cache the results for 24 hours using persistent storage
            update_option( 'wf_sn_vulnerabilities_cache', $found_vulnerabilities, false );
            update_option( 'wf_sn_vulnerabilities_cache_timestamp', time(), false );
            return $found_vulnerabilities;
        } else {
            // Cache empty results for 24 hours
            update_option( 'wf_sn_vulnerabilities_cache', false, false );
            update_option( 'wf_sn_vulnerabilities_cache_timestamp', time(), false );
            update_option( 'wf_sn_scan_summary', $scan_summary, false );
            return false;
        }
    }

    /**
     * Gets list of WordPress from official API and their security status
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Wednesday, January 13th, 2021.
     * @return  mixed
     */
    public static function get_wp_ver_status() {
        if ( empty( self::$options['enable_vulns'] ) ) {
            return false;
        }
        $wp_vers_status = get_transient( 'wp_vers_status' );
        if ( false === $wp_vers_status ) {
            $request_url = 'https://api.wordpress.org/core/stable-check/1.0/';
            $response = wp_remote_get( $request_url );
            if ( !is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
                $body = wp_remote_retrieve_body( $response );
                $decoded_body = json_decode( $body );
                if ( !empty( $decoded_body ) ) {
                    $wp_vers_status = $decoded_body;
                    set_transient( 'wp_vers_status', $wp_vers_status, 12 * HOUR_IN_SECONDS );
                }
            }
        }
        return $wp_vers_status;
    }

    /**
     * Returns the number of known vulnerabilities
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, July 6th, 2021.
     * @version v1.0.1  Monday, April 1st, 2024.
     * @return  mixed
     */
    public static function return_known_vuln_count() {
        $plugin_file = self::get_vuln_jsonl_file_path( 'plugins' );
        $themes_file = self::get_vuln_jsonl_file_path( 'themes' );
        $wordpress_file = self::get_vuln_jsonl_file_path( 'wordpress' );
        $plugin_vulns_count = ( $plugin_file ? self::count_jsonl_records( $plugin_file ) : 0 );
        $theme_vulns_count = ( $themes_file ? self::count_jsonl_records( $themes_file ) : 0 );
        $wp_vulns_count = ( $wordpress_file ? self::count_jsonl_records( $wordpress_file ) : 0 );
        $total = $plugin_vulns_count + $theme_vulns_count + $wp_vulns_count;
        if ( 0 === $total ) {
            $any_missing = false;
            foreach ( array($plugin_file, $themes_file, $wordpress_file) as $path ) {
                if ( !empty( $path ) && (!is_file( $path ) || !is_readable( $path )) ) {
                    $any_missing = true;
                    break;
                }
            }
            if ( $any_missing ) {
                self::ensure_vulns_directory();
                wp_schedule_single_event( time(), 'secnin_update_vuln_list' );
            }
        }
        return $total;
    }

    public static function get_vuln_details() {
        $plugin_file = self::get_vuln_jsonl_file_path( 'plugins' );
        $themes_file = self::get_vuln_jsonl_file_path( 'themes' );
        $wordpress_file = self::get_vuln_jsonl_file_path( 'wordpress' );
        return array(
            'plugins'   => ( $plugin_file ? self::count_jsonl_records( $plugin_file ) : 0 ),
            'themes'    => ( $themes_file ? self::count_jsonl_records( $themes_file ) : 0 ),
            'wordpress' => ( $wordpress_file ? self::count_jsonl_records( $wordpress_file ) : 0 ),
        );
    }

    /**
     * Helper method to count vulnerabilities in a more abstract way
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Monday, April 1st, 2024.
     * @param   mixed   $vuln_type
     * @return  mixed
     */
    private static function count_vulns( $vuln_type ) {
        return ( isset( $vuln_type ) ? count( $vuln_type ) : 0 );
    }

    /**
     * Returns number of known vulnerabilities across all types
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @return  mixed
     */
    public static function return_vuln_count() {
        $vulnerabilities = self::return_vulnerabilities();
        if ( !$vulnerabilities ) {
            return false;
        }
        $total_vulnerabilities = 0;
        if ( isset( $vulnerabilities['plugins'] ) ) {
            $total_vulnerabilities = $total_vulnerabilities + count( $vulnerabilities['plugins'] );
        }
        if ( isset( $vulnerabilities['themes'] ) ) {
            $total_vulnerabilities = $total_vulnerabilities + count( $vulnerabilities['themes'] );
        }
        if ( isset( $vulnerabilities['wordpress'] ) ) {
            $total_vulnerabilities = $total_vulnerabilities + count( $vulnerabilities['wordpress'] );
        }
        return $total_vulnerabilities;
    }

    /**
     * Renders vulnerability tab
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Tuesday, January 10th, 2023.
     * @return  void
     */
    public static function render_vuln_page() {
        global $wp_version;
        if ( self::$options['enable_vulns'] ) {
            // Get the list of vulnerabilities
            $vulnerabilities = self::return_vulnerabilities();
            $needs_update = false;
            foreach ( array('plugins', 'themes', 'wordpress') as $type ) {
                $file_path = self::get_vuln_jsonl_file_path( $type );
                if ( empty( $file_path ) || !file_exists( $file_path ) ) {
                    $needs_update = true;
                    break;
                }
            }
            if ( $needs_update ) {
                self::update_vuln_list();
            }
            $plugin_file = self::get_vuln_jsonl_file_path( 'plugins' );
            $themes_file = self::get_vuln_jsonl_file_path( 'themes' );
            $wordpress_file = self::get_vuln_jsonl_file_path( 'wordpress' );
            $plugin_vulns_count = ( $plugin_file ? self::count_jsonl_records( $plugin_file ) : 0 );
            $theme_vulns_count = ( $themes_file ? self::count_jsonl_records( $themes_file ) : 0 );
            $wp_vulns_count = ( $wordpress_file ? self::count_jsonl_records( $wordpress_file ) : 0 );
            $total_vulnerabilities = $plugin_vulns_count + $wp_vulns_count + $theme_vulns_count;
        }
        // Get scan summary for better display
        $scan_summary = get_option( 'wf_sn_scan_summary', false );
        if ( !isset( $vulnerabilities ) ) {
            $vulnerabilities = array();
        }
        // Generate HTML for displaying vulnerability results
        $output = self::generate_vulnerability_display( $vulnerabilities, $scan_summary );
        ?>
		<div class="submit-test-container">
			<div class="section sncard">
				<h2><span class="dashicons dashicons-shield-alt"></span> <?php 
        esc_html_e( 'Vulnerability Scanner', 'security-ninja' );
        ?></h2>
				<?php 
        $allowed_tags = wp_kses_allowed_html( 'post' );
        $allowed_tags['input'] = array(
            'id'      => true,
            'class'   => true,
            'type'    => true,
            'checked' => true,
            'name'    => true,
            'value'   => true,
            'for'     => true,
        );
        echo wp_kses( $output, $allowed_tags );
        ?>
			</div>
			<div class="section sncard settings-card">
				<form method="post" action="options.php">
					<?php 
        settings_fields( 'wf_sn_vu_settings_group' );
        ?>
					<h2 class="ss_header"><span class="dashicons dashicons-admin-generic"></span> <?php 
        esc_html_e( 'Settings', 'security-ninja' );
        ?></h2>
					<table class="form-table">
						<tbody>
							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_vulns">
										<h3><?php 
        esc_html_e( 'Vulnerability scanning', 'security-ninja' );
        ?></h3>
										<p class="description"><?php 
        esc_html_e( 'Checking for known vulnerabilites.', 'security-ninja' );
        ?></p>
									</label></th>
								<td class="sn-cf-options">
									<?php 
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_vu_settings_group_enable_vulns', array(
            'value'       => 1,
            'saved_value' => self::$options['enable_vulns'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_vulns]',
        ) );
        ?>

								</td>
							</tr>

							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_admin_notification">
										<h3><?php 
        esc_html_e( 'Admin counter', 'security-ninja' );
        ?></h3>
										<p class="description"><?php 
        esc_html_e( 'Disable warning notice in admin pages.', 'security-ninja' );
        ?></p>
									</label></th>
								<td class="sn-cf-options">
									<?php 
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_vu_settings_group_enable_admin_notification', array(
            'saved_value' => self::$options['enable_admin_notification'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_admin_notification]',
        ) );
        ?>

								</td>
							</tr>

							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_email_notice">
										<h3><?php 
        esc_html_e( 'Email warnings', 'security-ninja' );
        ?></h3>
										<p class="description"><?php 
        esc_html_e( 'Enable email notifications. Only when one or more vulnerabilites are detected.', 'security-ninja' );
        ?></p>
									</label></th>
								<td class="sn-cf-options">
									<?php 
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_vu_settings_group_enable_email_notice', array(
            'saved_value' => self::$options['enable_email_notice'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_email_notice]',
        ) );
        ?>

								</td>
							</tr>

							<tr>
								<th scope="row"><label for="wf_sn_vu_settings_group_email_notice_recipient_">
										<h3><?php 
        esc_html_e( 'Email recipient', 'security-ninja' );
        ?></h3>
										<p class="description">
											<?php 
        esc_html_e( 'Who should get the warning? The system will send an email when a vulnerability is detected. Maximum one email per day.', 'security-ninja' );
        ?>
										</p>
									</label></th>
								<td></td>
							</tr>
							<tr>
								<td class="fullwidth">
									<input name="wf_sn_vu_settings_group[email_notice_recipient]" id="wf_sn_vu_settings_group_email_notice_recipient_" type="text" value="<?php 
        echo esc_attr( self::$options['email_notice_recipient'] );
        ?>" class="regular-text" placeholder="">
								</td>
							</tr>

							<tr>
								<th scope="row"><label for="wf_sn_vu_settings_group_ignored_plugin_slugs">
										<h3><?php 
        esc_html_e( 'Ignored Plugins & Themes', 'security-ninja' );
        ?></h3>
										<p class="description">
											<?php 
        esc_html_e( 'Enter plugin or theme folder names (one per line) that should be ignored during vulnerability scanning. These will be skipped even if vulnerabilities are detected.', 'security-ninja' );
        ?>
										</p>
									</label></th>
								<td></td>
							</tr>
							<tr>
								<td class="fullwidth">
									<textarea name="wf_sn_vu_settings_group[ignored_plugin_slugs]" id="wf_sn_vu_settings_group_ignored_plugin_slugs" rows="5" cols="50" class="large-text code" placeholder="plugin-folder-name"><?php 
        echo esc_textarea( self::$options['ignored_plugin_slugs'] );
        ?></textarea>
									<p class="description">
										<?php 
        esc_html_e( 'Example: designthemes-core-features or twentytwentyfour', 'security-ninja' );
        ?>
									</p>
								</td>
							</tr>
							<tr>
								<td colspan="2" class="fullwidth">
									<p class="submit"><input type="submit" value="<?php 
        esc_html_e( 'Save Changes', 'security-ninja' );
        ?>" class="input-button button-primary" name="Submit" />

								</td>
							</tr>
						</tbody>
					</table>

				</form>
			</div><!-- .card -->

			<?php 
        if ( self::$options['enable_vulns'] ) {
            ?>
			<div class="section sncard">
				<h2><span class="dashicons dashicons-update"></span> <?php 
            esc_html_e( 'Manual Vulnerability Scan', 'security-ninja' );
            ?></h2>
				<p><?php 
            esc_html_e( 'Click the button below to perform a manual vulnerability scan. This will check your installed plugins, themes, and WordPress version against the latest vulnerability database.', 'security-ninja' );
            ?></p>
				
				<div class="manual-scan-container">
					<button type="button" id="secnin-manual-vuln-scan" class="button button-primary snbutton">
						<?php 
            esc_html_e( 'Run Manual Scan', 'security-ninja' );
            ?>
					</button>
					<span id="secnin-scan-status" class="scan-status" style="display: none;"></span>
				</div>
			</div>
			<?php 
        }
        ?>

			<?php 
        if ( self::$options['enable_vulns'] ) {
            $last_modified = self::get_vulnerabilities_last_modified();
            if ( $last_modified ) {
                ?>
					<div class="section sncard">
						<h3><?php 
                esc_html_e( 'Last Updated', 'security-ninja' );
                ?></h3>
						<div class="sn-vuln-update-list">
							<?php 
                $has_missing_or_outdated = false;
                $missing_files = array();
                $outdated_files = array();
                foreach ( $last_modified as $type => $timestamp ) {
                    // Ensure we have a valid timestamp
                    if ( $timestamp && is_numeric( $timestamp ) ) {
                        $current_time = time();
                        $time_diff = human_time_diff( $timestamp, $current_time );
                        // Check if file is outdated (older than 2 days)
                        $two_days_ago = $current_time - 2 * 24 * 60 * 60;
                        $is_outdated = $timestamp < $two_days_ago;
                        // If the timestamp is in the future or very recent, show appropriate message
                        if ( $timestamp > $current_time ) {
                            $time_diff = __( 'just now', 'security-ninja' );
                        } elseif ( $timestamp === $current_time ) {
                            $time_diff = __( 'just now', 'security-ninja' );
                        }
                        printf(
                            // translators: %1$s: Type, %2$s: Formatted date, %3$s: Time difference
                            '%1$s: %2$s (%3$s)',
                            '<strong>' . esc_html( ucfirst( $type ) ) . '</strong>',
                            esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) ),
                            esc_html( $time_diff )
                        );
                        if ( $is_outdated ) {
                            $has_missing_or_outdated = true;
                            $outdated_files[] = $type;
                        }
                    } else {
                        // Check if the file actually exists
                        $upload_dir = wp_upload_dir();
                        $file_path = $upload_dir['basedir'] . "/security-ninja/vulns/{$type}_vulns.jsonl";
                        if ( file_exists( $file_path ) ) {
                            printf( '%1$s: %2$s', '<strong>' . esc_html( ucfirst( $type ) ) . '</strong>', esc_html__( 'File exists but timestamp unavailable', 'security-ninja' ) );
                        } else {
                            printf( '%1$s: %2$s', '<strong>' . esc_html( ucfirst( $type ) ) . '</strong>', esc_html__( 'File not found', 'security-ninja' ) );
                            $has_missing_or_outdated = true;
                            $missing_files[] = $type;
                        }
                    }
                }
                // Show single download button if any files are missing or outdated
                if ( $has_missing_or_outdated ) {
                    echo '<br><br><a href="#" class="button button-primary download-all-vuln-files">' . esc_html__( 'Download All Files', 'security-ninja' ) . '</a>';
                }
                ?>
						</div>
					</div>
					<?php 
            }
        }
        ?>

		</div>
		<?php 
    }

    /**
     * Display warning if test were never run
     *
     * @since   v0.0.1
     * @return  void
     */
    public static function admin_notice_vulnerabilities() {
        global $current_screen;
        if ( !isset( $current_screen ) || !is_object( $current_screen ) ) {
            return;
        }
        // dont show on the wizard page
        if ( strpos( $current_screen->id, 'security-ninja-wizard' ) !== false ) {
            return;
        }
        $notice = get_option( 'wf_sn_vu_vulns_notice' );
        $title = __( 'Vulnerability list updated', 'security-ninja' );
        if ( $notice ) {
            $allowed_tags = wp_kses_allowed_html( 'post' );
            // 'post' ?
            ?>
			<div class="secnin-notice notice notice-success is-dismissible" id="sn_vulnerability_updated">
				<h3><span class="dashicons dashicons-yes-alt"></span><?php 
            echo esc_html( $title );
            ?></h3>
				<p><?php 
            echo wp_kses( $notice, $allowed_tags );
            ?></p>
			</div>
			<?php 
            // lets delete till next time.
            delete_option( 'wf_sn_vu_vulns_notice' );
        }
        if ( !\PAnD::is_admin_notice_active( 'dismiss-vulnerabilities-notice-1' ) || wf_sn::is_plugin_page() ) {
            return;
        }
        $found_plugin_vulnerabilities = self::return_vulnerabilities();
        if ( $found_plugin_vulnerabilities ) {
            $total = 0;
            if ( isset( $found_plugin_vulnerabilities['plugins'] ) ) {
                $total = $total + count( $found_plugin_vulnerabilities['plugins'] );
            }
            if ( isset( $found_plugin_vulnerabilities['wordpress'] ) ) {
                $total = $total + count( $found_plugin_vulnerabilities['wordpress'] );
            }
            if ( isset( $found_plugin_vulnerabilities['themes'] ) ) {
                $total = $total + count( $found_plugin_vulnerabilities['themes'] );
            }
            if ( 0 === $total ) {
                return;
            }
            ?>
			<div data-dismissible="dismiss-vulnerabilities-notice-1" class="secnin-notice notice notice-error is-dismissible" id="sn_vulnerability_warning_dismiss">

				<h3><span class="dashicons dashicons-warning"></span>
					<?php 
            // translators: Shown if one or multiple vulnerabilities found
            echo esc_html( sprintf( _n(
                'You have %s known vulnerability on your website!',
                'You have %s known vulnerabilities on your website!',
                $total,
                'security-ninja'
            ), number_format_i18n( $total ) ) );
            ?>
				</h3>
				<p>
					<?php 
            printf( 'Visit the <a href="%s">Vulnerabilities tab</a> for more details.', esc_url( admin_url( 'admin.php?page=wf-sn#sn_vuln' ) ) );
            ?>
					- <a href="#" class="dismiss-this"><?php 
            esc_html_e( 'Dismiss warning for 24 hours.', 'security-ninja' );
            ?></a></p>
			</div>
			<?php 
        }
    }

    /**
     * Plugin activation routines
     *
     * @since   v0.0.1
     * @return  void
     */
    public static function activate() {
        // Download the vulnerability list for the first time
        self::update_vuln_list();
    }

    /**
     * Sanitize settings on save
     *
     * @since   v0.0.1
     * @param   mixed   $values values to sanitize
     * @return  mixed
     */
    public static function sanitize_settings( $values ) {
        static $old_options = array(
            'enable_vulns'              => 0,
            'enable_outdated'           => 0,
            'enable_admin_notification' => 0,
            'enable_email_notice'       => 0,
            'email_notice_recipient'    => '',
            'ignored_plugin_slugs'      => '',
        );
        if ( !is_array( $values ) ) {
            return $old_options;
        }
        $sanitized_values = array();
        foreach ( $values as $key => $value ) {
            switch ( $key ) {
                case 'enable_vulns':
                case 'enable_outdated':
                case 'enable_admin_notification':
                case 'enable_email_notice':
                    // Normalize to integer (0 or 1) for consistency
                    $sanitized_values[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $value );
                    break;
                case 'email_notice_recipient':
                    $sanitized_values[$key] = sanitize_text_field( $value );
                    break;
                case 'ignored_plugin_slugs':
                    // Sanitize plugin slugs - remove empty lines and trim whitespace
                    $slugs = explode( "\n", $value );
                    $clean_slugs = array();
                    foreach ( $slugs as $slug ) {
                        $slug = trim( $slug );
                        if ( !empty( $slug ) ) {
                            $clean_slugs[] = sanitize_text_field( $slug );
                        }
                    }
                    $sanitized_values[$key] = implode( "\n", $clean_slugs );
                    break;
                default:
                    // Handle or log unknown keys
                    break;
            }
        }
        $return = array_merge( $old_options, $sanitized_values );
        delete_transient( 'wf_sn_return_vulnerabilities' );
        return $return;
    }

    /**
     * Routines that run on deactivation
     *
     * @since   v0.0.1
     * @return  void
     */
    public static function deactivate() {
        $centraloptions = Wf_Sn::get_options();
        if ( !isset( $centraloptions['remove_settings_deactivate'] ) ) {
            return;
        }
        delete_option( 'wf_sn_vu_settings_group' );
        delete_option( 'wf_sn_vu_vulns' );
        delete_option( 'wf_sn_vu_outdated' );
        delete_option( 'wf_sn_vu_settings' );
        delete_option( 'wf_sn_vu_vulns_notice' );
        delete_option( 'wf_sn_vu_last_email' );
        delete_option( 'wf_sn_vulnerabilities_cache' );
        delete_option( 'wf_sn_vulnerabilities_cache_timestamp' );
        delete_option( 'wf_sn_scan_summary' );
        // Clean up validator options for all file types.
        foreach ( self::$api_urls as $type => $url ) {
            delete_option( 'wf_sn_vu_file_validators_' . $type );
        }
    }

    /**
     * Memory-efficient vulnerability check for specific plugins
     * Processes vulnerability file line by line instead of loading entire file into memory
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Memory optimization - Friday, January 12th, 2024.
     * @version v1.0.2  Enhanced reporting - Friday, January 12th, 2024.
     * @param   array   $installed_plugins Array of installed plugins
     * @return  array   Array with vulnerabilities and scan statistics
     */
    public static function check_plugin_vulnerabilities_memory_efficient( $installed_plugins ) {
        $found_vulnerabilities = array();
        $scan_stats = array(
            'plugins_checked'         => 0,
            'plugins_ignored'         => 0,
            'vulnerabilities_found'   => 0,
            'lines_processed'         => 0,
            'total_plugins_installed' => count( $installed_plugins ),
        );
        $file_path = self::get_vuln_jsonl_file_path( 'plugins' );
        if ( empty( $file_path ) || !is_file( $file_path ) || !is_readable( $file_path ) ) {
            self::ensure_vulns_directory();
            wp_schedule_single_event( time(), 'secnin_update_vuln_list' );
            return array(
                'vulnerabilities' => array(),
                'stats'           => $scan_stats,
            );
        }
        // Get ignored plugin slugs
        $ignored_slugs = array();
        if ( !empty( self::$options['ignored_plugin_slugs'] ) ) {
            $ignored_slugs = array_map( 'trim', explode( "\n", self::$options['ignored_plugin_slugs'] ) );
            $ignored_slugs = array_filter( $ignored_slugs );
            // Remove empty entries
        }
        $ignored_set = array();
        if ( !empty( $ignored_slugs ) ) {
            $ignored_set = array_fill_keys( $ignored_slugs, true );
        }
        // Map installed plugins by slug for O(1) lookups.
        $plugin_slug_map = array();
        foreach ( $installed_plugins as $key => $plugin_data ) {
            $slug = strtok( $key, '/' );
            if ( !empty( $slug ) ) {
                $plugin_slug_map[$slug] = $plugin_data;
            }
        }
        $installed_set = array();
        if ( !empty( $plugin_slug_map ) ) {
            $installed_set = array_fill_keys( array_keys( $plugin_slug_map ), true );
        }
        foreach ( self::stream_jsonl_records( $file_path ) as $decoded_line ) {
            ++$scan_stats['lines_processed'];
            if ( !isset( $decoded_line['slug'] ) ) {
                continue;
            }
            // Only process if this plugin is installed
            $plugin_slug = $decoded_line['slug'];
            if ( !isset( $installed_set[$plugin_slug] ) ) {
                continue;
            }
            // Skip if this plugin is in the ignored list
            if ( isset( $ignored_set[$plugin_slug] ) ) {
                ++$scan_stats['plugins_ignored'];
                continue;
            }
            $installed_plugin = ( isset( $plugin_slug_map[$plugin_slug] ) ? $plugin_slug_map[$plugin_slug] : null );
            if ( !$installed_plugin ) {
                continue;
            }
            ++$scan_stats['plugins_checked'];
            // Check for vulnerabilities
            $is_vulnerable = false;
            $vulnerability_data = array();
            // Check versionEndExcluding
            if ( isset( $decoded_line['versionEndExcluding'] ) && '' !== $decoded_line['versionEndExcluding'] ) {
                if ( version_compare( $installed_plugin['Version'], $decoded_line['versionEndExcluding'], '<' ) ) {
                    $is_vulnerable = true;
                    $vulnerability_data = array(
                        'name'                => $installed_plugin['Name'],
                        'desc'                => ( isset( $decoded_line['description'] ) ? $decoded_line['description'] : '' ),
                        'installedVersion'    => $installed_plugin['Version'],
                        'versionEndExcluding' => $decoded_line['versionEndExcluding'],
                        'CVE_ID'              => $decoded_line['CVE_ID'],
                        'refs'                => ( isset( $decoded_line['refs'] ) ? $decoded_line['refs'] : array() ),
                    );
                }
            }
            // Check versionImpact
            if ( !$is_vulnerable && isset( $decoded_line['versionImpact'] ) && '' !== $decoded_line['versionImpact'] ) {
                if ( version_compare( $installed_plugin['Version'], $decoded_line['versionImpact'], '<=' ) ) {
                    $is_vulnerable = true;
                    $vulnerability_data = array(
                        'name'             => $installed_plugin['Name'],
                        'desc'             => ( isset( $decoded_line['description'] ) ? $decoded_line['description'] : '' ),
                        'installedVersion' => $installed_plugin['Version'],
                        'versionImpact'    => $decoded_line['versionImpact'],
                        'CVE_ID'           => $decoded_line['CVE_ID'],
                        'refs'             => ( isset( $decoded_line['refs'] ) ? $decoded_line['refs'] : array() ),
                    );
                    if ( isset( $decoded_line['recommendation'] ) ) {
                        $vulnerability_data['recommendation'] = $decoded_line['recommendation'];
                    }
                }
            }
            if ( $is_vulnerable ) {
                $found_vulnerabilities[$plugin_slug] = $vulnerability_data;
                ++$scan_stats['vulnerabilities_found'];
            }
        }
        return array(
            'vulnerabilities' => $found_vulnerabilities,
            'stats'           => $scan_stats,
        );
    }

    /**
     * Convert memory limit string to bytes
     *
     * @param   string  $val Memory limit string (e.g., '256M', '1G')
     * @return  int     Memory limit in bytes
     */
    private static function return_bytes( $val ) {
        $val = trim( $val );
        $last = strtolower( $val[strlen( $val ) - 1] );
        $val = (int) $val;
        switch ( $last ) {
            case 'g':
                $val *= 1024;
            case 'm':
                $val *= 1024;
            case 'k':
                $val *= 1024;
        }
        return $val;
    }

    /**
     * Legacy plugin vulnerability checking method (fallback)
     * Uses the original approach of loading all vulnerabilities into memory
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Memory optimization - Friday, January 12th, 2024.
     * @param   array   $installed_plugins Array of installed plugins
     * @param   array   $vuln_plugin_arr   Array of all plugin vulnerabilities
     * @return  array   Array of found vulnerabilities
     */
    public static function check_plugin_vulnerabilities_legacy( $installed_plugins, $vuln_plugin_arr ) {
        $found_vulnerabilities = array();
        // Get ignored plugin slugs
        $ignored_slugs = array();
        if ( !empty( self::$options['ignored_plugin_slugs'] ) ) {
            $ignored_slugs = array_map( 'trim', explode( "\n", self::$options['ignored_plugin_slugs'] ) );
            $ignored_slugs = array_filter( $ignored_slugs );
            // Remove empty entries
        }
        foreach ( $installed_plugins as $key => $ap ) {
            $lookup_id = strtok( $key, '/' );
            // Skip if this plugin is in the ignored list
            if ( in_array( $lookup_id, $ignored_slugs, true ) ) {
                continue;
            }
            $findplugin = array_search( $lookup_id, array_column( $vuln_plugin_arr, 'slug' ), true );
            if ( $findplugin ) {
                if ( isset( $vuln_plugin_arr[$findplugin]['versionEndExcluding'] ) && '' !== $vuln_plugin_arr[$findplugin]['versionEndExcluding'] ) {
                    // check #1 - versionEndExcluding
                    if ( version_compare( $ap['Version'], $vuln_plugin_arr[$findplugin]['versionEndExcluding'], '<' ) ) {
                        $description = '';
                        if ( isset( $vuln_plugin_arr[$findplugin]['description'] ) ) {
                            $description = $vuln_plugin_arr[$findplugin]['description'];
                        }
                        $found_vulnerabilities[$lookup_id] = array(
                            'name'                => $ap['Name'],
                            'desc'                => $description,
                            'installedVersion'    => $ap['Version'],
                            'versionEndExcluding' => $vuln_plugin_arr[$findplugin]['versionEndExcluding'],
                            'CVE_ID'              => $vuln_plugin_arr[$findplugin]['CVE_ID'],
                            'refs'                => $vuln_plugin_arr[$findplugin]['refs'],
                        );
                    }
                }
                // Checks via the versionImpact method
                if ( isset( $vuln_plugin_arr[$findplugin]['versionImpact'] ) && '' !== $vuln_plugin_arr[$findplugin]['versionImpact'] ) {
                    if ( version_compare( $ap['Version'], $vuln_plugin_arr[$findplugin]['versionImpact'], '<=' ) ) {
                        $found_vulnerabilities[$lookup_id] = array(
                            'name'             => $ap['Name'],
                            'desc'             => $vuln_plugin_arr[$findplugin]['description'],
                            'installedVersion' => $ap['Version'],
                            'versionImpact'    => $vuln_plugin_arr[$findplugin]['versionImpact'],
                            'CVE_ID'           => $vuln_plugin_arr[$findplugin]['CVE_ID'],
                            'refs'             => $vuln_plugin_arr[$findplugin]['refs'],
                        );
                        if ( isset( $vuln_plugin_arr[$findplugin]['recommendation'] ) ) {
                            $found_vulnerabilities[$lookup_id]['recommendation'] = $vuln_plugin_arr[$findplugin]['recommendation'];
                        }
                    }
                }
            }
        }
        return $found_vulnerabilities;
    }

    /**
     * Handle manual vulnerability scan AJAX request
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @return  void
     */
    public static function handle_manual_vuln_scan() {
        // Security checks
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( __( 'You do not have sufficient permissions to access this page.', 'security-ninja' ) );
        }
        // Verify nonce
        if ( !isset( $_POST['nonce'] ) || !wp_verify_nonce( $_POST['nonce'], 'secnin_manual_vuln_scan' ) ) {
            wp_die( __( 'Security check failed.', 'security-ninja' ) );
        }
        // Check if vulnerability scanning is enabled
        if ( !self::$options['enable_vulns'] ) {
            wp_send_json_error( array(
                'message' => __( 'Vulnerability scanning is disabled.', 'security-ninja' ),
            ) );
        }
        // Rate limiting - prevent too frequent scans
        $last_scan = get_transient( 'secnin_manual_vuln_scan_last' );
        if ( $last_scan && time() - $last_scan < 60 ) {
            // 1 minute cooldown
            wp_send_json_error( array(
                'message' => __( 'Please wait at least 1 minute between manual scans.', 'security-ninja' ),
            ) );
        }
        // Set transient to prevent rapid successive scans
        set_transient( 'secnin_manual_vuln_scan_last', time(), 60 );
        // Clear cached results to force fresh scan
        delete_option( 'wf_sn_vulnerabilities_cache' );
        delete_option( 'wf_sn_vulnerabilities_cache_timestamp' );
        delete_option( 'wf_sn_scan_summary' );
        // Perform the vulnerability scan
        $vulnerabilities = self::return_vulnerabilities();
        // Get scan summary for detailed reporting
        $scan_summary = get_option( 'wf_sn_scan_summary', false );
        // Count vulnerabilities found
        $vuln_count = 0;
        if ( $vulnerabilities ) {
            if ( isset( $vulnerabilities['plugins'] ) ) {
                $vuln_count += count( $vulnerabilities['plugins'] );
            }
            if ( isset( $vulnerabilities['themes'] ) ) {
                $vuln_count += count( $vulnerabilities['themes'] );
            }
            if ( isset( $vulnerabilities['wordpress'] ) ) {
                $vuln_count += count( $vulnerabilities['wordpress'] );
            }
        }
        // Log the manual scan with readable statistics
        $plugins_checked = 0;
        $themes_checked = 0;
        $wp_version = 'unknown';
        if ( $scan_summary ) {
            $plugins_checked = $scan_summary['plugins']['plugins_checked'] ?? 0;
            $themes_checked = $scan_summary['themes']['themes_checked'] ?? 0;
            $wp_version = $scan_summary['wordpress']['current_version'] ?? 'unknown';
        }
        // Debug: Log detailed breakdown
        $debug_details = array(
            'plugins_checked'       => number_format_i18n( $plugins_checked ),
            'themes_checked'        => number_format_i18n( $themes_checked ),
            'found_vulnerabilities' => number_format_i18n( $vuln_count ),
        );
        wf_sn_el_modules::log_event(
            'security_ninja',
            'vulnerabilities_manual_scan',
            'Manual vulnerability scan',
            array(
                'details' => $debug_details,
            )
        );
        // Build detailed completion message
        $completion_message = '';
        if ( $scan_summary ) {
            $completion_message = sprintf(
                /* translators: %1$s: Number of plugins checked, %2$s: Number of themes checked, %3$s: WordPress version */
                __( 'Scan completed successfully! Checked %1$s plugins, %2$s themes, and WordPress %3$s against the vulnerability database.', 'security-ninja' ),
                number_format_i18n( $scan_summary['plugins']['plugins_checked'] ?? 0 ),
                number_format_i18n( $scan_summary['themes']['themes_checked'] ?? 0 ),
                $scan_summary['wordpress']['current_version'] ?? 'unknown'
            );
            if ( $vuln_count > 0 ) {
                $completion_message .= ' ' . sprintf( 
                    /* translators: %s: Number of vulnerabilities found */
                    _n(
                        'Found %s vulnerability.',
                        'Found %s vulnerabilities.',
                        $vuln_count,
                        'security-ninja'
                    ),
                    number_format_i18n( $vuln_count )
                 );
            } else {
                $completion_message .= ' ' . __( 'No vulnerabilities found.', 'security-ninja' );
            }
        } else {
            $completion_message = sprintf( 
                /* translators: %s: Number of vulnerabilities found */
                _n(
                    'Scan completed. Found %s vulnerability.',
                    'Scan completed. Found %s vulnerabilities.',
                    $vuln_count,
                    'security-ninja'
                ),
                number_format_i18n( $vuln_count )
             );
        }
        // Return success response
        wp_send_json_success( array(
            'message'             => $completion_message,
            'vuln_count'          => $vuln_count,
            'has_vulnerabilities' => $vuln_count > 0,
            'scan_summary'        => $scan_summary,
        ) );
    }

    /**
     * Handle unauthorized AJAX requests for manual vulnerability scan
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @return  void
     */
    public static function handle_manual_vuln_scan_denied() {
        wp_die( esc_html__( 'You do not have permission to perform this action.', 'security-ninja' ) );
    }

    /**
     * Enqueue admin scripts for manual vulnerability scan
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @return  void
     */
    public static function enqueue_admin_scripts() {
        // Only enqueue on Security Ninja admin pages
        if ( !wf_sn::is_plugin_page() ) {
            return;
        }
        // Enqueue the manual scan JavaScript file
        wp_enqueue_script(
            'secnin-manual-vuln-scan',
            plugins_url( 'modules/vulnerabilities/js/min/manual-vuln-scan-min.js', WF_SN_BASE_FILE ),
            array('jquery'),
            wf_sn::$version,
            true
        );
        // Localize script for AJAX URL
        wp_localize_script( 'secnin-manual-vuln-scan', 'secnin_ajax', array(
            'ajaxurl' => admin_url( 'admin-ajax.php' ),
            'nonce'   => wp_create_nonce( 'secnin_manual_vuln_scan' ),
            'strings' => array(
                'scanning'           => __( 'Scanning...', 'security-ninja' ),
                'scanning_for_vulns' => __( 'Scanning for vulnerabilities...', 'security-ninja' ),
                'scan_completed'     => __( 'Scan completed successfully. Reloading the page!', 'security-ninja' ),
                'scan_failed'        => __( 'Scan failed!', 'security-ninja' ),
                'error_occurred'     => __( 'An error occurred during the scan. Please try again.', 'security-ninja' ),
                'run_scan'           => __( 'Run Manual Scan', 'security-ninja' ),
                'downloading'        => __( 'Downloading...', 'security-ninja' ),
                'download_completed' => __( 'Downloaded!', 'security-ninja' ),
                'download_failed'    => __( 'Download Failed', 'security-ninja' ),
            ),
        ) );
    }

    /**
     * Get a summary of the latest vulnerability scan
     * This can be used by other modules to display scan information
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @return  array   Array with scan summary and vulnerability count
     */
    public static function get_scan_summary() {
        $vulnerabilities = self::return_vulnerabilities();
        $scan_summary = get_option( 'wf_sn_scan_summary', false );
        $vuln_count = 0;
        if ( $vulnerabilities ) {
            if ( isset( $vulnerabilities['plugins'] ) ) {
                $vuln_count += count( $vulnerabilities['plugins'] );
            }
            if ( isset( $vulnerabilities['themes'] ) ) {
                $vuln_count += count( $vulnerabilities['themes'] );
            }
            if ( isset( $vulnerabilities['wordpress'] ) ) {
                $vuln_count += count( $vulnerabilities['wordpress'] );
            }
        }
        return array(
            'vulnerabilities'     => $vulnerabilities,
            'scan_summary'        => $scan_summary,
            'vuln_count'          => $vuln_count,
            'has_vulnerabilities' => $vuln_count > 0,
        );
    }

    /**
     * Memory-efficient vulnerability check for themes
     * Processes vulnerability file line by line instead of loading entire file into memory
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @param   array   $installed_themes Array of installed themes
     * @return  array   Array with vulnerabilities and scan statistics
     */
    public static function check_theme_vulnerabilities_memory_efficient( $installed_themes ) {
        $found_vulnerabilities = array();
        $scan_stats = array(
            'themes_checked'         => 0,
            'themes_ignored'         => 0,
            'vulnerabilities_found'  => 0,
            'lines_processed'        => 0,
            'total_themes_installed' => count( $installed_themes ),
        );
        $file_path = self::get_vuln_jsonl_file_path( 'themes' );
        if ( empty( $file_path ) || !is_file( $file_path ) || !is_readable( $file_path ) ) {
            self::ensure_vulns_directory();
            wp_schedule_single_event( time(), 'secnin_update_vuln_list' );
            return array(
                'vulnerabilities' => array(),
                'stats'           => $scan_stats,
            );
        }
        $installed_set = array();
        if ( !empty( $installed_themes ) ) {
            $installed_set = array_fill_keys( array_keys( $installed_themes ), true );
        }
        // Get ignored theme slugs
        $ignored_slugs = array();
        if ( !empty( self::$options['ignored_plugin_slugs'] ) ) {
            $ignored_slugs = array_map( 'trim', explode( "\n", self::$options['ignored_plugin_slugs'] ) );
            $ignored_slugs = array_filter( $ignored_slugs );
            // Remove empty entries
        }
        $ignored_set = array();
        if ( !empty( $ignored_slugs ) ) {
            $ignored_set = array_fill_keys( $ignored_slugs, true );
        }
        foreach ( self::stream_jsonl_records( $file_path ) as $decoded_line ) {
            ++$scan_stats['lines_processed'];
            if ( !isset( $decoded_line['slug'] ) ) {
                continue;
            }
            // Only process if this theme is installed
            $theme_slug = $decoded_line['slug'];
            if ( !isset( $installed_set[$theme_slug] ) ) {
                continue;
            }
            // Skip if this theme is in the ignored list
            if ( isset( $ignored_set[$theme_slug] ) ) {
                ++$scan_stats['themes_ignored'];
                continue;
            }
            // Find the installed theme data
            $installed_theme = ( isset( $installed_themes[$theme_slug] ) ? $installed_themes[$theme_slug] : null );
            if ( !$installed_theme ) {
                continue;
            }
            ++$scan_stats['themes_checked'];
            // Check for vulnerabilities
            $is_vulnerable = false;
            $vulnerability_data = array();
            // Check versionEndExcluding
            if ( isset( $decoded_line['versionEndExcluding'] ) && '' !== $decoded_line['versionEndExcluding'] ) {
                $decoded_line['versionEndExcluding'] = rtrim( $decoded_line['versionEndExcluding'], '.0' );
                if ( version_compare( $installed_theme['Version'], $decoded_line['versionEndExcluding'], '<' ) ) {
                    $is_vulnerable = true;
                    $vulnerability_data = array(
                        'name'                => $installed_theme['Name'],
                        'desc'                => ( isset( $decoded_line['description'] ) ? $decoded_line['description'] : '' ),
                        'installedVersion'    => $installed_theme['Version'],
                        'versionEndExcluding' => $decoded_line['versionEndExcluding'],
                        'CVE_ID'              => $decoded_line['CVE_ID'],
                        'refs'                => ( isset( $decoded_line['refs'] ) ? $decoded_line['refs'] : array() ),
                    );
                }
            }
            if ( $is_vulnerable ) {
                $found_vulnerabilities[$theme_slug] = $vulnerability_data;
                ++$scan_stats['vulnerabilities_found'];
            }
        }
        return array(
            'vulnerabilities' => $found_vulnerabilities,
            'stats'           => $scan_stats,
        );
    }

    /**
     * Generate HTML for displaying vulnerability results
     * This function can be reused across different pages
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 12th, 2024.
     * @param   array   $vulnerabilities Array of found vulnerabilities
     * @param   array   $scan_summary    Optional scan summary statistics
     * @return  string  HTML output for vulnerability display
     */
    public static function generate_vulnerability_display( $vulnerabilities, $scan_summary = null ) {
        global $wp_version;
        $output = '';
        // Check if any vulnerabilities were found
        $has_vulnerabilities = false;
        if ( $vulnerabilities ) {
            if ( isset( $vulnerabilities['plugins'] ) && !empty( $vulnerabilities['plugins'] ) ) {
                $has_vulnerabilities = true;
            }
            if ( isset( $vulnerabilities['themes'] ) && !empty( $vulnerabilities['themes'] ) ) {
                $has_vulnerabilities = true;
            }
            if ( isset( $vulnerabilities['wordpress'] ) && !empty( $vulnerabilities['wordpress'] ) ) {
                $has_vulnerabilities = true;
            }
        }
        if ( $has_vulnerabilities ) {
            $output .= '<h2 class="warning"><span class="dashicons dashicons-sos"></span>' . esc_html__( 'Vulnerabilities found on your system!', 'security-ninja' ) . '</h2>';
            // Display WordPress vulnerabilities
            if ( isset( $vulnerabilities['wordpress'] ) && !empty( $vulnerabilities['wordpress'] ) ) {
                $get_wp_ver_status = self::get_wp_ver_status();
                $wp_status = '';
                if ( isset( $get_wp_ver_status->{$wp_version} ) ) {
                    if ( 'insecure' === $get_wp_ver_status->{$wp_version} ) {
                        $wp_status = sprintf( 
                            /* translators: %s: WordPress version */
                            __( 'This version of WordPress (%1$s) is considered %2$s. You should upgrade as soon as possible.', 'security-ninja' ),
                            $wp_version,
                            '<strong>' . esc_html__( 'INSECURE', 'security-ninja' ) . '</strong>'
                         );
                    }
                    if ( 'outdated' === $get_wp_ver_status->{$wp_version} ) {
                        $wp_status = sprintf( 
                            /* translators: %s: WordPress version */
                            __( 'This version of WordPress (%1$s) is considered %2$s. You should upgrade as soon as possible.', 'security-ninja' ),
                            $wp_version,
                            '<strong>' . esc_html__( 'OUTDATED', 'security-ninja' ) . '</strong>'
                         );
                    }
                }
                $output .= '<div class="vuln vulnwordpress">';
                $output .= '<p>' . sprintf( 
                    /* translators: %s: WordPress version */
                    esc_html__( 'You are running WordPress version %s and there are known vulnerabilities that have been fixed in later versions. You should upgrade WordPress as soon as possible.', 'security-ninja' ),
                    esc_html( $wp_version )
                 ) . '</p>';
                if ( '' !== $wp_status ) {
                    $output .= '<div class="vulnrecommendation"><h2>' . wp_kses_post( $wp_status ) . '</h2></div>';
                }
                $output .= '<p>' . esc_html__( 'Known vulnerabilities', 'security-ninja' ) . '</p>';
                foreach ( $vulnerabilities['wordpress'] as $key => $wpvuln ) {
                    if ( isset( $wpvuln['versionEndExcluding'] ) ) {
                        $output .= '<h3><span class="dashicons dashicons-warning"></span> ' . esc_html( 'WordPress ' . $wpvuln['CVE_ID'] ) . '</h3>';
                        $output .= '<div class="wrap-collabsible">';
                        $output .= '<input id="collapsible-' . esc_attr( $key ) . '" class="toggle" type="checkbox">';
                        $output .= '<label for="collapsible-' . esc_attr( $key ) . '" class="lbl-toggle">' . esc_html__( 'Details', 'security-ninja' ) . '</label>';
                        $output .= '<div class="collapsible-content">';
                        $output .= '<div class="content-inner">';
                        if ( isset( $wpvuln['desc'] ) && '' !== $wpvuln['desc'] ) {
                            $output .= '<p class="vulndesc">' . esc_html( $wpvuln['desc'] ) . '</p>';
                        }
                        $output .= '<p class="vulnDetails">' . sprintf( 
                            /* translators: 1: WordPress version */
                            esc_html__( 'Fixed in WordPress version %1$s', 'security-ninja' ),
                            esc_attr( $wpvuln['versionEndExcluding'] )
                         ) . '</p>';
                        if ( isset( $wpvuln['CVE_ID'] ) && '' !== $wpvuln['CVE_ID'] ) {
                            $output .= '<p><span class="nvdlink">' . sprintf(
                                /* translators: %s: CVE ID */
                                esc_html__( 'More details: %1$sRead more about %2$s%3$s%4$s', 'security-ninja' ),
                                '<a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $wpvuln['CVE_ID'] ) . '" target="_blank" rel="noopener">',
                                esc_html( $wpvuln['CVE_ID'] ),
                                '</a>'
                            ) . '</span></p>';
                        }
                        $output .= '</div></div></div>';
                    }
                }
                $output .= '</div>';
            }
            // Display plugin vulnerabilities
            if ( isset( $vulnerabilities['plugins'] ) && !empty( $vulnerabilities['plugins'] ) ) {
                $output .= '<p>' . esc_html__( 'You should upgrade to latest version or find a different plugin as soon as possible.', 'security-ninja' ) . '</p>';
                foreach ( $vulnerabilities['plugins'] as $key => $found_vuln ) {
                    $output .= '<div class="sncard vulnplugin snerror">';
                    $output .= '<h3><span class="dashicons dashicons-warning"></span>';
                    $output .= sprintf( 
                        /* translators: %1$s: Plugin name, %2$s: Plugin version */
                        esc_html__( 'Plugin: %1$s %2$s', 'security-ninja' ),
                        '<span class="plugin-name">' . esc_html( $found_vuln['name'] ) . '</span>',
                        '<span class="ver">v. ' . esc_html( $found_vuln['installedVersion'] ) . '</span>'
                     );
                    $output .= '</h3>';
                    if ( isset( $found_vuln['versionEndExcluding'] ) ) {
                        $searchurl = admin_url( 'plugins.php?s=' . rawurlencode( $found_vuln['name'] ) . '&plugin_status=all' );
                        $output .= '<div class="vulnrecommendation"><p>';
                        $output .= sprintf(
                            wp_kses( 
                                // translators: %1$s: URL for the update, %2$s: Plugin name, %3$s: Minimum version required
                                __( 'Update %2$s to minimum version %3$s <a href="%1$s">here</a>', 'security-ninja' ),
                                array(
                                    'a' => array(
                                        'href' => array(),
                                    ),
                                )
                             ),
                            esc_url( $searchurl ),
                            esc_html( $found_vuln['name'] ),
                            esc_html( $found_vuln['versionEndExcluding'] )
                        );
                        $output .= '</p></div>';
                    }
                    // Always show details section if we have any vulnerability information
                    $has_details = false;
                    if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                        $has_details = true;
                    }
                    if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                        $has_details = true;
                    }
                    if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                        $has_details = true;
                    }
                    if ( $has_details ) {
                        $output .= '<div class="wrap-collabsible">';
                        $output .= '<input id="collapsible-' . esc_attr( $key ) . '" class="toggle" type="checkbox">';
                        $output .= '<label for="collapsible-' . esc_attr( $key ) . '" class="lbl-toggle">' . esc_html__( 'Details', 'security-ninja' ) . '</label>';
                        $output .= '<div class="collapsible-content">';
                        $output .= '<div class="content-inner">';
                        if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                            $output .= '<p class="vulndesc">' . wp_kses_post( $found_vuln['desc'] ) . '</p>';
                        }
                        if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                            $refs = json_decode( $found_vuln['refs'] );
                            if ( is_array( $refs ) ) {
                                $output .= '<h4>' . esc_html__( 'Read more:', 'security-ninja' ) . '</h4><ul>';
                                if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                                    $output .= '<li><a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] ) . '" target="_blank" class="exlink" rel="noopener">' . esc_attr( $found_vuln['CVE_ID'] ) . '</a></li>';
                                }
                                foreach ( $refs as $ref ) {
                                    $output .= '<li><a href="' . esc_url( $ref->url ) . '" target="_blank" class="exlink" rel="noopener">' . esc_html( self::remove_http( $ref->name ) ) . '</a></li>';
                                }
                                $output .= '</ul>';
                            }
                        } elseif ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                            // Show CVE link even if no other references
                            $output .= '<h4>' . esc_html__( 'Read more:', 'security-ninja' ) . '</h4><ul>';
                            $output .= '<li><a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] ) . '" target="_blank" class="exlink" rel="noopener">' . esc_attr( $found_vuln['CVE_ID'] ) . '</a></li>';
                            $output .= '</ul>';
                        }
                        $output .= '</div></div></div>';
                    }
                    $output .= '</div>';
                }
            }
            // Display theme vulnerabilities
            if ( isset( $vulnerabilities['themes'] ) && !empty( $vulnerabilities['themes'] ) ) {
                $output .= '<p>' . esc_html__( 'Warning - Vulnerable themes found! Note: comparison is made by folder name. Please verify the theme before deleting.', 'security-ninja' ) . '</p>';
                foreach ( $vulnerabilities['themes'] as $key => $found_vuln ) {
                    $output .= '<div class="sncard vulnplugin snerror">';
                    $output .= '<h3><span class="dashicons dashicons-warning"></span>';
                    $output .= sprintf( 
                        /* translators: %1$s: Theme name, %2$s: Theme version */
                        esc_html__( 'Theme: %1$s %2$s', 'security-ninja' ),
                        '<span class="theme-name">' . esc_html( $found_vuln['name'] ) . '</span>',
                        '<span class="ver">v. ' . esc_html( $found_vuln['installedVersion'] ) . '</span>'
                     );
                    $output .= '</h3>';
                    if ( isset( $found_vuln['versionEndExcluding'] ) ) {
                        $searchurl = admin_url( 'themes.php' );
                        $output .= '<div class="vulnrecommendation"><p>';
                        $output .= sprintf(
                            // translators: %1$s: URL for the update, %2$s: Theme name, %3$s: Minimum version required
                            __( 'Update %2$s to minimum version %3$s. You can do it %1$s.', 'security-ninja' ),
                            '<a href="' . esc_url( $searchurl ) . '">' . esc_html__( 'here', 'security-ninja' ) . '</a>',
                            esc_html( $found_vuln['name'] ),
                            esc_html( $found_vuln['versionEndExcluding'] )
                        );
                        $output .= '</p></div>';
                    }
                    // Always show details section if we have any vulnerability information
                    $has_details = false;
                    if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                        $has_details = true;
                    }
                    if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                        $has_details = true;
                    }
                    if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                        $has_details = true;
                    }
                    if ( $has_details ) {
                        $output .= '<div class="wrap-collabsible">';
                        $output .= '<input id="collapsible-' . esc_attr( $key ) . '" class="toggle" type="checkbox">';
                        $output .= '<label for="collapsible-' . esc_attr( $key ) . '" class="lbl-toggle">' . esc_html__( 'Details', 'security-ninja' ) . '</label>';
                        $output .= '<div class="collapsible-content">';
                        $output .= '<div class="content-inner">';
                        if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                            $output .= '<p class="vulndesc">' . esc_html( $found_vuln['desc'] ) . '</p>';
                        }
                        if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                            $refs = json_decode( $found_vuln['refs'] );
                            if ( is_array( $refs ) ) {
                                $output .= '<h4>' . esc_html__( 'Read more:', 'security-ninja' ) . '</h4><ul>';
                                if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                                    $output .= '<li><a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] ) . '" target="_blank" class="exlink" rel="noopener">' . esc_attr( $found_vuln['CVE_ID'] ) . '</a></li>';
                                }
                                foreach ( $refs as $ref ) {
                                    $output .= '<li><a href="' . esc_url( $ref->url ) . '" target="_blank" class="exlink" rel="noopener">' . esc_html( self::remove_http( $ref->name ) ) . '</a></li>';
                                }
                                $output .= '</ul>';
                            }
                        } elseif ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                            // Show CVE link even if no other references
                            $output .= '<h4>' . esc_html__( 'Read more:', 'security-ninja' ) . '</h4><ul>';
                            $output .= '<li><a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] ) . '" target="_blank" class="exlink" rel="noopener">' . esc_attr( $found_vuln['CVE_ID'] ) . '</a></li>';
                            $output .= '</ul>';
                        }
                        $output .= '</div></div></div>';
                    }
                    $output .= '</div>';
                }
            }
        } else {
            // No vulnerabilities found
            $output .= '<div class="noerrorsfound">';
            $output .= '<h3>' . esc_html__( 'Great news!', 'security-ninja' ) . '</h3>';
            $output .= '<p>' . esc_html__( 'No vulnerabilities found.', 'security-ninja' ) . '</p>';
            $output .= '</div>';
            // Show scan summary if available
            if ( $scan_summary ) {
                $output .= '<p>' . sprintf(
                    /* translators: %1$s: Number of plugins checked, %2$s: Number of themes checked, %3$s: WordPress version */
                    esc_html__( 'Scan completed: %1$s plugins, %2$s themes, WordPress %3$s checked against vulnerability database.', 'security-ninja' ),
                    number_format_i18n( $scan_summary['plugins']['plugins_checked'] ?? 0 ),
                    number_format_i18n( $scan_summary['themes']['themes_checked'] ?? 0 ),
                    $scan_summary['wordpress']['current_version'] ?? 'unknown'
                ) . '</p>';
            }
        }
        return $output;
    }

    /**
     * Handle AJAX request to download all vulnerability files
     *
     * @author  Lars Koudal
     * @since   v1.0.1
     * @version v1.0.0  Tuesday, June 11th, 2024.
     * @access  public static
     * @return  void
     */
    public static function handle_download_all_vuln_files() {
        // Verify nonce
        if ( !wp_verify_nonce( $_POST['nonce'], 'secnin_manual_vuln_scan' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Security check failed.', 'security-ninja' ),
            ) );
        }
        // Check user permissions
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'You do not have permission to perform this action.', 'security-ninja' ),
            ) );
        }
        $success_count = 0;
        $error_count = 0;
        $errors = array();
        // Download all vulnerability files using conditional GET.
        foreach ( self::$api_urls as $file_type => $api_url ) {
            $result = self::download_vuln_file_with_conditional_get( $file_type, $api_url );
            if ( $result && isset( $result['success'] ) && $result['success'] ) {
                ++$success_count;
            } else {
                ++$error_count;
                /* translators: %s: Vulnerability type */
                $errors[] = sprintf( __( 'Failed to download %s data.', 'security-ninja' ), ucfirst( $file_type ) );
            }
        }
        if ( $success_count > 0 && $error_count === 0 ) {
            // All files downloaded successfully
            wp_send_json_success( array(
                'message' => __( 'All vulnerability files downloaded successfully.', 'security-ninja' ),
            ) );
        } elseif ( $success_count > 0 && $error_count > 0 ) {
            // Some files downloaded, some failed
            wp_send_json_success( array(
                'message' => sprintf(
                    /* translators: %1$d: Number of files downloaded, %2$d: Number of files failed, %3$s: List of failed files */
                    __( 'Downloaded %1$d files successfully. %2$d files failed: %3$s', 'security-ninja' ),
                    $success_count,
                    $error_count,
                    implode( ', ', $errors )
                ),
            ) );
        } else {
            // All files failed
            wp_send_json_error( array(
                'message' => sprintf( 
                    /* translators: %s: Vulnerability type */
                    __( 'Failed to download vulnerability files: %s', 'security-ninja' ),
                    implode( ', ', $errors )
                 ),
            ) );
        }
    }

}

// hook everything up
add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\Wf_Sn_Vu', 'init') );
// when deativated clean up
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\Wf_Sn_Vu', 'deactivate') );