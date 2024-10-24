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
        add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\wf_sn_vu', 'sn_tabs') );
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
    }

    /**
     * daily_vulnerability_check.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Friday, June 7th, 2024.
     * @return	void
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
     * Register settings on admin init
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @return  void
     */
    public static function admin_init() {
        register_setting( 'wf_sn_vu_settings_group', 'wf_sn_vu_settings_group', array(__NAMESPACE__ . '\\wf_sn_vu', 'sanitize_settings') );
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
            $return_vuln_count = self::return_vuln_count();
            if ( $return_vuln_count ) {
                $vuln_tab['count'] = $return_vuln_count;
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
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, July 25th, 2023.
     * @version v1.0.1  Friday, October 13th, 2023.
     * @param   mixed   $file_content
     * @param   mixed   $filename
     * @return  boolean
     */
    public static function get_file_and_save( $file_content, $filename ) {
        if ( empty( $file_content ) || empty( $filename ) ) {
            return false;
        }
        require_once ABSPATH . 'wp-admin/includes/file.php';
        $url = wp_nonce_url( 'plugins.php' );
        $creds = request_filesystem_credentials(
            $url,
            '',
            false,
            false,
            null
        );
        if ( !$creds ) {
            return false;
            // Failed to get credentials
        }
        if ( !WP_Filesystem( $creds ) ) {
            return false;
            // Failed to initialize the filesystem
        }
        global $wp_filesystem;
        $upload_dir = wp_upload_dir();
        $dir_path = $upload_dir['basedir'] . '/security-ninja/vulns/';
        // Ensure the directory exists
        if ( !$wp_filesystem->is_dir( $dir_path ) && !$wp_filesystem->mkdir( $dir_path, FS_CHMOD_DIR, true ) ) {
            // Log failure to create directory
            return false;
        }
        $file_path = $dir_path . sanitize_file_name( $filename );
        $result = $wp_filesystem->put_contents( $file_path, $file_content, FS_CHMOD_FILE );
        if ( false === $result ) {
            return false;
        }
        add_option( 'wf_sn_vu_outdated', time() );
        return true;
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
        $oldcount = false;
        $newcount = false;
        $old_data = self::load_vulnerabilities();
        $oldcount = 0;
        if ( $old_data ) {
            $oldcount = self::return_known_vuln_count();
        }
        foreach ( self::$api_urls as $type => $url ) {
            $compressed_request_url = add_query_arg( 'ver', wf_sn::$version, $url . '.gz' );
            $response = wp_safe_remote_get( $compressed_request_url );
            if ( !is_wp_error( $response ) ) {
                $headers = wp_remote_retrieve_headers( $response );
                if ( isset( $headers['content-encoding'] ) && strtolower( $headers['content-encoding'] ) === 'gzip' ) {
                    $compressed_body = wp_remote_retrieve_body( $response );
                    $decompressed_content = gzdecode( $compressed_body );
                    if ( false !== $decompressed_content ) {
                        self::get_file_and_save( $decompressed_content, "{$type}_vulns.jsonl" );
                        continue;
                    } else {
                    }
                }
            } else {
                $error_message = $response->get_error_message();
                wf_sn_el_modules::log_event( 'security_ninja', 'vulnerabilities_update', sprintf( __( 'Failed to retrieve response: %s', 'security-ninja' ), $error_message ) );
            }
            // If the compressed version doesn't work or is not valid, try the regular URL
            $response = wp_safe_remote_get( add_query_arg( 'ver', wf_sn::$version, $url ) );
            if ( !is_wp_error( $response ) ) {
                $body = wp_remote_retrieve_body( $response );
                if ( $body ) {
                    // Save the content from the regular URL
                    self::get_file_and_save( $body, "{$type}_vulns.jsonl" );
                }
            }
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
                $update_emoji = '🛡️';
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
                        esc_html__( '%1$s Now tracking a total of %2$s known vulnerabilities. Last checked: %3$s. Update or replace vulnerable plugins promptly.', 'security-ninja' ),
                        $update_emoji,
                        esc_html( number_format_i18n( $newcount ) ),
                        esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $old_data->timestamp ) )
                    ) : '' );
                } else {
                    // If no timestamp is available, keep it simple but informative
                    $message .= ' ' . sprintf( 
                        // Translators:
                        esc_html__( '%1$s Now tracking a total of %2$s known vulnerabilities. Ensure your plugins are secure.', 'security-ninja' ),
                        $update_emoji,
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
        // HTML formatted message content
        $message_content_html = '<p>' . esc_html__( 'You are receiving this email because you have activated email warnings for the vulnerability scanner.', 'security-ninja' ) . '</p>';
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
                Wf_Sn_El_Modules::log_event( 'security_ninja', 'vulnerabilities', sprintf( __( 'Email not sent to %s. Error: %s', 'security-ninja' ), esc_html( $recipient ), esc_html( $error_message ) ) );
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
        // Note - transient is deleted when updating settings.
        //if (false === ($found_vulnerabilities = get_transient('wf_sn_return_vulnerabilities'))) {
        global $wp_version;
        $vuln_plugin_arr = false;
        $installed_plugins = false;
        if ( self::$options['enable_vulns'] ) {
            $vulns = self::load_vulnerabilities();
            if ( !$vulns ) {
                self::update_vuln_list();
                $vulns = self::load_vulnerabilities();
            }
            // offers problem here on free version? memory issue, maxes out 256mb
            $vuln_plugin_arr = self::object_to_array( $vulns->plugins );
            $installed_plugins = get_plugins();
        }
        // Tests for plugin problems
        if ( $installed_plugins && $vuln_plugin_arr ) {
            $found_vulnerabilities = array();
            foreach ( $installed_plugins as $key => $ap ) {
                $lookup_id = strtok( $key, '/' );
                $findplugin = array_search( $lookup_id, array_column( $vuln_plugin_arr, 'slug' ), true );
                if ( $findplugin ) {
                    if ( isset( $vuln_plugin_arr[$findplugin]['versionEndExcluding'] ) && '' !== $vuln_plugin_arr[$findplugin]['versionEndExcluding'] ) {
                        // check #1 - versionEndExcluding
                        if ( version_compare( $ap['Version'], $vuln_plugin_arr[$findplugin]['versionEndExcluding'], '<' ) ) {
                            $description = '';
                            if ( isset( $vuln_plugin_arr[$findplugin]['description'] ) ) {
                                $description = $vuln_plugin_arr[$findplugin]['description'];
                            }
                            $found_vulnerabilities['plugins'][$lookup_id] = array(
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
                            $found_vulnerabilities['plugins'][$lookup_id] = array(
                                'name'             => $ap['Name'],
                                'desc'             => $vuln_plugin_arr[$findplugin]['description'],
                                'installedVersion' => $ap['Version'],
                                'versionImpact'    => $vuln_plugin_arr[$findplugin]['versionImpact'],
                                'CVE_ID'           => $vuln_plugin_arr[$findplugin]['CVE_ID'],
                                'refs'             => $vuln_plugin_arr[$findplugin]['refs'],
                            );
                            if ( isset( $vuln_plugin_arr[$findplugin]['recommendation'] ) ) {
                                $found_vulnerabilities['plugins'][$lookup_id]['recommendation'] = $vuln_plugin_arr[$findplugin]['recommendation'];
                            }
                        }
                    }
                }
            }
        }
        // ------------ Find WordPress vulnerabilities ------------
        $wordpressarr = false;
        if ( isset( $vulns->wordpress ) ) {
            $wordpressarr = self::object_to_array( $vulns->wordpress );
        }
        $lookup_id = 0;
        if ( $wordpressarr ) {
            foreach ( $wordpressarr as $key => $wpvuln ) {
                $wpvuln['versionEndExcluding'] = rtrim( $wpvuln['versionEndExcluding'], '.0' );
                // Trim trailing .0s for comparing
                if ( version_compare( $wp_version, $wpvuln['versionEndExcluding'], '<' ) ) {
                    $desc = '';
                    if ( isset( $wpvuln['description'] ) ) {
                        $desc = $wpvuln['description'];
                    }
                    $found_vulnerabilities['wordpress'][$lookup_id] = array(
                        'desc'                => $desc,
                        'versionEndExcluding' => $wpvuln['versionEndExcluding'],
                        'CVE_ID'              => $wpvuln['CVE_ID'],
                    );
                    if ( isset( $wpvuln['recommendation'] ) ) {
                        $found_vulnerabilities['wordpress'][$lookup_id]['recommendation'] = $wpvuln['recommendation'];
                    }
                    ++$lookup_id;
                }
            }
        }
        // Find vulnerable themes
        // Build new empty Array to store the themes
        $themes = array();
        // Loads theme data
        $all_themes = wp_get_themes();
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
        $vuln_theme_arr = false;
        if ( isset( $vulns->themes ) ) {
            $vuln_theme_arr = self::object_to_array( $vulns->themes );
        }
        if ( $themes && $vuln_theme_arr ) {
            foreach ( $themes as $key => $ap ) {
                $findtheme = array_search( $key, array_column( $vuln_theme_arr, 'slug' ), true );
                if ( false !== $findtheme ) {
                    // $Matched theme array with details
                    $matched = $vuln_theme_arr[$findtheme];
                    if ( isset( $matched['versionEndExcluding'] ) && '' !== $vuln_theme_arr[$findtheme]['versionEndExcluding'] ) {
                        $matched['versionEndExcluding'] = rtrim( $matched['versionEndExcluding'], '.0' );
                        if ( version_compare( $ap['Version'], $matched['versionEndExcluding'], '<' ) ) {
                            $desc = '';
                            if ( isset( $matched['description'] ) ) {
                                $desc = $matched['description'];
                            }
                            $found_vulnerabilities['themes'][$key] = array(
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
            // 2 - Lookup child themes (look by Template value) @todo!
        }
        if ( isset( $found_vulnerabilities ) ) {
            return $found_vulnerabilities;
        } else {
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
        $vulns = self::load_vulnerabilities();
        if ( !$vulns ) {
            return 0;
        }
        $plugin_vulns_count = self::count_vulns( $vulns->plugins );
        $theme_vulns_count = self::count_vulns( $vulns->themes );
        $wp_vulns_count = self::count_vulns( $vulns->wordpress );
        $total_vulnerabilities = $plugin_vulns_count + $theme_vulns_count + $wp_vulns_count;
        return $total_vulnerabilities;
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
            $vulns = self::load_vulnerabilities();
            if ( !$vulns ) {
                self::update_vuln_list();
                $vulns = self::load_vulnerabilities();
            }
            $plugin_vulns_count = count( $vulns->plugins );
            $theme_vulns_count = count( $vulns->themes );
            $wp_vulns_count = count( $vulns->wordpress );
            $total_vulnerabilities = $plugin_vulns_count + $wp_vulns_count + $theme_vulns_count;
            // Used for the output of WordPress version being used
            $wp_status = '';
        }
        ?>
		<div class="submit-test-container">
			<div class="card">
				<h3><?php 
        esc_html_e( 'Vulnerability Scanner', 'security-ninja' );
        ?></h3>
				<p><?php 
        echo esc_html__( 'Warns you of any known vulnerabilities in the plugins and themes you have installed.', 'security-ninja' );
        ?></p>
				<?php 
        if ( isset( $vulnerabilities['wordpress'] ) || isset( $vulnerabilities['plugins'] ) || isset( $vulnerabilities['themes'] ) ) {
            ?>
					<h2><?php 
            esc_html_e( 'Vulnerabilities found on your system!', 'security-ninja' );
            ?></h2>

					<?php 
            if ( isset( $vulnerabilities['wordpress'] ) ) {
                $get_wp_ver_status = self::get_wp_ver_status();
                if ( isset( $get_wp_ver_status->{$wp_version} ) ) {
                    if ( 'insecure' === $get_wp_ver_status->{$wp_version} ) {
                        $wp_status = sprintf( 
                            /* translators: %s: WordPress version */
                            __( 'This version of WordPress (%s) is considered %s. You should upgrade as soon as possible.', 'security-ninja' ),
                            $wp_version,
                            '<strong>' . esc_html__( 'INSECURE', 'security-ninja' ) . '</strong>'
                         );
                    }
                    if ( 'outdated' === $get_wp_ver_status->{$wp_version} ) {
                        $wp_status = sprintf( 
                            /* translators: %s: WordPress version */
                            __( 'This version of WordPress (%s) is considered %s. You should upgrade as soon as possible.', 'security-ninja' ),
                            $wp_version,
                            '<strong>' . esc_html__( 'OUTDATED', 'security-ninja' ) . '</strong>'
                         );
                    }
                }
                ?>
						<div class="vuln vulnwordpress">
							<p>
								<?php 
                printf( 
                    /* translators: %s: WordPress version */
                    esc_html__( 'You are running WordPress version %s and there are known vulnerabilities that have been fixed in later versions. You should upgrade WordPress as soon as possible.', 'security-ninja' ),
                    esc_html( $wp_version )
                 );
                ?>
							</p>
							<?php 
                if ( '' !== $wp_status ) {
                    ?>
								<div class="vulnrecommendation">
									<h2>
										<?php 
                    echo wp_kses_post( $wp_status );
                    ?>
									</h2>
								</div>
							<?php 
                }
                ?>

							<p><?php 
                esc_html_e( 'Known vulnerabilities', 'security-ninja' );
                ?></p>

							<?php 
                foreach ( $vulnerabilities['wordpress'] as $key => $wpvuln ) {
                    if ( isset( $wpvuln['versionEndExcluding'] ) ) {
                        ?>
									<h3><span class="dashicons dashicons-warning"></span> <?php 
                        echo esc_html( 'WordPress ' . $wpvuln['CVE_ID'] );
                        ?></h3>
									<div class="wrap-collabsible">
										<input id="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="toggle" type="checkbox">
										<label for="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="lbl-toggle"><?php 
                        esc_html_e( 'Details', 'security-ninja' );
                        ?></label>
										<div class="collapsible-content">
											<div class="content-inner">
												<?php 
                        if ( isset( $wpvuln['desc'] ) && '' !== $wpvuln['desc'] ) {
                            ?>
													<p class="vulndesc"><?php 
                            echo esc_html( $wpvuln['desc'] );
                            ?></p>
												<?php 
                        }
                        ?>
												<p class="vulnDetails">
													<?php 
                        printf( 
                            /* translators: 1: WordPress version */
                            esc_html__( 'Fixed in WordPress version %1$s', 'security-ninja' ),
                            esc_attr( $wpvuln['versionEndExcluding'] )
                         );
                        ?>
												</p>
												<?php 
                        if ( isset( $wpvuln['CVE_ID'] ) && '' !== $wpvuln['CVE_ID'] ) {
                            ?>
													<p><span class="nvdlink">
															<?php 
                            printf(
                                /* translators: %s: CVE ID */
                                esc_html__( 'More details: %1$sRead more about %2$s%3$s%4$s', 'security-ninja' ),
                                '<a href="' . esc_url( 'https://nvd.nist.gov/vuln/detail/' . $wpvuln['CVE_ID'] ) . '" target="_blank" rel="noopener">',
                                esc_html( $wpvuln['CVE_ID'] ),
                                '</a>'
                            );
                            ?>
														</span></p>
												<?php 
                        }
                        ?>
											</div>
										</div>
									</div>
							<?php 
                    }
                }
                ?>
						</div><!-- .vuln vulnwordpress -->
					<?php 
            }
            // display list of vulns in plugins
            if ( isset( $vulnerabilities['plugins'] ) ) {
                ?>
						<p><?php 
                esc_html_e( 'You should upgrade to latest version or find a different plugin as soon as possible.', 'security-ninja' );
                ?></p>
						<?php 
                foreach ( $vulnerabilities['plugins'] as $key => $found_vuln ) {
                    ?>
							<div class="card vulnplugin">
								<h3>
									<span class="dashicons dashicons-warning"></span>
									<?php 
                    printf( 
                        /* translators: %1$s: Plugin name, %2$s: Plugin version */
                        esc_html__( 'Plugin: %1$s %2$s', 'security-ninja' ),
                        '<span class="plugin-name">' . esc_html( $found_vuln['name'] ) . '</span>',
                        '<span class="ver">v. ' . esc_html( $found_vuln['installedVersion'] ) . '</span>'
                     );
                    ?>
								</h3>
								<?php 
                    if ( isset( $found_vuln['versionEndExcluding'] ) ) {
                        $searchurl = admin_url( 'plugins.php?s=' . rawurlencode( $found_vuln['name'] ) . '&plugin_status=all' );
                        ?>
									<div class="vulnrecommendation">
										<p>
											<?php 
                        $searchurl = filter_var( $searchurl, FILTER_SANITIZE_URL );
                        printf( wp_kses( 
                            // translators: %1$s: URL for the update, %2$s: Plugin name, %3$s: Minimum version required
                            __( 'Update %2$s to minimum version %3$s', 'security-ninja' ),
                            array(
                                'a' => array(
                                    'href' => array(),
                                ),
                            )
                         ) . ' <a href="' . esc_url( $searchurl ) . '">' . esc_html__( 'here', 'security-ninja' ) . '</a>', esc_html( $found_vuln['name'] ), esc_html( $found_vuln['versionEndExcluding'] ) );
                        ?>
										</p>
									</div>
								<?php 
                    } elseif ( isset( $found_vuln['recommendation'] ) && '' !== $found_vuln['recommendation'] ) {
                        ?>
									<div class="vulnrecommendation">
										<p><strong><?php 
                        echo wp_kses_post( $found_vuln['recommendation'] );
                        ?></strong></p>
									</div>
								<?php 
                    }
                    if ( isset( $found_vuln['desc'] ) || isset( $found_vuln['refs'] ) ) {
                        ?>
									<div class="wrap-collabsible">
										<input id="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="toggle" type="checkbox">
										<label for="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="lbl-toggle"><?php 
                        esc_html_e( 'Details', 'security-ninja' );
                        ?></label>
										<div class="collapsible-content">
											<div class="content-inner">
												<?php 
                        if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                            ?>
													<p class="vulndesc"><?php 
                            echo wp_kses_post( $found_vuln['desc'] );
                            ?></p>
													<?php 
                        }
                        if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                            $refs = json_decode( $found_vuln['refs'] );
                            if ( is_array( $refs ) ) {
                                ?>
														<h4><?php 
                                esc_html_e( 'Read more:', 'security-ninja' );
                                ?></h4>
														<ul>
															<?php 
                                if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                                    ?>
																<li><a href="<?php 
                                    echo esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] );
                                    ?>" target="_blank" class="exlink" rel="noopener"><?php 
                                    echo esc_attr( $found_vuln['CVE_ID'] );
                                    ?></a></li>
															<?php 
                                }
                                foreach ( $refs as $ref ) {
                                    ?>
																<li><a href="<?php 
                                    echo esc_url( $ref->url );
                                    ?>" target="_blank" class="exlink" rel="noopener"><?php 
                                    echo esc_html( self::remove_http( $ref->name ) );
                                    ?></a></li>
															<?php 
                                }
                                ?>
														</ul>
												<?php 
                            }
                        }
                        ?>
											</div>
										</div>
									</div>
								<?php 
                    }
                    ?>
							</div><!-- .vuln .vulnplugin -->
						<?php 
                }
            }
            // end plugins
            // display list of vulns in themes
            if ( isset( $vulnerabilities['themes'] ) ) {
                ?>

						<p><?php 
                esc_html_e( 'Warning - Vulnerable themes found! Note: comparison is made by folder name. Please verify the theme before deleting.', 'security-ninja' );
                ?></p>

						<?php 
                foreach ( $vulnerabilities['themes'] as $key => $found_vuln ) {
                    ?>
							<div class="card vulnplugin">
								<h3>
									<span class="dashicons dashicons-warning"></span>
									<?php 
                    printf( 
                        /* translators: %1$s: Theme name, %2$s: Theme version */
                        esc_html__( 'Theme: %1$s %2$s', 'security-ninja' ),
                        '<span class="theme-name">' . esc_html( $found_vuln['name'] ) . '</span>',
                        '<span class="ver">v. ' . esc_html( $found_vuln['installedVersion'] ) . '</span>'
                     );
                    ?>
								</h3>

								<?php 
                    if ( isset( $found_vuln['versionEndExcluding'] ) ) {
                        $searchurl = admin_url( 'plugins.php?s=' . rawurlencode( $found_vuln['name'] ) . '&plugin_status=all' );
                        ?>
									<div class="vulnrecommendation">
										<p>
											<?php 
                        $searchurl = filter_var( $searchurl, FILTER_SANITIZE_URL );
                        printf(
                            // translators: %1$s: URL for the update, %2$s: Plugin name, %3$s: Minimum version required
                            __( 'Update %2$s to minimum version %3$s. You can do it %1$s.', 'security-ninja' ),
                            '<a href="' . esc_url( $searchurl ) . '">' . esc_html__( 'here', 'security-ninja' ) . '</a>',
                            esc_html( $found_vuln['name'] ),
                            esc_html( $found_vuln['versionEndExcluding'] )
                        );
                        ?>
										</p>
									</div>
								<?php 
                    } elseif ( isset( $found_vuln['recommendation'] ) && '' !== $found_vuln['recommendation'] ) {
                        ?>
									<div class="vulnrecommendation">
										<p><strong><?php 
                        echo esc_html( $found_vuln['recommendation'] );
                        ?></strong></p>
									</div>
								<?php 
                    }
                    if ( isset( $found_vuln['desc'] ) || isset( $found_vuln['refs'] ) ) {
                        ?>
									<div class="wrap-collabsible">
										<input id="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="toggle" type="checkbox">
										<label for="collapsible-<?php 
                        echo esc_attr( $key );
                        ?>" class="lbl-toggle"><?php 
                        esc_html_e( 'Details', 'security-ninja' );
                        ?></label>
										<div class="collapsible-content">
											<div class="content-inner">
												<?php 
                        if ( isset( $found_vuln['desc'] ) && '' !== $found_vuln['desc'] ) {
                            ?>
													<p class="vulndesc"><?php 
                            echo esc_html( $found_vuln['desc'] );
                            ?></p>
												<?php 
                        }
                        ?>
												<?php 
                        if ( isset( $found_vuln['refs'] ) && '' !== $found_vuln['refs'] ) {
                            $refs = json_decode( $found_vuln['refs'] );
                            if ( is_array( $refs ) ) {
                                ?>
														<h4><?php 
                                esc_html_e( 'Read more', 'security-ninja' );
                                ?>:</h4>
														<ul>
															<?php 
                                if ( isset( $found_vuln['CVE_ID'] ) && '' !== $found_vuln['CVE_ID'] ) {
                                    ?>
																<li><a href="<?php 
                                    echo esc_url( 'https://nvd.nist.gov/vuln/detail/' . $found_vuln['CVE_ID'] );
                                    ?>" target="_blank" class="exlink" rel="noopener"><?php 
                                    echo esc_attr( $found_vuln['CVE_ID'] );
                                    ?></a></li>
															<?php 
                                }
                                foreach ( $refs as $ref ) {
                                    ?>
																<li><a href="<?php 
                                    echo esc_url( $ref->url );
                                    ?>" target="_blank" class="exlink" rel="noopener"><?php 
                                    echo esc_html( self::remove_http( $ref->name ) );
                                    ?></a></li>
															<?php 
                                }
                                ?>
														</ul>
												<?php 
                            }
                        }
                        ?>
											</div>
										</div>
									</div>
								<?php 
                    }
                    ?>
							</div><!-- .vuln .vulnplugin -->
						<?php 
                }
            }
            // end themes
        } else {
            // No update if feature disabled
            if ( !self::$options['enable_vulns'] ) {
                ?>
						<h3><?php 
                esc_html_e( 'The vulnerability scanner is disabled', 'security-ninja' );
                ?></h3>
					<?php 
            } else {
                ?>
						<h3><?php 
                esc_html_e( 'Great, no known vulnerabilities found on your website', 'security-ninja' );
                ?></h3>
				<?php 
            }
        }
        ?>
			</div>
			<div class="card">
				<form method="post" action="options.php">
					<?php 
        settings_fields( 'wf_sn_vu_settings_group' );
        ?>
					<h3 class="ss_header"><?php 
        esc_html_e( 'Settings', 'security-ninja' );
        ?></h3>
					<table class="form-table">
						<tbody>
							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_vulns"><?php 
        esc_html_e( 'Vulnerability scanning', 'security-ninja' );
        ?></label></th>
								<td class="sn-cf-options">
									<?php 
        Wf_Sn::create_toggle_switch( 'wf_sn_vu_settings_group_enable_vulns', array(
            'value'       => 1,
            'saved_value' => self::$options['enable_vulns'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_vulns]',
        ) );
        ?>
									<p class="description"><?php 
        esc_html_e( 'Checking for known vulnerabilites.', 'security-ninja' );
        ?></p>
								</td>
							</tr>

							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_admin_notification"><?php 
        esc_html_e( 'Admin counter', 'security-ninja' );
        ?></label></th>
								<td class="sn-cf-options">
									<?php 
        Wf_Sn::create_toggle_switch( 'wf_sn_vu_settings_group_enable_admin_notification', array(
            'saved_value' => self::$options['enable_admin_notification'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_admin_notification]',
        ) );
        ?>
									<p class="description"><?php 
        esc_html_e( 'Disable warning notice in admin pages.', 'security-ninja' );
        ?></p>
								</td>
							</tr>

							<tr valign="top">
								<th scope="row"><label for="wf_sn_vu_settings_group_enable_email_notice"><?php 
        esc_html_e( 'Email warnings', 'security-ninja' );
        ?></label></th>
								<td class="sn-cf-options">
									<?php 
        Wf_Sn::create_toggle_switch( 'wf_sn_vu_settings_group_enable_email_notice', array(
            'saved_value' => self::$options['enable_email_notice'],
            'option_key'  => 'wf_sn_vu_settings_group[enable_email_notice]',
        ) );
        ?>
									<p class="description"><?php 
        esc_html_e( 'Enable email notifications. Only when one or more vulnerabilites are detected.', 'security-ninja' );
        ?></p>
								</td>
							</tr>

							<tr>
								<th scope="row"><label for="wf_sn_vu_settings_group_email_notice_recipient_"><?php 
        esc_html_e( 'Email recipient', 'security-ninja' );
        ?></label></th>
								<td>
									<input name="wf_sn_vu_settings_group[email_notice_recipient]" type="text" value="<?php 
        echo esc_attr( self::$options['email_notice_recipient'] );
        ?>" class="regular-text" placeholder="">
									<p class="description">
										<?php 
        esc_html_e( 'Who should get the warning? The system will send an email when a vulnerability is detected. Maximum one email per day.', 'security-ninja' );
        ?>
									</p>
								</td>
							</tr>
							<tr>
								<td colspan="2">
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
				<p>
					<?php 
            printf( 
                // translators: Shows how many vulnerabilities
                esc_html__( 'Vulnerability list contains %1$s known vulnerabilities.', 'security-ninja' ),
                esc_html( number_format_i18n( $total_vulnerabilities ) )
             );
            ?>
				</p>
				<?php 
            $last_modified = Wf_Sn_Vu::get_vulnerabilities_last_modified();
            if ( $last_modified ) {
                echo '<h4>' . esc_html__( 'Last Updated', 'security-ninja' ) . '</h4>';
                echo '<ul class="sn-vuln-update-list">';
                foreach ( $last_modified as $type => $timestamp ) {
                    $time_diff = human_time_diff( $timestamp, current_time( 'timestamp' ) );
                    printf(
                        // translators: %1$s: Type, %2$s: Formatted date, %3$s: Time difference
                        '%1$s: %2$s (%3$s ' . esc_html__( 'ago', 'security-ninja' ) . ')',
                        '<strong>' . esc_html( ucfirst( $type ) ) . '</strong>',
                        esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) ),
                        esc_html( $time_diff )
                    );
                }
                echo '</ul>';
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
        // dont show on the wizard page
        if ( strpos( $current_screen->id, 'security-ninja-wizard' ) !== false ) {
            return false;
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
                    $sanitized_values[$key] = intval( $value );
                    break;
                case 'email_notice_recipient':
                    $sanitized_values[$key] = sanitize_text_field( $value );
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
    }

}

// setup environment when activated
register_activation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\Wf_Sn_Vu', 'activate') );
// hook everything up
add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\Wf_Sn_Vu', 'init') );
// when deativated clean up
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\Wf_Sn_Vu', 'deactivate') );