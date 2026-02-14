<?php

namespace WPSecurityNinja\Plugin;

if ( !function_exists( 'add_action' ) ) {
    die( 'Please don\'t open this file directly!' );
}
require 'sn-el-modules.php';
class Wf_Sn_El {
    private static $is_active = null;

    private static $options = null;

    private static $watching_actions = false;

    /**
     * init plugin
     *
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Wednesday, May 15th, 2024.
     * @access	public static
     * @return	void
     */
    public static function init() {
        self::$options = get_option( 'wf_sn_el' );
        self::default_settings( false );
        // Register settings earlier in the init process
        add_action( 'admin_init', array(__CLASS__, 'register_settings') );
        add_action( 'wp_ajax_get_events_data', array(__CLASS__, 'ajax_get_events_data') );
        add_action( 'wp_ajax_get_events_actions', array(__CLASS__, 'ajax_get_events_actions') );
        // Add the monitor for new admin users
        add_action( 'user_register', array(__CLASS__, 'monitor_new_admin_creation') );
        // Schedule hourly check for direct database admin creations
        if ( !wp_next_scheduled( 'secnin_check_direct_admin_creation' ) ) {
            wp_schedule_event( time(), 'hourly', 'secnin_check_direct_admin_creation' );
        }
        add_action( 'secnin_check_direct_admin_creation', array(__CLASS__, 'check_direct_admin_creation') );
        if ( is_null( self::$is_active ) ) {
            self::$is_active = self::is_active();
        }
        if ( is_admin() ) {
            // add tab to Security Ninja tabs
            add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\Wf_Sn_El', 'sn_tabs') );
            add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_El', 'enqueue_scripts') );
            add_action( 'wp_ajax_sn_el_truncate_log', array(__NAMESPACE__ . '\\Wf_Sn_El', 'ajax_truncate_log') );
            add_action( 'secnin_prune_logs_cron', array(__NAMESPACE__ . '\\Wf_Sn_El', 'do_cron_prune_logs') );
            if ( self::$is_active ) {
                add_action(
                    'all',
                    array(__NAMESPACE__ . '\\Wf_Sn_El', 'watch_actions'),
                    9,
                    10
                );
            }
        }
        // REST API logging hooks
        add_filter( 'rest_authentication_errors', array(__CLASS__, 'rest_log_auth_errors'), 999 );
        add_filter( 'determine_current_user', array(__CLASS__, 'rest_log_determine_user'), 99 );
        add_filter(
            'rest_pre_dispatch',
            array(__CLASS__, 'rest_log_pre_dispatch'),
            999,
            3
        );
        add_filter(
            'rest_post_dispatch',
            array(__CLASS__, 'rest_log_post_dispatch'),
            999,
            3
        );
        // Schedule the cron job to run twice daily
        if ( !wp_next_scheduled( 'secnin_prune_logs_cron' ) ) {
            wp_schedule_event( time(), 'daily', 'secnin_prune_logs_cron' );
        }
    }

    /**
     * Monitor creation of new admin users through WordPress
     *
     * @param int $user_id The ID of the newly created user
     * @return void
     */
    public static function monitor_new_admin_creation( $user_id ) {
        $user = get_userdata( $user_id );
        if ( !$user || !in_array( 'administrator', (array) $user->roles ) ) {
            return;
        }
        if ( !self::$options['notify_new_admin'] ) {
            return;
        }
        // self::send_admin_notification($user, false); // @todo - when activating this feature, mark existing admins to prevent notifications for existing admin accounts.
        // Update the last checked ID immediately when a legitimate admin is created
        update_option( 'secnin_last_checked_admin_id', $user_id );
        // Log the legitimate creation
        wf_sn_el_modules::log_event(
            'security_ninja',
            'admin_created',
            sprintf( __( 'New administrator account created normally: %s', 'security-ninja' ), $user->user_login ),
            array(
                'user_id' => $user_id,
            )
        );
    }

    /**
     * Log REST API authentication errors
     *
     * @param mixed $result
     * @return mixed
     */
    public static function rest_log_auth_errors( $result ) {
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST && is_wp_error( $result ) ) {
            $user_ip = call_user_func( __NAMESPACE__ . '\\Wf_sn_cf::get_user_ip' );
            $payload = array(
                'ip'      => $user_ip,
                'uri'     => ( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ),
                'code'    => $result->get_error_code(),
                'message' => $result->get_error_message(),
                'data'    => $result->get_error_data(),
            );
            wf_sn_el_modules::log_event(
                'rest',
                'auth_error',
                __( 'REST authentication error', 'security-ninja' ),
                $payload,
                get_current_user_id()
            );
        }
        return $result;
    }

    /**
     * Log resolved user during REST requests
     *
     * @param int|false $user_id
     * @return int|false
     */
    public static function rest_log_determine_user( $user_id ) {
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            $payload = array(
                'uri'     => ( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ),
                'user_id' => $user_id,
            );
        }
        return $user_id;
    }

    /**
     * Log pre-dispatch REST errors (short-circuits)
     *
     * @param mixed           $result
     * @param \WP_REST_Server $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function rest_log_pre_dispatch( $result, $server, $request ) {
        if ( is_wp_error( $result ) ) {
            $payload = array(
                'method'  => $request->get_method(),
                'route'   => $request->get_route(),
                'code'    => $result->get_error_code(),
                'message' => $result->get_error_message(),
                'data'    => $result->get_error_data(),
            );
        }
        return $result;
    }

    /**
     * Log REST final error responses and successful post creations
     *
     * @param mixed            $result
     * @param \WP_REST_Server  $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public static function rest_log_post_dispatch( $result, $server, $request ) {
        $response = rest_ensure_response( $result );
        $status = (int) $response->get_status();
        $data = $response->get_data();
        // Log error responses
        if ( $status >= 400 ) {
            $error_payload = array(
                'method' => $request->get_method(),
                'route'  => $request->get_route(),
                'status' => $status,
            );
            if ( is_array( $data ) ) {
                // Include common error fields only
                $error_payload['code'] = ( isset( $data['code'] ) ? $data['code'] : '' );
                $error_payload['message'] = ( isset( $data['message'] ) ? $data['message'] : '' );
            }
            // Use hardcoded string to prevent infinite loop with translation functions
            wf_sn_el_modules::log_event(
                'rest',
                'error_response',
                'REST error response',
                $error_payload,
                get_current_user_id()
            );
            return $result;
        }
        // Log successful post creation via REST
        if ( 'POST' === $request->get_method() && strpos( $request->get_route(), '/wp/v2/posts' ) !== false ) {
            $post_id = null;
            if ( is_array( $data ) && isset( $data['id'] ) ) {
                $post_id = (int) $data['id'];
            }
            if ( $post_id && in_array( $status, array(200, 201), true ) ) {
                $success_payload = array(
                    'route'   => $request->get_route(),
                    'status'  => $status,
                    'post_id' => $post_id,
                );
            }
        }
        return $result;
    }

    /**
     * Check for admin users created directly in the database
     */
    public static function check_direct_admin_creation() {
        global $wpdb;
        $last_checked_id = get_option( 'secnin_last_checked_admin_id', 0 );
        $query = $wpdb->prepare(
            "SELECT DISTINCT u.ID, u.user_login, u.user_email, u.user_registered \n\t\t\t FROM {$wpdb->users} u \n\t\t\t INNER JOIN {$wpdb->usermeta} um ON u.ID = um.user_id \n\t\t\t WHERE um.meta_key = %s \n\t\t\t AND (\n\t\t\t\t um.meta_value LIKE %s \n\t\t\t\t OR um.meta_value LIKE %s\n\t\t\t\t OR um.meta_value LIKE %s\n\t\t\t )\n\t\t\t AND u.ID > %d",
            $wpdb->prefix . 'capabilities',
            '%administrator%',
            '%s:13:"administrator"%',
            '%a:1:{s:13:"administrator";b:1}%',
            $last_checked_id
        );
        $new_admins = $wpdb->get_results( $query );
        if ( !empty( $new_admins ) ) {
            foreach ( $new_admins as $admin ) {
                // Check if this admin was created through WordPress (has an action log)
                $was_created_normally = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}wf_sn_el \n\t\t\t\t\t WHERE action = %s \n\t\t\t\t\t AND description LIKE %s \n\t\t\t\t\t AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)", 'admin_created', '%' . $admin->user_login . '%' ) );
                // @todo - what if user was created before plugin install
                // @todo - what if user
                // Only notify if it wasn't created through WordPress
                // if (!$was_created_normally) {
                // 	if (isset(self::$options['notify_new_admin']) && self::$options['notify_new_admin']) {
                // 		self::send_admin_notification($admin, true);
                // 	}
                // 	wf_sn_el_modules::log_event(
                // 		'security_ninja',
                // 		'direct_admin_created',
                // 		sprintf(__('WARNING: Administrator account created directly in database: %s', 'security-ninja'), $admin->user_login),
                // 		array('user_id' => $admin->ID)
                // 	);
                // }
                update_option( 'secnin_last_checked_admin_id', $admin->ID );
            }
        }
    }

    /**
     * Send admin creation notification email
     *
     * @param WP_User|object $user User object
     * @param bool $is_direct_creation Whether the user was created directly in database
     * @return void
     */
    private static function send_admin_notification( $user, $is_direct_creation ) {
        $site_name = esc_html( get_bloginfo( 'name' ) );
        $settings_url = admin_url( 'admin.php?page=wf-sn' );
        $headers = array('Content-Type: text/html; charset=UTF-8');
        try {
            add_filter( 'wp_mail_content_type', array(__NAMESPACE__ . '\\Wf_Sn_El', 'sn_set_html_mail_content_type') );
            $is_whitelabel = class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_Wl' ) && 1 === \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active();
            // Set subject based on creation type and white label status
            if ( $is_direct_creation ) {
                $subject = ( $is_whitelabel ? sprintf( esc_html__( '[%s] WARNING: Administrator Created in Database', 'security-ninja' ), $site_name ) : sprintf( esc_html__( '[%s] Security Ninja - WARNING: Direct Database Creation', 'security-ninja' ), $site_name ) );
            } else {
                $subject = ( $is_whitelabel ? sprintf( esc_html__( '[%s] New Administrator Account Created', 'security-ninja' ), $site_name ) : sprintf( esc_html__( '[%s] Security Ninja - New Administrator Account', 'security-ninja' ), $site_name ) );
            }
            // Build the notification table
            $body = sprintf(
                '<table style="width: 100%%; border-collapse: collapse; margin: 20px 0;">
					<tr>
						<td style="padding: 12px; vertical-align: top;"><strong>%s</strong></td>
						<td style="padding: 12px; vertical-align: top;">%s</td>
					</tr>
					<tr style="background-color: #f8f9fa;">
						<td style="padding: 12px; vertical-align: top;"><strong>%s</strong></td>
						<td style="padding: 12px; vertical-align: top;">%s</td>
					</tr>
					<tr>
						<td style="padding: 12px; vertical-align: top;"><strong>%s</strong></td>
						<td style="padding: 12px; vertical-align: top;">%s</td>
					</tr>
					<tr style="background-color: #f8f9fa;">
						<td style="padding: 12px; vertical-align: top;"><strong>%s</strong></td>
						<td style="padding: 12px; vertical-align: top;">%s</td>
					</tr>
				</table>',
                esc_html__( 'Username', 'security-ninja' ),
                esc_html( $user->user_login ),
                esc_html__( 'Email', 'security-ninja' ),
                esc_html( $user->user_email ),
                esc_html__( 'Created By', 'security-ninja' ),
                ( $is_direct_creation ? esc_html__( 'Direct Database Creation', 'security-ninja' ) : esc_html( wp_get_current_user()->user_login ) ),
                esc_html__( 'Created On', 'security-ninja' ),
                esc_html( ( $is_direct_creation ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $user->user_registered ) ) : date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ) ) )
            );
            // Add appropriate header text
            $header_text = ( $is_direct_creation ? esc_html__( 'WARNING: An administrator account has been created directly in the database. This could indicate a security breach if you did not create this user manually.', 'security-ninja' ) : esc_html__( 'A new administrator account has been created on your website.', 'security-ninja' ) );
            $body = sprintf( '<p>%s</p>%s', $header_text, $body );
            // Add footer with settings link
            $body .= sprintf( '<p style="margin-top: 20px; color: #666;">%s</p>', sprintf( 
                // translators: %1$s: opening link tag, %2$s: closing link tag
                ( $is_whitelabel ? esc_html__( 'Notification settings can be adjusted in %1$sWordPress admin%2$s', 'security-ninja' ) : esc_html__( 'Security Ninja notification settings can be adjusted in %1$sWordPress admin%2$s', 'security-ninja' ) ),
                '<a href="' . esc_url( $settings_url ) . '" style="color: #0073aa; text-decoration: underline;">',
                '</a>'
             ) );
            // Ensure proper HTML formatting
            if ( strpos( $body, '<html' ) === false ) {
                $body = sprintf( '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /></head><body>%s</body></html>', $body );
            }
            $sent = wp_mail(
                self::$options['new_admin_notification_email'],
                $subject,
                $body,
                $headers
            );
            if ( !$sent ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'new_admin_notification_failed',
                    esc_html__( 'Failed to send new admin notification email.', 'security-ninja' ),
                    array(
                        'new_admin' => $user->user_login,
                    )
                );
            }
        } catch ( \Exception $e ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'new_admin_notification_error',
                esc_html__( 'Error sending new admin notification email', 'security-ninja' ),
                array(
                    'error'     => $e->getMessage(),
                    'new_admin' => $user->user_login,
                )
            );
        } finally {
            remove_filter( 'wp_mail_content_type', array(__NAMESPACE__ . '\\Wf_Sn_El', 'sn_set_html_mail_content_type') );
        }
    }

    /**
     * return_table_name.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, December 8th, 2023.
     * @access  public static
     * @return  mixed
     */
    public static function return_table_name() {
        global $wpdb;
        return $wpdb->prefix . 'wf_sn_el';
    }

    /**
     * ajax_get_events_data.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Friday, October 27th, 2023.	
     * @version	v1.0.1	Thursday, October 26th, 2023.	
     * @version	v1.0.2	Monday, May 20th, 2024.
     * @access	public static
     * @return	mixed
     */
    public static function ajax_get_events_data() {
        global $wpdb;
        // Verify nonce
        if ( !isset( $_POST['nonce'] ) || !wp_verify_nonce( $_POST['nonce'], 'sn_datatables_nonce' ) ) {
            wp_die( 'Permission denied' );
        }
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Error saving dismiss pointer.', 'security-ninja' ),
            ) );
        }
        // Get DataTables parameters
        $draw = intval( $_POST['draw'] );
        $start = intval( $_POST['start'] );
        $length = intval( $_POST['length'] );
        $search = sanitize_text_field( $_POST['search']['value'] ?? '' );
        $action_filter = sanitize_text_field( $_POST['action_filter'] ?? '' );
        $order = $_POST['order'] ?? array();
        // Build the initial query
        $query = 'SELECT id, timestamp, ip, user_agent, user_id, action, raw_data, description FROM ' . $wpdb->prefix . 'wf_sn_el';
        // Handle search filtering
        $where_conditions = array();
        if ( !empty( $search ) ) {
            $where_conditions[] = '(description LIKE "%' . esc_sql( $search ) . '%" OR ip LIKE "%' . esc_sql( $search ) . '%" OR action LIKE "%' . esc_sql( $search ) . '%" OR user_agent LIKE "%' . esc_sql( $search ) . '%")';
        }
        if ( !empty( $action_filter ) ) {
            $where_conditions[] = 'action = "' . esc_sql( $action_filter ) . '"';
        }
        if ( !empty( $where_conditions ) ) {
            $query .= ' WHERE ' . implode( ' AND ', $where_conditions );
        }
        // Get the total number of records before filtering
        $total_records = $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'wf_sn_el' );
        // Get the total number of records after filtering
        $total_filtered = $wpdb->get_var( "SELECT COUNT(*) FROM ({$query}) AS filtered_table" );
        // Handle sorting
        $order_by = ' ORDER BY timestamp DESC';
        if ( !empty( $order ) ) {
            $columns = array(
                'timestamp',
                'description',
                'ip',
                'user_agent',
                'user_id',
                'action'
            );
            $order_by = ' ORDER BY ';
            foreach ( $order as $o ) {
                $col_index = intval( $o['column'] );
                $col_dir = ( $o['dir'] === 'asc' ? 'ASC' : 'DESC' );
                $order_by .= $columns[$col_index] . ' ' . $col_dir . ', ';
            }
            $order_by = rtrim( $order_by, ', ' );
        }
        $query .= $order_by;
        // Add pagination
        if ( $length != -1 ) {
            $query .= ' LIMIT ' . $start . ', ' . $length;
        }
        // Execute the query to get events
        $events = $wpdb->get_results( $query );
        $data = array();
        $current_time = current_time( 'timestamp' );
        // Process each event for output
        foreach ( $events as $event ) {
            $user = ( $event->user_id && $event->user_id !== '0' ? get_userdata( $event->user_id ) : null );
            $user_details = '';
            if ( $user instanceof \WP_User ) {
                $user_details = esc_html( $user->user_nicename ) . '<br><small>';
            }
            // Geolocate IP (premium feature)
            $geolocate_ip = false;
            if ( secnin_fs()->can_use_premium_code() ) {
                // Ensure the geolocation class is loaded
                if ( !class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
                    include_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-sn-geolocation.php';
                }
                if ( class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
                    $geolocate_ip = \WPSecurityNinja\Plugin\SN_Geolocation::geolocate_ip( $event->ip, true );
                    if ( $geolocate_ip && $geolocate_ip['country'] !== '-' ) {
                        $country_code = $geolocate_ip['country'];
                    }
                }
            }
            $user_details .= esc_html( $event->ip ) . '</small>';
            // Prepare details output
            $raw_data = maybe_unserialize( $event->raw_data );
            // Initialize the details output
            $details_output = '';
            if ( !empty( $raw_data ) ) {
                $details_output = '<button class="button button-small button-secondary">' . __( 'Details', 'security-ninja' ) . '</button>';
                $details_output .= '<div class="details-content" style="display:none;"><dl class="rowdetails">';
                if ( is_array( $raw_data ) ) {
                    foreach ( $raw_data as $key => $value ) {
                        // Check if the value is a WP_Error object
                        if ( is_wp_error( $value ) ) {
                            // Handle the error, for example, display the error message
                            $details_output .= '<dt>' . esc_html( $key ) . '</dt><dd>' . esc_html( $value->get_error_message() ) . '</dd>';
                        } elseif ( is_object( $value ) ) {
                            // Handle the object, for example, display the class name
                            $details_output .= '<dt>' . esc_html( $key ) . '</dt><dd>' . esc_html( get_class( $value ) ) . '</dd>';
                        } elseif ( is_array( $value ) ) {
                            // Handle array values
                            $details_output .= '<dt>' . esc_html( $key ) . '</dt><dd>';
                            foreach ( $value as $sub_key => $sub_value ) {
                                if ( is_scalar( $sub_value ) ) {
                                    $details_output .= esc_html( $sub_key ) . ': ' . esc_html( $sub_value ) . '<br>';
                                } else {
                                    $details_output .= esc_html( $sub_key ) . ': ' . esc_html( gettype( $sub_value ) ) . '<br>';
                                }
                            }
                            $details_output .= '</dd>';
                        } else {
                            // Process normally if it's not an error, object, or array
                            $details_output .= '<dt>' . esc_html( $key ) . '</dt><dd>' . esc_html( $value ) . '</dd>';
                        }
                    }
                } else {
                    // If $raw_data is not an array, check if it is a WP_Error
                    if ( is_wp_error( $raw_data ) ) {
                        $details_output .= '<dd>' . esc_html( $raw_data->get_error_message() ) . '</dd>';
                    } elseif ( is_object( $raw_data ) ) {
                        // Handle the object, for example, display the class name
                        $details_output .= '<dd>' . esc_html( get_class( $raw_data ) ) . '</dd>';
                    } else {
                        $details_output .= '<dd>' . esc_html( $raw_data ) . '</dd>';
                    }
                }
                $details_output .= '</dl></div>';
            }
            $timestamp_unix = strtotime( $event->timestamp );
            // Calculate the time since
            $time_since = human_time_diff( $timestamp_unix, $current_time ) . ' ' . __( 'ago', 'security-ninja' );
            // Format the original timestamp
            $formatted_timestamp = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp_unix );
            // Concatenate the time since and the formatted timestamp
            $timestamp_details = esc_html( $time_since ) . '<br><small>' . esc_html( $formatted_timestamp ) . '</small>';
            $data[] = array(
                'timestamp'   => $timestamp_details,
                'user_id'     => $user_details,
                'action'      => esc_html( $event->action ),
                'description' => esc_html( $event->description ),
                'details'     => $details_output,
            );
        }
        // Return JSON response
        $response = array(
            'draw'            => $draw,
            'recordsTotal'    => $total_records,
            'recordsFiltered' => $total_filtered,
            'data'            => $data,
        );
        wp_send_json( $response );
        wp_die();
    }

    /**
     * Get unique actions for the filter dropdown
     *
     * @author	Lars Koudal
     * @since	v1.0.0
     * @version	v1.0.0	Monday, December 9th, 2024.
     * @access	public static
     * @return	mixed
     */
    public static function ajax_get_events_actions() {
        global $wpdb;
        // Verify nonce
        if ( !isset( $_POST['nonce'] ) || !wp_verify_nonce( $_POST['nonce'], 'sn_datatables_nonce' ) ) {
            wp_die( 'Permission denied' );
        }
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Permission denied.', 'security-ninja' ),
            ) );
        }
        // Get unique actions from the database
        $actions = $wpdb->get_col( 'SELECT DISTINCT action FROM ' . $wpdb->prefix . 'wf_sn_el ORDER BY action ASC' );
        wp_send_json_success( array(
            'actions' => $actions,
        ) );
        wp_die();
    }

    /**
     * Send a webhook event.
     *
     * @since   v0.0.1
     * @version v1.0.1  Thursday, October 5th, 2023.
     * @access  public static
     * @param   string $event The event name.
     * @param   array  $data  The event data.
     * @return  bool          True on success, false on failure.
     */
    public static function send_webhook_event( $event, $data ) {
        if ( empty( $event ) || !is_string( $event ) || empty( $data ) || !is_array( $data ) ) {
            return false;
        }
        $options = get_option( 'wf_sn_el' );
        if ( !isset( $options['webhook_active'] ) || intval( $options['webhook_active'] ) !== 1 || empty( $options['webhook_url'] ) || !filter_var( $options['webhook_url'], FILTER_VALIDATE_URL ) ) {
            return false;
        }
        if ( empty( $options[$event] ) || intval( $options[$event] ) !== 1 ) {
            return false;
        }
        $data = array_merge( $data, array(
            'event'          => sanitize_text_field( $event ),
            'source'         => site_url(),
            'plugin_version' => \WPSecurityNinja\Plugin\Utils::get_plugin_version(),
            'webhook_url'    => esc_url( $options['webhook_url'] ),
        ) );
        $response = wp_remote_post( $options['webhook_url'], array(
            'body'    => wp_json_encode( $data ),
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'timeout' => 15,
        ) );
        if ( is_wp_error( $response ) ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'webhook_event',
                esc_html__( 'Webhook request failed', 'security-ninja' ),
                array(
                    'error' => $response->get_error_message(),
                )
            );
            return false;
        }
        wf_sn_el_modules::log_event( 'security_ninja', 'webhook_event', sprintf( 
            // translators: %s: event name
            esc_html__( 'Webhook event sent - %s', 'security-ninja' ),
            esc_attr( $event )
         ) );
        return true;
    }

    /**
     * Is the event logger enabled
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  mixed
     */
    public static function is_active() {
        if ( self::$is_active !== null ) {
            return self::$is_active;
        }
        if ( !self::$options ) {
            self::$options = get_option( 'wf_sn_el' );
        }
        if ( isset( self::$options['active'] ) ) {
            self::$is_active = (bool) self::$options['active'];
        } else {
            self::$is_active = false;
        }
        return self::$is_active;
    }

    /**
     * enqueue CSS and JS scripts on plugin's admin page
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function enqueue_scripts() {
        if ( !Wf_Sn::is_plugin_page() ) {
            return;
        }
        $plugin_url = plugin_dir_url( __FILE__ );
        $datatables_nonce = wp_create_nonce( 'sn_datatables_nonce' );
        wp_enqueue_script(
            'sn-el-datatables',
            $plugin_url . 'js/jquery.dataTables.min.js',
            array('jquery'),
            wf_sn::$version,
            true
        );
        wp_localize_script( 'sn-el-datatables', 'datatables_object', array(
            'nonce' => $datatables_nonce,
        ) );
        wp_enqueue_style(
            'sn-el-datatables',
            $plugin_url . 'css/jquery.dataTables.min.css',
            array(),
            wf_sn::$version
        );
        $js_vars = array(
            'nonce' => wp_create_nonce( 'wf_sn_el' ),
        );
        wp_register_script(
            'sn-el',
            $plugin_url . 'js/wf-sn-el.js',
            array('jquery', 'sn-el-datatables'),
            wf_sn::$version,
            true
        );
        wp_localize_script( 'sn-el', 'wf_sn_el', $js_vars );
        wp_enqueue_script( 'sn-el' );
        wp_enqueue_style(
            'sn-el',
            $plugin_url . 'css/wf-sn-el.css',
            array(),
            wf_sn::$version
        );
    }

    /**
     * add new tab
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @param   mixed   $tabs
     * @return  mixed
     */
    public static function sn_tabs( $tabs ) {
        $logger_tab = array(
            'id'       => 'sn_logger',
            'class'    => '',
            'label'    => esc_html__( 'Events', 'security-ninja' ),
            'callback' => array(__NAMESPACE__ . '\\wf_sn_el', 'logger_page'),
        );
        $done = false;
        $tab_count = count( $tabs );
        for ($i = 0; $i < $tab_count; $i++) {
            if ( $tabs[$i]['id'] === 'sn_logger' ) {
                $tabs[$i] = $logger_tab;
                $done = true;
                break;
            }
        }
        if ( !$done ) {
            $tabs[] = $logger_tab;
        }
        return $tabs;
    }

    /**
     * set default options
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @param   boolean $force  Default: false
     * @return  void
     */
    public static function default_settings( $force = true ) {
        $options = array(
            'active'                       => 1,
            'email_reports'                => '',
            'email_modules'                => array(
                'users',
                'menus',
                'file_editor',
                'taxonomies',
                'media',
                'posts',
                'widgets',
                'installer',
                'comments',
                'settings',
                'security_ninja',
                'woocommerce'
            ),
            'email_to'                     => get_option( 'admin_email' ),
            'retention'                    => 'day-7',
            'remove_settings_deactivate'   => 0,
            'notify_new_admin'             => 0,
            'new_admin_notification_email' => get_option( 'admin_email' ),
        );
        if ( $force ) {
            update_option( 'wf_sn_el', $options );
        } else {
            add_option(
                'wf_sn_el',
                $options,
                '',
                false
            );
        }
    }

    /**
     * sanitize settings on save
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Monday, November 13th, 2023.
     * @version v1.0.2  Thursday, February 22nd, 2024.
     * @access  public static
     * @param   mixed   $values
     * @return  mixed
     */
    public static function sanitize_settings( $values ) {
        // Handle null or non-array values (WordPress may call this with null)
        if ( !is_array( $values ) ) {
            // Return existing options normalized
            $old_options = get_option( 'wf_sn_el', array() );
            if ( !is_array( $old_options ) ) {
                $old_options = array();
            }
            // Normalize existing boolean values
            $boolean_keys = array(
                'active',
                'webhook_firewall_events',
                'webhook_user_logins',
                'webhook_updates',
                'webhook_active',
                'notify_new_admin'
            );
            foreach ( $boolean_keys as $key ) {
                if ( isset( $old_options[$key] ) ) {
                    $old_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] );
                }
            }
            return $old_options;
        }
        $old_options = get_option( 'wf_sn_el', array() );
        if ( !is_array( $old_options ) ) {
            $old_options = array();
        }
        $new_options = $old_options;
        // Add to boolean_keys array
        $boolean_keys = array(
            'active',
            'webhook_firewall_events',
            'webhook_user_logins',
            'webhook_updates',
            'webhook_active',
            'notify_new_admin'
        );
        // Ensure all boolean keys are normalized to 0/1, defaulting to 0 if not present
        foreach ( $boolean_keys as $key ) {
            if ( isset( $values[$key] ) ) {
                $new_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $values[$key] );
            } else {
                // Preserve existing value if not in form submission
                $new_options[$key] = ( isset( $old_options[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] ) : 0 );
            }
        }
        // Handle all other keys with specific data types or requirements
        foreach ( $values as $key => $value ) {
            switch ( $key ) {
                case 'retention':
                case 'email_reports':
                case 'webhook_url':
                case 'email_to':
                case 'remove_settings_deactivate':
                case 'new_admin_notification_email':
                    // Sanitize text fields
                    $new_options[$key] = sanitize_text_field( $value );
                    break;
                case 'webhook_events':
                case 'email_modules':
                    // Ensure array values are sanitized
                    if ( is_array( $value ) ) {
                        $new_options[$key] = array_map( 'sanitize_text_field', $value );
                    }
                    break;
            }
        }
        // Optional: Check and initialize missing fields if necessary
        $new_options['email_modules'] = $new_options['email_modules'] ?? array();
        return $new_options;
    }

    /**
     * all settings are saved in one option key
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function register_settings() {
        register_setting( 'wf_sn_el', 'wf_sn_el', array(__NAMESPACE__ . '\\wf_sn_el', 'sanitize_settings') );
    }

    /**
     * process selected actions / filters
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function watch_actions() {
        $current_action = current_action();
        // Hard skip translation hooks - they are extremely noisy and can cause recursion and memory issues
        // when other plugins (e.g., debug tools) render translated output on shutdown.
        if ( empty( $current_action ) || 0 === strpos( $current_action, 'gettext' ) ) {
            return;
        }
        // Prevent infinite recursion
        if ( self::$watching_actions ) {
            return;
        }
        // Set flag to prevent recursive calls
        self::$watching_actions = true;
        try {
            // Skip low-level WordPress hooks that can cause recursion during query parsing
            $skip_hooks = array('sanitize_key', 'parse_query', 'pre_get_posts');
            if ( in_array( $current_action, $skip_hooks, true ) ) {
                return;
            }
            // Define audited hooks once per request (this function runs on the global "all" hook).
            static $login_actions = null;
            static $security_ninja = null;
            static $users = null;
            static $menus = null;
            static $file_editor = null;
            static $taxonomies = null;
            static $media = null;
            static $posts = null;
            static $widgets = null;
            static $installer = null;
            static $comments = null;
            static $settings = null;
            static $woocommerce = null;
            static $premium_hooks_all = null;
            if ( is_null( $login_actions ) ) {
                $login_actions = array('wp_login_failed');
                $security_ninja = array(
                    'security_ninja_done_testing',
                    'security_ninja_scheduled_scanner_done_cron',
                    'security_ninja_core_scanner_done_scanning',
                    'security_ninja_remote_access',
                    'security_ninja_malware_scanner_done_scanning'
                );
                // Premium version: actions that can be audited for premium users.
                $users = array(
                    'user_register',
                    'wp_login_failed',
                    'profile_update',
                    'password_reset',
                    'retrieve_password',
                    'set_logged_in_cookie',
                    'clear_auth_cookie',
                    'delete_user',
                    'deleted_user',
                    'set_user_role'
                );
                $menus = array('wp_create_nav_menu', 'wp_update_nav_menu', 'delete_nav_menu');
                $file_editor = array('wp_redirect');
                $taxonomies = array('created_term', 'delete_term', 'edited_term');
                $media = array(
                    'add_attachment',
                    'edit_attachment',
                    'delete_attachment',
                    'wp_save_image_editor_file'
                );
                $posts = array(
                    'deleted_post',
                    // When a post is deleted
                    'publish_post',
                    // When a post is published
                    'edit_post',
                    // When a post is updated
                    'trash_post',
                    // When a post is moved to trash
                    'untrash_post',
                );
                $widgets = array('update_option_sidebars_widgets', 'wp_ajax_widgets-order', 'widget_update_callback');
                $installer = array(
                    'upgrader_process_complete',
                    'activate_plugin',
                    'deactivate_plugin',
                    'switch_theme',
                    '_core_updated_successfully'
                );
                $comments = array(
                    'comment_flood_trigger',
                    'wp_insert_comment',
                    'edit_comment',
                    'delete_comment',
                    'trash_comment',
                    'untrash_comment',
                    'spam_comment',
                    'unspam_comment',
                    'transition_comment_status',
                    'comment_duplicate_trigger'
                );
                $settings = array(
                    'whitelist_options',
                    'update_site_option',
                    'update_option_permalink_structure',
                    'update_option_category_base',
                    'update_option_tag_base'
                );
                $woocommerce = array(
                    // Product actions
                    'woocommerce_update_product',
                    'woocommerce_new_product_data',
                    'woocommerce_product_duplicate',
                    'woocommerce_update_product_variation',
                    'woocommerce_delete_product',
                    // Customer actions
                    'woocommerce_new_customer',
                    // New customer added
                    'woocommerce_delete_customer',
                    // Customer deleted
                    'woocommerce_customer_reset_password',
                    // Customer reset password
                    // Order actions
                    'woocommerce_new_order',
                    // New order created
                    'woocommerce_delete_order',
                    // Order deleted
                    'woocommerce_order_status_changed',
                    // Order status changed
                    'woocommerce_order_refunded',
                    // Order refunded
                    // Coupon actions
                    'woocommerce_delete_coupon',
                    // Coupon deleted
                    'woocommerce_coupon_updated',
                    // Coupon updated
                    'woocommerce_coupon_created',
                );
                $premium_hooks_all = array_unique( array_merge(
                    $users,
                    $menus,
                    $file_editor,
                    $taxonomies,
                    $media,
                    $posts,
                    $widgets,
                    $installer,
                    $comments,
                    $settings,
                    $woocommerce
                ) );
            }
            // Bail early if this hook isn't one we audit (prevents calling Freemius on every hook).
            if ( !in_array( $current_action, $login_actions, true ) && !in_array( $current_action, $security_ninja, true ) && !in_array( $current_action, $premium_hooks_all, true ) ) {
                return;
            }
            // Only fetch args if we're going to log something.
            $args = func_get_args();
            // Free version: Check login actions and Security Ninja actions first
            if ( in_array( $current_action, $login_actions, true ) ) {
                wf_sn_el_modules::parse_action_users( $current_action, $args );
                return;
                // Exit early if we handled it
            } elseif ( in_array( $current_action, $security_ninja, true ) ) {
                wf_sn_el_modules::parse_action_security_ninja( $current_action, $args );
                return;
                // Exit early if we handled it
            }
            // Premium version: check only for audited premium hooks, and cache Freemius result to avoid log/memory spam.
            if ( in_array( $current_action, $premium_hooks_all, true ) ) {
                static $can_use_premium = null;
                if ( is_null( $can_use_premium ) ) {
                    $can_use_premium = false;
                    if ( function_exists( 'secnin_fs' ) ) {
                        $fs = secnin_fs();
                        if ( is_object( $fs ) && method_exists( $fs, 'can_use_premium_code' ) ) {
                            $can_use_premium = (bool) $fs->can_use_premium_code();
                        }
                    }
                }
                if ( !$can_use_premium ) {
                    return;
                }
                if ( in_array( $current_action, $users, true ) ) {
                    wf_sn_el_modules::parse_action_users( $current_action, $args );
                } elseif ( in_array( $current_action, $menus, true ) ) {
                    wf_sn_el_modules::parse_action_menus( $current_action, $args );
                } elseif ( in_array( $current_action, $file_editor, true ) ) {
                    wf_sn_el_modules::parse_action_file_editor( $current_action, $args );
                } elseif ( in_array( $current_action, $taxonomies, true ) ) {
                    wf_sn_el_modules::parse_action_taxonomies( $current_action, $args );
                } elseif ( in_array( $current_action, $media, true ) ) {
                    wf_sn_el_modules::parse_action_media( $current_action, $args );
                } elseif ( in_array( $current_action, $posts, true ) ) {
                    wf_sn_el_modules::parse_action_posts( $current_action, $args );
                } elseif ( in_array( $current_action, $widgets, true ) ) {
                    wf_sn_el_modules::parse_action_widgets( $current_action, $args );
                } elseif ( in_array( $current_action, $installer, true ) ) {
                    wf_sn_el_modules::parse_action_installer( $current_action, $args );
                } elseif ( in_array( $current_action, $comments, true ) ) {
                    wf_sn_el_modules::parse_action_comments( $current_action, $args );
                } elseif ( in_array( $current_action, $settings, true ) ) {
                    wf_sn_el_modules::parse_action_settings( $current_action, $args );
                } elseif ( in_array( $current_action, $woocommerce, true ) ) {
                    wf_sn_el_modules::parse_action_woocommerce( $current_action, $args );
                }
            }
        } finally {
            // Always reset the flag, even if an exception occurs
            self::$watching_actions = false;
        }
    }

    /**
     * truncate event log table
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function ajax_truncate_log() {
        global $wpdb;
        check_ajax_referer( 'wf_sn_el' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        $options = get_option( 'wf_sn_el' );
        $options['last_reported_event'] = 0;
        update_option( 'wf_sn_el', $options, false );
        $wpdb->query( 'TRUNCATE TABLE ' . $wpdb->prefix . 'wf_sn_el' );
        wp_send_json_success( array(
            'message' => __( 'Emptied the log.', 'security-ninja' ),
        ) );
        exit;
    }

    /**
     * prune events log table
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Tuesday, October 24th, 2023.
     * @version v1.0.2  Monday, November 13th, 2023.
     * @access  public static
     * @param   boolean $force  Default: false
     * @return  void
     */
    public static function do_cron_prune_logs() {
        global $wpdb;
        if ( empty( self::$options['retention'] ) ) {
            return false;
        }
        // Define the list of protected actions
        $protected_actions = array(
            'login_form_blocked_ip',
            'blockadminlogin',
            'blacklisted_IP',
            'blocked_ip_banned',
            'blocked_ip_suspicious_request',
            'blocked_ip_country_ban',
            'login_denied_banned_IP',
            'firewall_ip_banned'
        );
        // Prepare placeholders for protected actions
        $placeholders = implode( ', ', array_fill( 0, count( $protected_actions ), '%s' ) );
        // Prepare the base query with placeholders for dynamic values
        $base_query = "DELETE FROM {$wpdb->prefix}wf_sn_el WHERE (action NOT IN ({$placeholders}) OR (action IN ({$placeholders}) AND timestamp < DATE_SUB(NOW(), INTERVAL 2 YEAR)))";
        // Determine retention strategy
        $tmp = explode( '-', self::$options['retention'] );
        $retention_value = (int) $tmp[1];
        if ( 'cnt' === $tmp[0] ) {
            $id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}wf_sn_el ORDER BY id DESC LIMIT %d, 1", $retention_value ) );
            if ( $id ) {
                $query = $wpdb->prepare( $base_query . ' AND id < %d', array_merge( $protected_actions, $protected_actions, array($id) ) );
                $wpdb->query( $query );
            }
        } else {
            $query = $wpdb->prepare( $base_query . ' AND timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)', array_merge( $protected_actions, $protected_actions, array($retention_value) ) );
            $wpdb->query( $query );
        }
        $deleted_rows = $wpdb->rows_affected;
        if ( $deleted_rows > 0 ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'prune_events_log',
                sprintf( 
                    // translators: %d: number of deleted rows
                    esc_html__( 'Cron job: Emptied event logs. Deleted rows: %d', 'security-ninja' ),
                    $deleted_rows
                 ),
                array(
                    'Deleted rows' => $deleted_rows,
                )
            );
        }
        return true;
    }

    /**
     * send email reports based on user's preferences
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @version v1.0.1  Friday, March 3rd, 2023.
     * @access  public static
     * @param   mixed   $last_id
     * @return  void
     */
    public static function send_email_reports( $last_id ) {
        global $wpdb;
        $body = '';
        if ( !isset( self::$options ) || !is_array( self::$options ) || !isset( self::$options['email_reports'] ) || !self::$options['email_reports'] || !$last_id ) {
            return false;
        }
        if ( isset( self::$options['last_reported_event'] ) && $last_id - self::$options['last_reported_event'] >= (int) self::$options['email_reports'] ) {
            $modules = '';
            if ( self::$options['email_modules'] ) {
                $modules = " and module IN('" . implode( "', '", self::$options['email_modules'] ) . "') ";
            }
            $events = $wpdb->get_results( 'SELECT * FROM ' . $wpdb->prefix . 'wf_sn_el WHERE id > ' . self::$options['last_reported_event'] . $modules . ' ORDER BY id DESC LIMIT ' . self::$options['email_reports'] );
            if ( !$events || count( $events ) < (int) self::$options['email_reports'] ) {
                return;
            }
            self::$options['last_reported_event'] = $events[0]->id;
            update_option( 'wf_sn_el', self::$options, false );
            $admin_url = admin_url( 'admin.php?page=wf-sn#sn_logger' );
            // if ($admin_url = SecNin_Rename_WP_Login::new_login_slug()) {
            // 	$admin_url = trailingslashit(site_url( $admin_url)) . 'admin.php?page=wf-sn#sn_logger';
            // }
            $headers = array('Content-Type: text/html; charset=UTF-8');
            $body .= sprintf(
                // translators: %1$s: site name, %2$s: opening link tag, %3$s: closing link tag, %4$s: line break
                __( 'Recent events on %1$s: %2$s(more details are available in WordPress admin)%3$s%4$s', 'security-ninja' ),
                esc_html( get_bloginfo( 'name' ) ),
                '<a href="' . esc_url( $admin_url ) . '">',
                '</a>',
                '<br>'
            );
            // Add email-friendly responsive table styles
            $body .= '
			<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
				<thead>
					<tr style="background-color: #f8f9fa;">
						<th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">' . esc_html__( 'Date & Time', 'security-ninja' ) . '</th>
						<th style="padding: 12px; text-align: left; border-bottom: 2px solid #dee2e6;">' . esc_html__( 'Event Details', 'security-ninja' ) . '</th>
					</tr>
				</thead>
				<tbody>';
            foreach ( $events as $event ) {
                $user = '';
                if ( $event->user_id ) {
                    $user_info = get_userdata( $event->user_id );
                    if ( $user_info ) {
                        $user = '<strong>' . esc_html( $user_info->user_nicename ) . '</strong>';
                        $user .= ' (' . esc_html( implode( ', ', $user_info->roles ) ) . ')';
                    } else {
                        $user = '<strong>' . __( 'user deleted', 'security-ninja' ) . '</strong>';
                    }
                } elseif ( substr( $event->user_agent, 0, 10 ) === 'WordPress/' ) {
                    $user = '<strong>' . __( 'WP cron', 'security-ninja' ) . '</strong>';
                } else {
                    $user = '<strong>' . __( 'Anonymous user', 'security-ninja' ) . '</strong>';
                }
                if ( '' !== $event->ip ) {
                    $user .= ' (' . esc_html( $event->ip ) . ')';
                }
                $module = str_replace( array('_', '-', 'ninja'), array(' ', ' ', 'Ninja'), ucfirst( $event->module ) );
                // Format the timestamp according to WP settings
                $timestamp = sprintf( '%s<br><span style="color: #666; font-size: 0.9em;">%s</span>', esc_html( date_i18n( get_option( 'date_format' ), strtotime( $event->timestamp ) ) ), esc_html( date_i18n( get_option( 'time_format' ), strtotime( $event->timestamp ) ) ) );
                // Format the event details
                $event_details = sprintf(
                    // translators: 1: Event description, 2: User name, 3: Module name
                    __( '%1$s by %2$s in %3$s module.', 'security-ninja' ),
                    esc_html( $event->description ),
                    $user,
                    // already escaped
                    esc_html( $module )
                );
                $body .= sprintf( '<tr style="border-bottom: 1px solid #dee2e6;">
						<td style="padding: 12px; vertical-align: top; min-width: 140px;">%s</td>
						<td style="padding: 12px; vertical-align: top;">%s</td>
					</tr>', $timestamp, $event_details );
            }
            $body .= '</tbody></table>';
            $body .= sprintf( '<p style="margin-top: 20px; color: #666;">' . __( 'Events Logger email report settings can be adjusted in %1$sWordPress admin%2$s', 'security-ninja' ) . '</p>', '<a href="' . esc_url( $admin_url ) . '" style="color: #0073aa; text-decoration: underline;">', '</a>' );
            $emreps = (array) explode( ',', self::$options['email_to'] );
            foreach ( $emreps as $emrep ) {
                $emrep = trim( $emrep );
                if ( !empty( $emrep ) && is_email( $emrep ) ) {
                    try {
                        add_filter( 'wp_mail_content_type', array(__NAMESPACE__ . '\\Wf_Sn_El', 'sn_set_html_mail_content_type') );
                        $subject = sprintf( esc_html__( '[%s] Security Ninja - Events Logger report', 'security-ninja' ), wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES ) );
                        // Ensure body is properly formatted as HTML
                        if ( strpos( $body, '<html' ) === false ) {
                            $body = sprintf( '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /></head><body>%s</body></html>', $body );
                        }
                        // Send email
                        $sendrep = wp_mail(
                            $emrep,
                            $subject,
                            $body,
                            $headers
                        );
                        if ( !$sendrep ) {
                            wf_sn_el_modules::log_event(
                                'security_ninja',
                                'send_email_update',
                                esc_html__( 'Email could not be sent.', 'security-ninja' ),
                                array(
                                    'recipient' => $emrep,
                                )
                            );
                        } else {
                            wf_sn_el_modules::log_event(
                                'security_ninja',
                                'send_email_update',
                                esc_html__( 'Email update sent', 'security-ninja' ),
                                array(
                                    'recipient' => $emrep,
                                )
                            );
                        }
                    } catch ( \Exception $e ) {
                        // Log the error
                        wf_sn_el_modules::log_event(
                            'security_ninja',
                            'send_email_error',
                            esc_html__( 'Email error occurred', 'security-ninja' ),
                            array(
                                'error'     => $e->getMessage(),
                                'recipient' => $emrep,
                            )
                        );
                    } finally {
                        // Always remove the filter, even if an error occurred
                        remove_filter( 'wp_mail_content_type', array(__NAMESPACE__ . '\\Wf_Sn_El', 'sn_set_html_mail_content_type') );
                    }
                } else {
                    wf_sn_el_modules::log_event(
                        'security_ninja',
                        'send_email_update',
                        __( 'Invalid email address.', 'security-ninja' ),
                        array(
                            'recipient' => $emrep,
                        )
                    );
                }
            }
        }
    }

    /**
     * sn_set_html_mail_content_type.
     *
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Friday, November 8th, 2024.
     * @access	public static
     * @return	mixed
     */
    public static function sn_set_html_mail_content_type() {
        return 'text/html';
    }

    /**
     * display results
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function logger_page() {
        global $wpdb;
        $current_user = wp_get_current_user();
        $email_reports_settings = array(
            ''     => __( 'Do not email reports', 'security-ninja' ),
            '10'   => __( 'Email report after 10 events', 'security-ninja' ),
            '25'   => __( 'Email report after 25 events', 'security-ninja' ),
            '50'   => __( 'Email report after 50 events', 'security-ninja' ),
            '100'  => __( 'Email report after 100 events', 'security-ninja' ),
            '250'  => __( 'Email report after 250 events', 'security-ninja' ),
            '500'  => __( 'Email report after 500 events', 'security-ninja' ),
            '1000' => __( 'Email report after 1000 events', 'security-ninja' ),
        );
        $retention_settings = array(
            'day-1'         => __( 'Keep logs for 1 day', 'security-ninja' ),
            'day-7'         => __( 'Keep logs for 7 days', 'security-ninja' ),
            'day-30'        => __( 'Keep logs for 30 days', 'security-ninja' ),
            'day-60'        => __( 'Keep logs for 60 days', 'security-ninja' ),
            'day-90'        => __( 'Keep logs for 90 days', 'security-ninja' ),
            'day-180'       => __( 'Keep logs for 180 days', 'security-ninja' ),
            'day-365'       => __( 'Keep logs for 365 days', 'security-ninja' ),
            'records-100'   => __( 'Keep last 100 records', 'security-ninja' ),
            'records-250'   => __( 'Keep last 250 records', 'security-ninja' ),
            'records-500'   => __( 'Keep last 500 records', 'security-ninja' ),
            'records-1000'  => __( 'Keep last 1000 records', 'security-ninja' ),
            'records-5000'  => __( 'Keep last 5000 records', 'security-ninja' ),
            'records-10000' => __( 'Keep last 10000 records', 'security-ninja' ),
        );
        $modules = array(
            'users'          => __( 'Users', 'security-ninja' ),
            'menus'          => __( 'Menus', 'security-ninja' ),
            'file_editor'    => __( 'File Editor', 'security-ninja' ),
            'taxonomies'     => __( 'Taxonomies', 'security-ninja' ),
            'media'          => __( 'Media', 'security-ninja' ),
            'posts'          => __( 'Posts', 'security-ninja' ),
            'widgets'        => __( 'Widgets', 'security-ninja' ),
            'installer'      => __( 'Installer', 'security-ninja' ),
            'comments'       => __( 'Comments', 'security-ninja' ),
            'settings'       => __( 'Settings', 'security-ninja' ),
            'security_ninja' => 'Security Ninja',
            'woocommerce'    => __( 'WooCommerce', 'security-ninja' ),
        );
        ?>
		<div class="section">
			<div class="wf-el-tab-content">
			<div class="nav-tab-wrapper" id="wf-sn-el-subtabs">
				<a href="#sn_el_log" class="nav-tab nav-tab-active"><?php 
        esc_html_e( 'Event Log', 'security-ninja' );
        ?></a>
				<a href="#sn_el_settings" class="nav-tab"><?php 
        esc_html_e( 'Settings', 'security-ninja' );
        ?></a>
				<?php 
        $can_use_premium = false;
        if ( secnin_fs()->can_use_premium_code() ) {
            $can_use_premium = true;
        }
        $pro_class = ( $can_use_premium ? '' : ' profeature' );
        ?>
				<a href="#sn_el_notifications" class="nav-tab<?php 
        echo esc_attr( $pro_class );
        ?>"><?php 
        esc_html_e( 'Notifications', 'security-ninja' );
        ?></a>
				<a href="#sn_el_webhooks" class="nav-tab<?php 
        echo esc_attr( $pro_class );
        ?>"><?php 
        esc_html_e( 'Webhooks', 'security-ninja' );
        ?></a>
			</div>

				<form action="options.php" method="post">
					<?php 
        settings_fields( 'wf_sn_el' );
        ?>

					<div id="sn_el_log" class="wf-sn-el-subtab">
						<div class="sncard">
							<h2><span class="dashicons dashicons-info-outline"></span> <?php 
        esc_html_e( 'Events Logger', 'security-ninja' );
        ?></h2>
							<p><?php 
        esc_html_e( 'Track and analyze security events on your WordPress site', 'security-ninja' );
        ?></p>
							
							<!-- Action Filter -->
							<div class="sn-el-filter-container">
								<select id="sn-el-action-filter">
									<option value=""><?php 
        esc_html_e( 'Loading...', 'security-ninja' );
        ?></option>
								</select>
								<button type="button" id="sn-el-reset-filter" class="button button-secondary"><?php 
        esc_html_e( 'Reset', 'security-ninja' );
        ?></button>
							</div>
							
							<table class="wp-list-table widefat fixed table-view-list" id="sn-el-datatable" style="border-spacing: 0;">
								<thead>
									<tr>
										<th id="sn-el-date" class="column-primary"><?php 
        esc_html_e( 'Time', 'security-ninja' );
        ?></th>
										<th id="sn-el-event"><?php 
        esc_html_e( 'Event', 'security-ninja' );
        ?></th>
										<th id="sn-el-user_id"><?php 
        esc_html_e( 'User', 'security-ninja' );
        ?></th>
										<th id="sn-el-action"><?php 
        esc_html_e( 'Action', 'security-ninja' );
        ?></th>
										<th id="sn-el-details"><?php 
        esc_html_e( 'Details', 'security-ninja' );
        ?></th>
									</tr>
								</thead>
								<tbody>
								</tbody>
								<tfoot>
									<tr>
										<th class="column-primary"><?php 
        esc_html_e( 'Time', 'security-ninja' );
        ?></th>
										<th><?php 
        esc_html_e( 'Event', 'security-ninja' );
        ?></th>
										<th><?php 
        esc_html_e( 'User', 'security-ninja' );
        ?></th>
										<th><?php 
        esc_html_e( 'Action', 'security-ninja' );
        ?></th>
										<th><?php 
        esc_html_e( 'Details', 'security-ninja' );
        ?></th>
									</tr>
								</tfoot>
							</table>

							<div id="datatable-error" class="card" style="display:none;"></div>
						</div>
					</div>

					<div id="sn_el_settings" class="wf-sn-el-subtab" style="display:none;">
						<div class="sncard settings-card">
							<div id="wf-sn-el-options-container">
								<h2><?php 
        esc_html_e( 'General Settings', 'security-ninja' );
        ?></h2>
								<p><?php 
        esc_html_e( 'Configure how events are logged and managed', 'security-ninja' );
        ?></p>
								<table class="form-table">
									<tbody>
										<tr valign="top">
											<th scope="row"><label for="wf_sn_el_active">
													<h3><?php 
        esc_html_e( 'Enable events logging', 'security-ninja' );
        ?></h3>
													<p class="description"><?php 
        esc_html_e( 'If enabled events happening on your website will be logged here.', 'security-ninja' );
        ?></p>
													<p class="description"><?php 
        esc_html_e( 'Note - Some important events will still be logged here.', 'security-ninja' );
        ?></p>
												</label></th>
											<td class="sn-cf-options">
												<?php 
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_el_active', array(
            'saved_value' => self::$options['active'],
            'option_key'  => 'wf_sn_el[active]',
        ) );
        ?>
											</td>
										</tr>
										<?php 
        if ( secnin_fs()->can_use_premium_code() ) {
            ?>
										<tr valign="top">
											<th scope="row"><label for="email_reports">
													<h3><?php 
            esc_html_e( 'Email Reports', 'security-ninja' );
            ?></h3>
													<p class="description"><?php 
            esc_html_e( 'Email reports with a specified number of latest events can be automatically emailed to alert the admin of any suspicious events. Default: Do not email any reports', 'security-ninja' );
            ?></p>
												</label></th>
											<td><select id="email_reports" name="wf_sn_el[email_reports]" class="regular-text">
													<?php 
            foreach ( $email_reports_settings as $value => $label ) {
                ?>
														<option value="<?php 
                echo esc_attr( $value );
                ?>" <?php 
                selected( self::$options['email_reports'], $value );
                ?>>
															<?php 
                echo esc_html( $label );
                ?>
														</option>
													<?php 
            }
            ?>
												</select>

											</td>
										</tr>
										<?php 
            $selected_modules = (array) self::$options['email_modules'];
            ?>
										<tr valign="top">
											<th scope="row"><label for="email_modules">
													<h3><?php 
            esc_html_e( 'Modules Included in Email Reports', 'security-ninja' );
            ?>
												</label></h3>
												<p class="description"><?php 
            esc_html_e( 'If you don\'t want to receive event reports from specific modules, deselect them. Default: all modules.', 'security-ninja' );
            ?></p>
											</th>
											<td><select size="12" id="email_modules" multiple="multiple" name="wf_sn_el[email_modules][]">
													<?php 
            foreach ( $modules as $value => $label ) {
                ?>
														<option value="<?php 
                echo esc_attr( $value );
                ?>" <?php 
                selected( in_array( $value, $selected_modules ), true );
                ?>>
															<?php 
                echo esc_html( $label );
                ?>
														</option>
													<?php 
            }
            ?>
												</select>

											</td>
										</tr>
										<tr valign="top">
											<th scope="row"><label for="email_to">
													<h3><?php 
            esc_html_e( 'Email Recipient', 'security-ninja' );
            ?></h3>
													<p class="description"><?php 
            esc_html_e( 'One or more email addresses who will receive the reports. Separate more recipients with comma. Default: WP admin email.', 'security-ninja' );
            ?></p>
												</label></th>
											<td></td>
										</tr>
										<tr>
											<td colspan="2"><input type="text" class="regular-text" id="email_to" name="wf_sn_el[email_to]" value="<?php 
            echo esc_html( self::$options['email_to'] );
            ?>" />

											</td>
										</tr>
										<tr valign="top">
											<th scope="row"><label for="retention">
													<h3><?php 
            esc_html_e( 'Log Retention Policy', 'security-ninja' );
            ?></h3>
													<p class="description"><?php 
            esc_html_e( 'In order to preserve disk space logs are automatically deleted based on this option. Default: keep logs for 7 days.', 'security-ninja' );
            ?></p>
												</label></th>
											<td><select id="retention" name="wf_sn_el[retention]" class="regular-text">
													<?php 
            foreach ( $retention_settings as $value => $label ) {
                ?>
														<option value="<?php 
                echo esc_attr( $value );
                ?>" <?php 
                selected( self::$options['retention'], $value );
                ?>>
															<?php 
                echo esc_html( $label );
                ?>
														</option>
													<?php 
            }
            ?>
												</select>
											</td>
										</tr>
										<?php 
        }
        ?>
										<tr valign="top">
											<th scope="row"><label for="">
													<h3><?php 
        esc_html_e( 'Miscellaneous', 'security-ninja' );
        ?></h3>
													<p class="description"><?php 
        esc_html_e( 'Delete all logged events in the database. Please note that there is NO undo for this action.', 'security-ninja' );
        ?></p>
												</label></th>
										</tr>
										<tr>
											<td colspan="2"><input type="button" value="<?php 
        esc_html_e( 'Delete all log entries', 'security-ninja' );
        ?>" class="button-secondary button" id="sn-el-truncate" />

											</td>
										</tr>
									</tbody>
								</table>
								<?php 
        if ( !secnin_fs()->can_use_premium_code() ) {
            ?>
								<div class="sncard infobox" style="margin-top: 20px;">
									<div class="inner">
										<h3><?php 
            esc_html_e( 'Upgrade to Pro for Advanced Event Auditing', 'security-ninja' );
            ?></h3>
										<p><?php 
            esc_html_e( 'The free version of Events Logger provides basic event auditing for your website, including login and failed login tracking. Upgrade to Security Ninja Pro to unlock powerful features:', 'security-ninja' );
            ?></p>
										<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
											<li><?php 
            esc_html_e( 'Email reports with customizable frequency and module selection', 'security-ninja' );
            ?></li>
											<li><?php 
            esc_html_e( 'Advanced log retention policies for long-term auditing', 'security-ninja' );
            ?></li>
											<li><?php 
            esc_html_e( 'Webhook integrations for real-time event notifications', 'security-ninja' );
            ?></li>
											<li><?php 
            esc_html_e( 'Geolocation data for security events', 'security-ninja' );
            ?></li>
											<li><?php 
            esc_html_e( 'Advanced filtering and search capabilities', 'security-ninja' );
            ?></li>
											<li><?php 
            esc_html_e( 'Comprehensive tracking of all WordPress actions and changes', 'security-ninja' );
            ?></li>
										</ul>
										<p style="margin-top: 15px;">
											<a href="<?php 
            echo esc_url( secnin_fs()->get_upgrade_url() );
            ?>" class="button button-primary"><?php 
            esc_html_e( 'Upgrade to Pro', 'security-ninja' );
            ?></a>
										</p>
									</div>
								</div>
								<?php 
        }
        ?>
							</div>
						</div>
					</div>

					<div id="sn_el_notifications" class="wf-sn-el-subtab" style="display:none;">
						<?php 
        if ( secnin_fs()->can_use_premium_code() ) {
            ?>
							<div class="sncard settings-card">
								<h2><?php 
            esc_html_e( 'Notification Settings', 'security-ninja' );
            ?></h2>
								<p><?php 
            esc_html_e( 'Configure notifications for important security events', 'security-ninja' );
            ?></p>
								<table class="form-table">
									<tr>
										<th scope="row">
											<label for="wf_sn_el_notify_new_admin">
												<h3><?php 
            esc_html_e( 'New Admin User Notifications', 'security-ninja' );
            ?></h3>
												<p class="description">
													<?php 
            esc_html_e( 'Get notified when a new administrator user is created', 'security-ninja' );
            ?>
												</p>
											</label>
										</th>
										<td class="sn-cf-options">
											<?php 
            \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_el_notify_new_admin', array(
                'saved_value' => ( isset( self::$options['notify_new_admin'] ) ? self::$options['notify_new_admin'] : 0 ),
                'option_key'  => 'wf_sn_el[notify_new_admin]',
            ) );
            ?>

										</td>
									</tr>

									<tr class="notify-new-admin-email">
										<th scope="row">
											<label for="wf_sn_el_new_admin_notification_email">
												<h3><?php 
            esc_html_e( 'Notification Email', 'security-ninja' );
            ?></h3>
												<p class="description">
													<?php 
            esc_html_e( 'Email address that will receive notifications about new admin users', 'security-ninja' );
            ?>
												</p>
											</label>
										</th>
									</tr>
									<tr>
										<td colspan="2" class="fullwidth">
											<input
												name="wf_sn_el[new_admin_notification_email]"
												type="text"
												value="<?php 
            echo esc_attr( ( !empty( self::$options['new_admin_notification_email'] ) ? self::$options['new_admin_notification_email'] : $current_user->user_email ) );
            ?>"
												class="regular-text">

										</td>
									</tr>
								</table>
							</div>
						<?php 
        } else {
            ?>
							<table class="form-table">
								<tbody>
									<tr>
										<td colspan="2">
											<div class="sncard infobox">
												<div class="inner">
													<h3><?php 
            esc_html_e( 'Upgrade to Pro for Notification Settings', 'security-ninja' );
            ?></h3>
													<p><?php 
            esc_html_e( 'The free version provides basic event logging. Upgrade to Security Ninja Pro to unlock notification features:', 'security-ninja' );
            ?></p>
													<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
														<li><?php 
            esc_html_e( 'Get notified when new administrator users are created', 'security-ninja' );
            ?></li>
														<li><?php 
            esc_html_e( 'Customize notification email addresses', 'security-ninja' );
            ?></li>
													</ul>
													<p style="margin-top: 15px;">
														<a href="<?php 
            echo esc_url( secnin_fs()->get_upgrade_url() );
            ?>" class="button button-primary"><?php 
            esc_html_e( 'Upgrade to Pro', 'security-ninja' );
            ?></a>
													</p>
												</div>
											</div>
										</td>
									</tr>
								</tbody>
							</table>
						<?php 
        }
        ?>
					</div>

					<?php 
        if ( secnin_fs()->can_use_premium_code() ) {
            ?>
					<div id="sn_el_webhooks" class="wf-sn-el-subtab" style="display:none;">
						<div class="sncard settings-card">
							<h2><?php 
            esc_html_e( 'Webhook Settings', 'security-ninja' );
            ?></h2>
							<p><?php 
            esc_html_e( 'Configure webhooks to integrate with external services', 'security-ninja' );
            ?></p>

							<div class="sncard infobox">
								<div class="inner">
									<h3><?php 
            esc_html_e( 'Webhooks Integration', 'security-ninja' );
            ?></h3>
									<p><?php 
            esc_html_e( 'Webhooks are sent as POST requests to the URL you specify. The request body contains a JSON object with information about the event that triggered the webhook.', 'security-ninja' );
            ?></p>
								</div>
							</div>




							<table class="form-table">
								<tr valign="top">
									<th scope="row">
										<label for="webhook_active">
											<h3><?php 
            esc_html_e( 'Webhook Active', 'security-ninja' );
            ?></h3>
											<p class="description"><?php 
            esc_html_e( 'If enabled the webhook URL will be notified about the selected events.', 'security-ninja' );
            ?></p>
										</label>
									</th>
									<td class="sn-cf-options">
										<?php 
            \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'webhook_active', array(
                'saved_value' => ( !empty( self::$options['webhook_active'] ) ? self::$options['webhook_active'] : 0 ),
                'option_key'  => 'wf_sn_el[webhook_active]',
            ) );
            ?>

									</td>
								</tr>
								<tr valign="top">
									<th scope="row"><label for="webhook_url">
											<h3><?php 
            esc_html_e( 'Webhook URL', 'security-ninja' );
            ?></h3>
											<p class="description"><?php 
            esc_html_e( 'Webhooks are sent as POST requests to the URL you specify. The request body contains a JSON object with information about the event that triggered the webhook. You can use this information to take action in your own systems.', 'security-ninja' );
            ?></p>
										</label></th>
								</tr>
								<tr>
									<td colspan="2" class="fullwidth"><input type="text" class="regular-text code" id="webhook_url" name="wf_sn_el[webhook_url]" value="<?php 
            echo esc_url( ( isset( self::$options['webhook_url'] ) ? self::$options['webhook_url'] : '' ) );
            ?>" placeholder="https://" />

									</td>
								</tr>
								<tr valign="top">
									<th scope="row">
										<h3><?php 
            esc_html_e( 'Events', 'security-ninja' );
            ?></h3>
										<p class="description"><?php 
            esc_html_e( 'Select the events you want to send as webhooks. Webhooks are sent as POST requests to the specified URL. Each request contains a JSON object with details about the event, enabling you to react or log these events in your system. Note: Changes apply to future events only.', 'security-ninja' );
            ?></p>
										</label>
									</th>
								</tr>

								<tr>
									<th scope="row">
										<label for="webhook_firewall_events">
											<h3><?php 
            esc_html_e( 'Firewall events', 'security-ninja' );
            ?></h3>
											<p class="description"><?php 
            esc_html_e( 'Notify about blocked visitors', 'security-ninja' );
            ?></p>
										</label>
									</th>
									<td class="sn-cf-options">
										<?php 
            \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'webhook_firewall_events', array(
                'saved_value' => ( !empty( self::$options['webhook_firewall_events'] ) ? self::$options['webhook_firewall_events'] : 0 ),
                'option_key'  => 'wf_sn_el[webhook_firewall_events]',
            ) );
            ?>
									</td>
								</tr>

								<tr>
									<th>
										<label for="webhook_user_logins">
											<h3><?php 
            esc_html_e( 'User logins', 'security-ninja' );
            ?></h3>
											<p class="description"><?php 
            esc_html_e( 'Notify on failed and successful logins', 'security-ninja' );
            ?></p>
										</label>
									</th>
									<td class="sn-cf-options">
										<?php 
            \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'webhook_user_logins', array(
                'saved_value' => ( !empty( self::$options['webhook_user_logins'] ) ? self::$options['webhook_user_logins'] : 0 ),
                'option_key'  => 'wf_sn_el[webhook_user_logins]',
            ) );
            ?>
									</td>
								</tr>
								<tr>
									<th>
										<label for="webhook_updates">
											<h3><?php 
            esc_html_e( 'Updates', 'security-ninja' );
            ?></h3>
											<p class="description"><?php 
            esc_html_e( 'Notify about WordPress, plugins, and themes updates', 'security-ninja' );
            ?></p>
										</label>
									</th>
									<td class="sn-cf-options">
										<?php 
            \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'webhook_updates', array(
                'saved_value' => ( !empty( self::$options['webhook_updates'] ) ? self::$options['webhook_updates'] : 0 ),
                'option_key'  => 'wf_sn_el[webhook_updates]',
            ) );
            ?>
									</td>
								</tr>
							</table>
						</div>
					</div>
					<?php 
        } else {
            ?>
					<div id="sn_el_webhooks" class="wf-sn-el-subtab" style="display:none;">
						<table class="form-table">
							<tbody>
								<tr>
									<td colspan="2">
										<div class="sncard infobox">
											<div class="inner">
												<h3><?php 
            esc_html_e( 'Upgrade to Pro for Webhook Integrations', 'security-ninja' );
            ?></h3>
												<p><?php 
            esc_html_e( 'The free version provides basic event logging. Upgrade to Security Ninja Pro to unlock webhook integrations:', 'security-ninja' );
            ?></p>
												<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
													<li><?php 
            esc_html_e( 'Real-time webhook notifications for security events', 'security-ninja' );
            ?></li>
													<li><?php 
            esc_html_e( 'Integrate with external services and APIs', 'security-ninja' );
            ?></li>
													<li><?php 
            esc_html_e( 'Customize which events trigger webhooks', 'security-ninja' );
            ?></li>
													<li><?php 
            esc_html_e( 'Send POST requests with JSON event data', 'security-ninja' );
            ?></li>
													<li><?php 
            esc_html_e( 'Monitor firewall events, user logins, and updates', 'security-ninja' );
            ?></li>
													<li><?php 
            esc_html_e( 'Build custom integrations with your workflow tools', 'security-ninja' );
            ?></li>
												</ul>
												<p style="margin-top: 15px;">
													<a href="<?php 
            echo esc_url( secnin_fs()->get_upgrade_url() );
            ?>" class="button button-primary"><?php 
            esc_html_e( 'Upgrade to Pro', 'security-ninja' );
            ?></a>
												</p>
											</div>
										</div>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
					<?php 
        }
        ?>

					<p class="submit">
						<input type="submit" value="<?php 
        esc_html_e( 'Save Changes', 'security-ninja' );
        ?>" class="button-primary input-button" name="Submit" />
					</p>
				</form>
			</div>
		</div>


<?php 
    }

    /**
     * clean-up when deactivated
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @access  public static
     * @return  void
     */
    public static function deactivate() {
        if ( !isset( self::$options['remove_settings_deactivate'] ) ) {
            return;
        }
        if ( self::$options['remove_settings_deactivate'] ) {
            global $wpdb;
            delete_option( 'wf_sn_el' );
            $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_el' );
        }
        // Clear both old and new cron jobs
        wp_clear_scheduled_hook( 'wf_sn_check_new_admins' );
        wp_clear_scheduled_hook( 'secnin_check_direct_admin_creation' );
    }

}

add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\wf_sn_el', 'init') );
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\wf_sn_el', 'deactivate') );