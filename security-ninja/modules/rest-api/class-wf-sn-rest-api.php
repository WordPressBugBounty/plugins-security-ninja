<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Security Ninja REST API Class
 * 
 * Provides secure REST API endpoints for dashboard integration
 * 
 * @author Lars Koudal
 * @since v5.242
 * @version v1.0.0
 */
class Wf_Sn_Rest_Api {
    /**
     * API namespace
     */
    const API_NAMESPACE = 'wp-security-ninja/v1';

    /**
     * Flag to control which endpoints are active
     * Set to true to enable all endpoints, false to only enable /info
     */
    const ENABLE_ALL_ENDPOINTS = false;

    /**
     * Initialize the REST API module
     */
    public static function init() {
        add_action( 'rest_api_init', array(__CLASS__, 'register_routes') );
        add_action( 'rest_api_init', array(__CLASS__, 'add_cors_headers') );
        add_action( 'rest_api_init', array(__CLASS__, 'add_security_headers') );
    }

    /**
     * Register REST API routes
     */
    public static function register_routes() {
        // Site information endpoint - always enabled
        register_rest_route( self::API_NAMESPACE, '/info', array(
            'methods'             => 'GET',
            'callback'            => array(__CLASS__, 'get_site_info'),
            'permission_callback' => array(__CLASS__, 'check_permissions'),
            'args'                => array(),
        ) );
        // Only register other endpoints if ENABLE_ALL_ENDPOINTS is true
        if ( self::ENABLE_ALL_ENDPOINTS ) {
            // Trigger security scan endpoint
            register_rest_route( self::API_NAMESPACE, '/scan', array(
                'methods'             => 'POST',
                'callback'            => array(__CLASS__, 'trigger_scan'),
                'permission_callback' => array(__CLASS__, 'check_permissions'),
                'args'                => array(
                    'scan_type'    => array(
                        'required'          => false,
                        'type'              => 'string',
                        'enum'              => array('quick', 'full', 'custom'),
                        'default'           => 'full',
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                    'priority'     => array(
                        'required'          => false,
                        'type'              => 'string',
                        'enum'              => array('low', 'normal', 'high'),
                        'default'           => 'normal',
                        'sanitize_callback' => 'sanitize_text_field',
                    ),
                    'callback_url' => array(
                        'required'          => false,
                        'type'              => 'string',
                        'format'            => 'uri',
                        'sanitize_callback' => 'esc_url_raw',
                    ),
                ),
            ) );
            // Configuration update endpoint
            register_rest_route( self::API_NAMESPACE, '/config', array(
                'methods'             => 'POST',
                'callback'            => array(__CLASS__, 'update_config'),
                'permission_callback' => array(__CLASS__, 'check_permissions'),
                'args'                => array(
                    'settings' => array(
                        'required'          => true,
                        'type'              => 'object',
                        'validate_callback' => array(__CLASS__, 'validate_settings'),
                    ),
                ),
            ) );
            // Get scan results endpoint
            register_rest_route( self::API_NAMESPACE, '/results', array(
                'methods'             => 'GET',
                'callback'            => array(__CLASS__, 'get_scan_results'),
                'permission_callback' => array(__CLASS__, 'check_permissions'),
                'args'                => array(
                    'limit' => array(
                        'required'          => false,
                        'type'              => 'integer',
                        'minimum'           => 1,
                        'maximum'           => 100,
                        'default'           => 10,
                        'sanitize_callback' => 'absint',
                    ),
                ),
            ) );
            // Get vulnerabilities endpoint
            register_rest_route( self::API_NAMESPACE, '/vulnerabilities', array(
                'methods'             => 'GET',
                'callback'            => array(__CLASS__, 'get_vulnerabilities'),
                'permission_callback' => array(__CLASS__, 'check_permissions'),
                'args'                => array(),
            ) );
            // Get firewall status endpoint
            register_rest_route( self::API_NAMESPACE, '/firewall', array(
                'methods'             => 'GET',
                'callback'            => array(__CLASS__, 'get_firewall_status'),
                'permission_callback' => array(__CLASS__, 'check_permissions'),
                'args'                => array(),
            ) );
        }
    }

    /**
     * Check if user has permission to access the API
     * 
     * @return bool|WP_Error
     */
    public static function check_permissions() {
        // Check if this is a dashboard request
        $dashboard_request = isset( $_SERVER['HTTP_X_DASHBOARD_REQUEST'] ) && $_SERVER['HTTP_X_DASHBOARD_REQUEST'] === 'true';
        if ( !$dashboard_request ) {
            return new \WP_Error('rest_forbidden', 'Dashboard request header required.', array(
                'status' => 403,
            ));
        }
        // Check for Bearer token
        $auth_header = ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ? $_SERVER['HTTP_AUTHORIZATION'] : '' );
        if ( empty( $auth_header ) || !preg_match( '/Bearer\\s+(.*)$/i', $auth_header, $matches ) ) {
            return new \WP_Error('rest_forbidden', 'Valid authorization header required.', array(
                'status' => 401,
            ));
        }
        $token = $matches[1];
        // Validate the token
        if ( !self::validate_api_token( $token ) ) {
            return new \WP_Error('rest_forbidden', 'Invalid API token.', array(
                'status' => 401,
            ));
        }
        // Check rate limiting
        $rate_limit_check = self::check_rate_limit();
        if ( is_wp_error( $rate_limit_check ) ) {
            return $rate_limit_check;
        }
        return true;
    }

    /**
     * Add CORS headers for dashboard requests
     */
    public static function add_cors_headers() {
        if ( isset( $_SERVER['HTTP_X_DASHBOARD_REQUEST'] ) && $_SERVER['HTTP_X_DASHBOARD_REQUEST'] === 'true' ) {
            // Get allowed origins from settings or use default
            $allowed_origins = get_option( 'wf_sn_api_allowed_origins', array('https://wpsecuritydashboard.com') );
            $origin = ( isset( $_SERVER['HTTP_ORIGIN'] ) ? $_SERVER['HTTP_ORIGIN'] : '' );
            // Check if origin is allowed
            if ( in_array( $origin, $allowed_origins ) || in_array( '*', $allowed_origins ) ) {
                header( 'Access-Control-Allow-Origin: ' . $origin );
            } else {
                header( 'Access-Control-Allow-Origin: https://wpsecuritydashboard.com' );
            }
            header( 'Access-Control-Allow-Methods: GET, POST, OPTIONS' );
            header( 'Access-Control-Allow-Headers: Authorization, Content-Type, X-Dashboard-Request, X-Requested-With' );
            header( 'Access-Control-Max-Age: 86400' );
            // 24 hours
            header( 'Access-Control-Allow-Credentials: false' );
            // Handle preflight requests
            if ( $_SERVER['REQUEST_METHOD'] === 'OPTIONS' ) {
                http_response_code( 200 );
                exit;
            }
        }
    }

    /**
     * Add security headers
     */
    public static function add_security_headers() {
        if ( isset( $_SERVER['HTTP_X_DASHBOARD_REQUEST'] ) && $_SERVER['HTTP_X_DASHBOARD_REQUEST'] === 'true' ) {
            header( 'X-Content-Type-Options: nosniff' );
            header( 'X-Frame-Options: DENY' );
            header( 'X-XSS-Protection: 1; mode=block' );
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
            header( 'Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';' );
        }
    }

    /**
     * Validate API token
     * 
     * @param string $token The API token to validate
     * @return bool
     */
    private static function validate_api_token( $token ) {
        // Verify and decode JWT token
        $payload = Wf_Sn_Crypto::verify_jwt( $token );
        if ( !$payload ) {
            return false;
        }
        // Check if token is for the correct site
        if ( isset( $payload['site_id'] ) && $payload['site_id'] !== Wf_Sn_Crypto::get_site_id() ) {
            return false;
        }
        return true;
    }

    /**
     * Generate a secure API token
     * 
     * @return string
     */
    public static function generate_api_token() {
        $payload = array(
            'site_id' => Wf_Sn_Crypto::get_site_id(),
            'type'    => 'api_access',
        );
        return Wf_Sn_Crypto::generate_jwt( $payload, 30 * 24 * 60 * 60 );
        // 30 days
    }

    /**
     * Get the current API token for display purposes
     * 
     * @return string
     */
    public static function get_current_api_token() {
        return self::generate_api_token();
    }

    /**
     * Get site information
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function get_site_info( $request ) {
        $scores = wf_sn::return_test_scores();
        $info = array(
            'site_url'       => get_site_url(),
            'plugin_version' => wf_sn::get_plugin_version(),
            'license_status' => ( secnin_fs()->can_use_premium_code__premium_only() ? 'premium' : 'free' ),
            'install_id'     => secnin_fs()->get_site()->id,
            'public_key'     => secnin_fs()->get_public_key(),
            'user_id'        => ( secnin_fs()->is_registered() ? secnin_fs()->get_user()->id : get_current_user_id() ),
        );
        return new \WP_REST_Response($info, 200);
    }

    /**
     * Trigger a security scan
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function trigger_scan( $request ) {
        $scan_type = $request->get_param( 'scan_type' );
        $priority = $request->get_param( 'priority' );
        $callback_url = $request->get_param( 'callback_url' );
        // Run the scan
        $results = wf_sn::run_all_tests( true );
        // Update last scan timestamp
        update_option( 'wf_sn_last_scan', current_time( 'mysql' ), false );
        // Send callback if provided
        if ( !empty( $callback_url ) ) {
            self::send_callback( $callback_url, $results );
        }
        $response = array(
            'success'   => true,
            'message'   => __( 'Security scan completed successfully.', 'security-ninja' ),
            'scan_id'   => uniqid( 'scan_' ),
            'timestamp' => current_time( 'mysql' ),
            'results'   => $results,
        );
        return new \WP_REST_Response($response, 200);
    }

    /**
     * Update plugin configuration
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function update_config( $request ) {
        $settings = $request->get_param( 'settings' );
        // Validate and sanitize settings
        $validated_settings = self::validate_and_sanitize_settings( $settings );
        if ( is_wp_error( $validated_settings ) ) {
            return new \WP_REST_Response(array(
                'success' => false,
                'message' => $validated_settings->get_error_message(),
            ), 400);
        }
        // Update the settings
        $current_options = get_option( 'wf_sn_options', array() );
        $updated_options = array_merge( $current_options, $validated_settings );
        update_option( 'wf_sn_options', $updated_options, false );
        $response = array(
            'success'          => true,
            'message'          => __( 'Configuration updated successfully.', 'security-ninja' ),
            'updated_settings' => $validated_settings,
        );
        return new \WP_REST_Response($response, 200);
    }

    /**
     * Get scan results
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function get_scan_results( $request ) {
        $limit = $request->get_param( 'limit' );
        global $wpdb;
        $table_name = $wpdb->prefix . 'wf_sn_tests';
        $results = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table_name} ORDER BY timestamp DESC LIMIT %d", $limit ), ARRAY_A );
        return new \WP_REST_Response($results, 200);
    }

    /**
     * Get vulnerabilities information
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function get_vulnerabilities( $request ) {
        return new \WP_REST_Response(array(
            'success' => false,
            'message' => __( 'Vulnerability scanning is a premium feature.', 'security-ninja' ),
        ), 403);
        $vulns = Wf_Sn_Vu::return_vulnerabilities();
        $vuln_count = Wf_Sn_Vu::return_vuln_count();
        $response = array(
            'total_vulnerabilities' => $vuln_count,
            'vulnerabilities'       => $vulns,
            'last_updated'          => get_option( 'wf_sn_vu_last_update', '' ),
        );
        return new \WP_REST_Response($response, 200);
    }

    /**
     * Get firewall status
     * 
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public static function get_firewall_status( $request ) {
        return new \WP_REST_Response(array(
            'success' => false,
            'Firewall is a premium feature.',
        ), 403);
        $firewall_options = get_option( 'wf_sn_cf', array() );
        $response = array(
            'active'              => ( isset( $firewall_options['active'] ) ? (bool) $firewall_options['active'] : false ),
            'blocked_countries'   => ( isset( $firewall_options['blocked_countries'] ) ? $firewall_options['blocked_countries'] : array() ),
            'blacklist_count'     => ( isset( $firewall_options['blacklist'] ) ? count( $firewall_options['blacklist'] ) : 0 ),
            'whitelist_count'     => ( isset( $firewall_options['whitelist'] ) ? count( $firewall_options['whitelist'] ) : 0 ),
            'max_login_attempts'  => ( isset( $firewall_options['max_login_attempts'] ) ? $firewall_options['max_login_attempts'] : 5 ),
            'bruteforce_ban_time' => ( isset( $firewall_options['bruteforce_ban_time'] ) ? $firewall_options['bruteforce_ban_time'] : 120 ),
        );
        return new \WP_REST_Response($response, 200);
    }

    /**
     * Validate settings object
     * 
     * @param array $settings
     * @return bool|WP_Error
     */
    public static function validate_settings( $settings ) {
        if ( !is_array( $settings ) ) {
            return new \WP_Error('invalid_settings', 'Settings must be an object.');
        }
        // Add validation for specific settings here
        $allowed_settings = array(
            'scan_frequency',
            'auto_quarantine',
            'email_alerts',
            'firewall_mode'
        );
        foreach ( $settings as $key => $value ) {
            if ( !in_array( $key, $allowed_settings, true ) ) {
                return new \WP_Error('invalid_setting', 'Setting is not allowed');
            }
        }
        return true;
    }

    /**
     * Validate and sanitize settings
     * 
     * @param array $settings
     * @return array|WP_Error
     */
    private static function validate_and_sanitize_settings( $settings ) {
        $sanitized = array();
        if ( isset( $settings['scan_frequency'] ) ) {
            $sanitized['scan_frequency'] = absint( $settings['scan_frequency'] );
        }
        if ( isset( $settings['auto_quarantine'] ) ) {
            $sanitized['auto_quarantine'] = (bool) $settings['auto_quarantine'];
        }
        if ( isset( $settings['email_alerts'] ) ) {
            $sanitized['email_alerts'] = (bool) $settings['email_alerts'];
        }
        if ( isset( $settings['firewall_mode'] ) ) {
            $allowed_modes = array('strict', 'moderate', 'relaxed');
            if ( in_array( $settings['firewall_mode'], $allowed_modes, true ) ) {
                $sanitized['firewall_mode'] = sanitize_text_field( $settings['firewall_mode'] );
            }
        }
        return $sanitized;
    }

    /**
     * Get enabled features
     * 
     * @return array
     */
    private static function get_enabled_features() {
        $features = array('security_tests');
        return $features;
    }

    /**
     * Get MySQL version
     * 
     * @return string
     */
    private static function get_mysql_version() {
        global $wpdb;
        return $wpdb->db_version();
    }

    /**
     * Send callback to dashboard
     * 
     * @param string $callback_url
     * @param array $data
     */
    private static function send_callback( $callback_url, $data ) {
        $response = wp_remote_post( $callback_url, array(
            'body'    => json_encode( $data ),
            'headers' => array(
                'Content-Type'              => 'application/json',
                'X-Security-Ninja-Callback' => 'true',
            ),
            'timeout' => 30,
        ) );
    }

    /**
     * Check rate limiting and request size
     * 
     * @param mixed $result
     * @param WP_REST_Server $server
     * @param WP_REST_Request $request
     * @return mixed
     */
    public static function check_rate_limit( $result = null, $server = null, $request = null ) {
        // Check request size limit (1MB)
        $content_length = ( isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0 );
        $max_size = 1024 * 1024;
        // 1MB
        if ( $content_length > $max_size ) {
            return new \WP_Error('rest_request_entity_too_large', 'Request entity too large. Maximum size is 1MB.', array(
                'status' => 413,
            ));
        }
        $client_ip = self::get_client_ip();
        $rate_limit_key = 'wf_sn_api_rate_limit_' . md5( $client_ip );
        // Get current rate limit data
        $rate_data = get_transient( $rate_limit_key );
        $current_time = time();
        if ( !$rate_data ) {
            $rate_data = array(
                'requests'      => 1,
                'window_start'  => $current_time,
                'blocked_until' => 0,
            );
        } else {
            // Check if currently blocked
            if ( $rate_data['blocked_until'] > $current_time ) {
                return new \WP_Error('rest_too_many_requests', 'Rate limit exceeded. Please try again later.', array(
                    'status' => 429,
                ));
            }
            // Reset window if expired (1 hour window)
            if ( $current_time - $rate_data['window_start'] > 3600 ) {
                $rate_data = array(
                    'requests'      => 1,
                    'window_start'  => $current_time,
                    'blocked_until' => 0,
                );
            } else {
                $rate_data['requests']++;
            }
        }
        // Apply rate limits: 100 requests per hour, 10 requests per minute
        $hourly_limit = 100;
        $minute_limit = 10;
        if ( $rate_data['requests'] > $hourly_limit ) {
            $rate_data['blocked_until'] = $current_time + 3600;
            // Block for 1 hour
            set_transient( $rate_limit_key, $rate_data, 7200 );
            return new \WP_Error('rest_too_many_requests', 'Hourly rate limit exceeded. Please try again later.', array(
                'status' => 429,
            ));
        }
        // Check minute-based limit (last 60 seconds)
        $minute_requests = 0;
        $minute_data = get_transient( $rate_limit_key . '_minute' );
        if ( $minute_data && $current_time - $minute_data['start'] < 60 ) {
            $minute_requests = $minute_data['count'];
        }
        if ( $minute_requests >= $minute_limit ) {
            return new \WP_Error('rest_too_many_requests', 'Rate limit exceeded. Please slow down your requests.', array(
                'status' => 429,
            ));
        }
        // Update minute counter
        set_transient( $rate_limit_key . '_minute', array(
            'count' => $minute_requests + 1,
            'start' => $current_time,
        ), 120 );
        // Store rate limit data
        set_transient( $rate_limit_key, $rate_data, 7200 );
        // Log API access for security monitoring
        self::log_api_access( $request, $client_ip );
        return null;
    }

    /**
     * Log API access for security monitoring
     * 
     * @param WP_REST_Request|null $request
     * @param string $client_ip
     */
    private static function log_api_access( $request, $client_ip ) {
        $log_data = array(
            'timestamp'  => current_time( 'mysql' ),
            'ip'         => $client_ip,
            'method'     => ( $request ? $request->get_method() : $_SERVER['REQUEST_METHOD'] ?? 'Unknown' ),
            'endpoint'   => ( $request ? $request->get_route() : $_SERVER['REQUEST_URI'] ?? 'Unknown' ),
            'user_agent' => ( $request ? $request->get_header( 'user_agent' ) : (( isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown' )) ),
            'origin'     => ( $request ? $request->get_header( 'origin' ) : (( isset( $_SERVER['HTTP_ORIGIN'] ) ? $_SERVER['HTTP_ORIGIN'] : 'Unknown' )) ),
        );
        // Store in WordPress options for admin review
        $api_logs = get_option( 'wf_sn_api_access_logs', array() );
        $api_logs[] = $log_data;
        // Keep only last 1000 entries
        if ( count( $api_logs ) > 1000 ) {
            $api_logs = array_slice( $api_logs, -1000 );
        }
        update_option( 'wf_sn_api_access_logs', $api_logs, false );
    }

    /**
     * Get client IP address
     * 
     * @return string
     */
    private static function get_client_ip() {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        foreach ( $ip_keys as $key ) {
            if ( array_key_exists( $key, $_SERVER ) === true ) {
                foreach ( explode( ',', $_SERVER[$key] ) as $ip ) {
                    $ip = trim( $ip );
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
                        return $ip;
                    }
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

}

// Initialize the REST API module
Wf_Sn_Rest_Api::init();