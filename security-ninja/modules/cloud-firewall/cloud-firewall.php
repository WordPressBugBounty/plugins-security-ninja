<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
define( 'WF_SN_CF_OPTIONS_KEY', 'wf_sn_cf' );
// @important - if changed, this is used various places, 2FA, etc.
define( 'WF_SN_CF_VALIDATED_CRAWLERS', 'wf_sn_cf_validated_crawlers' );
class Wf_sn_cf {
    private static $cached_ip = null;

    public static $options = null;

    public static $banned_ips = null;

    // Bruges til at cache lokalt bannede IPs så ikke indlæst hver pageload.
    public static $central_api_url = 'https://api.securityninjawp.com/wp-json/secnin/v1/';

    public static function init() {
        // Load options if not already loaded
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        // update geolocation database via SN_Geolocation in class-sn-geolocation.php
        // setup_theme seems to be earliest hook - because of Freemius API - Future - add as mu-plugin - plugins_loaded earliest possible hook
        if ( self::$options['active'] ) {
            add_action( 'template_redirect', array(__CLASS__, 'check_visitor'), 1 );
            add_action( 'login_head', array(__NAMESPACE__ . '\\wf_sn_cf', 'check_visitor'), 1 );
        }
        add_action( 'init', array(__NAMESPACE__ . '\\wf_sn_cf', 'do_init_action'), 1 );
        // Basic login/failed login logging for all versions
        add_action(
            'wp_login',
            array(__NAMESPACE__ . '\\wf_sn_cf', 'log_successful_login'),
            10,
            2
        );
        add_action( 'wp_login_failed', array(__NAMESPACE__ . '\\wf_sn_cf', 'failed_login') );
        if ( is_admin() ) {
            // add tab to Security Ninja tabs
            add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\wf_sn_cf', 'sn_tabs') );
            // Register settings
            add_action( 'admin_init', array(__NAMESPACE__ . '\\wf_sn_cf', 'register_settings') );
            // Register AJAX actions
            add_action( 'wp_ajax_sn_enable_firewall', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_enable_firewall') );
            add_action( 'wp_ajax_sn_disable_firewall', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_disable_firewall') );
            add_action( 'wp_ajax_sn_test_ip', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_test_ip') );
            add_action( 'wp_ajax_sn_clear_blacklist', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_clear_blacklist') );
            // Enqueue scripts and styles
            add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\wf_sn_cf', 'enqueue_scripts') );
        }
    }

    /**
     * Process IP only early.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, May 21st, 2024.
     * @version	v1.0.1	Monday, January 13th, 2025 - Added REST API protection
     * @access	public static
     * @return	void
     */
    public static function do_init_action() {
        // Load options if not already loaded
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        // Check for safe URL unlock parameter BEFORE checking bans
        // This allows blocked visitors to whitelist their IP using the secret access URL
        if ( isset( $_REQUEST['snf'] ) && sanitize_key( $_REQUEST['snf'] ) === self::$options['unblock_url'] ) {
            $current_user_ip = self::get_user_ip();
            if ( !in_array( $current_user_ip, self::$options['whitelist'], true ) ) {
                self::$options['whitelist'][] = $current_user_ip;
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'unblocked_ip',
                    'New IP added to the whitelist using the secret access URL.',
                    ''
                );
                update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
            }
            // Return early - don't check bans or kill the request
            return;
        }
        // Enhanced REST API protection - check for wp-json in the URL
        $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
        if ( strpos( $request_uri, '/wp-json/' ) !== false ) {
            return;
        }
        // Additional protection for REST API requests that might not have /wp-json/ in the path
        // but are still legitimate REST API calls
        if ( wp_is_json_request() || defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return;
        }
        $current_user_ip = self::get_user_ip();
        $reason = self::is_banned_ip( $current_user_ip );
        if ( $reason ) {
            // Check if this is a country-based ban
            $is_country_ban = strpos( $reason, 'Country is blocked' ) !== false;
            // For country bans, check countryblock_loginonly setting
            if ( $is_country_ban && isset( self::$options['countryblock_loginonly'] ) && self::$options['countryblock_loginonly'] ) {
            } else {
                // For other ban types, check if 'global' setting is enabled - if not, only block from login pages
                if ( !self::$options['global'] ) {
                }
            }
            self::update_blocked_count( $current_user_ip );
            $ua_string = '';
            if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
                $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
            }
            $data = [
                'user_agent' => $ua_string,
                'ip'         => $current_user_ip,
                'reason'     => $reason,
            ];
            wf_sn_el_modules::log_event(
                'security_ninja',
                'do_init_action',
                'Blocked.',
                $data,
                null,
                $current_user_ip
            );
            wp_clear_auth_cookie();
            self::kill_request(
                $current_user_ip,
                $reason,
                null,
                true
            );
            exit;
        }
        // Only check if firewall is active
        if ( 1 === (int) self::$options['active'] && 1 === (int) self::$options['filterqueries'] ) {
            // Determine if user is whitelisted (but still check for suspicious requests)
            $whitelisted_user = false;
            if ( current_user_can( 'manage_options' ) ) {
                $whitelisted_user = true;
            }
            if ( in_array( $current_user_ip, self::$options['whitelist'], true ) ) {
                $whitelisted_user = true;
            }
            // Always check for bad queries (even for whitelisted users), but skip AJAX, cron, and admin requests
            if ( !wp_doing_ajax() && !wp_doing_cron() && !is_admin() ) {
                $bad_query = self::check_bad_queries();
                if ( $bad_query !== false ) {
                    // Detects if we are importing
                    if ( defined( 'WP_IMPORTING' ) && $bad_query ) {
                        // set the query to false, not going to block but we left a notice
                        $bad_query = false;
                    }
                    if ( $bad_query ) {
                        $extramessage = '';
                        $extraarr = [
                            'ban_type' => '',
                        ];
                        if ( isset( $bad_query['request_uri'] ) ) {
                            $extraarr['ban_reason'] = $bad_query['request_uri'];
                            $extraarr['ban_type'] = 'request_uri';
                            $extramessage = 'request_uri';
                        }
                        if ( isset( $bad_query['query_string'] ) ) {
                            $extraarr['ban_type'] = 'query_string';
                            $extraarr['ban_reason'] = $bad_query['query_string'];
                        }
                        if ( isset( $bad_query['http_user_agent'] ) ) {
                            $extraarr['ban_type'] = 'http_user_agent';
                            $extraarr['ban_reason'] = $bad_query['http_user_agent'];
                        }
                        if ( isset( $bad_query['referrer'] ) ) {
                            $extraarr['ban_type'] = 'referrer';
                            $extraarr['ban_reason'] = $bad_query['referrer'];
                        }
                        if ( isset( $bad_query['blocked_host'] ) ) {
                            $extraarr['ban_type'] = 'blocked_host';
                            $extraarr['ban_reason'] = $bad_query['visitor_host'];
                        }
                        $extraarr = array_merge( $extraarr, $bad_query );
                        $extraarr['ip'] = $current_user_ip;
                        $ua_string = ( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '' );
                        $extraarr['user_agent'] = $ua_string;
                        $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url( $_SERVER['REQUEST_URI'] ) : '' );
                        if ( !empty( $request_uri ) ) {
                            $extraarr['request_uri'] = $request_uri;
                        }
                        $query_string = ( isset( $_SERVER['QUERY_STRING'] ) ? esc_url( $_SERVER['QUERY_STRING'] ) : '' );
                        if ( !empty( $query_string ) ) {
                            $extraarr['query_string'] = $query_string;
                        }
                        $http_referer = ( isset( $_SERVER['HTTP_REFERER'] ) ? esc_url( $_SERVER['HTTP_REFERER'] ) : '' );
                        if ( !empty( $http_referer ) ) {
                            $extraarr['http_referer'] = $http_referer;
                        }
                        $blockedmessage = __( 'Suspicious Request', 'security-ninja' );
                        if ( isset( $extramessage ) ) {
                            $blockedmessage .= ' ' . $extramessage;
                        }
                        // Always log suspicious requests, even for whitelisted users
                        $log_action = ( $whitelisted_user ? 'suspicious_request_whitelisted' : 'blocked_ip_suspicious_request' );
                        $log_message = ( $whitelisted_user ? __( 'Suspicious Request (Whitelisted - Not Blocked)', 'security-ninja' ) . (( $extramessage ? ' ' . $extramessage : '' )) : $blockedmessage );
                        wf_sn_el_modules::log_event(
                            'security_ninja',
                            $log_action,
                            $log_message,
                            $extraarr
                        );
                        // Only block non-whitelisted users
                        if ( !$whitelisted_user ) {
                            // Update blocked count
                            self::update_blocked_count( $current_user_ip );
                            // Block the request
                            wp_clear_auth_cookie();
                            self::kill_request(
                                $current_user_ip,
                                $extraarr['ban_reason'],
                                1 * HOUR_IN_SECONDS,
                                true
                            );
                            exit;
                        }
                        // For whitelisted users, log but allow the request to continue
                    }
                }
            }
        }
    }

    /**
     * Basic logging for successful login (free version)
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, January 14th, 2025.
     * @param	mixed	$user_login	
     * @param	mixed	$user      	
     * @return	void
     */
    public static function log_successful_login( $user_login, $user ) {
        if ( !is_object( $user ) || !isset( $user->ID ) ) {
            return;
        }
        $current_user_ip = self::get_user_ip();
        $ua_string = '';
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
        }
        $description = sprintf( 
            /* translators: 1: User login name, 2: IP address */
            __( '%1$s logged in successfully from %2$s', 'security-ninja' ),
            esc_html( $user_login ),
            esc_html( $current_user_ip )
         );
        $event_data = array(
            'ip'         => $current_user_ip,
            'username'   => $user_login,
            'user_id'    => $user->ID,
            'user_agent' => $ua_string,
        );
        wf_sn_el_modules::log_event(
            'security_ninja',
            'wp_login',
            $description,
            $event_data,
            $user->ID
        );
    }

    /**
     * Sets a timestamp for the user when successfully logging in.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, February 6th, 2024.
     * @param	mixed	$user_login	
     * @param	mixed	$user      	
     * @return	void
     */
    public static function set_login_timestamp( $user_login, $user ) {
        if ( !is_object( $user ) || !isset( $user->ID ) ) {
            return;
        }
        update_user_meta( $user->ID, 'sn_last_login', current_time( 'mysql' ) );
    }

    /**
     * endsWith. - ref https://www.php.net/manual/en/function.str-ends-with.php
     *
     * @author  javalc6 at gmail dot com
     * @since   v0.0.1
     * @version v1.0.0  Monday, August 30th, 2021.
     * @param   mixed   $haystack
     * @param   mixed   $needle
     * @return  mixed
     */
    private static function string_ends_with( $haystack, $needle ) {
        $length = strlen( $needle );
        return ( $length > 0 ? substr( $haystack, -$length ) === $needle : true );
    }

    /**
     * Validate a crawlers IP against the hostname
     *
     * @author	Lars Koudal
     * @since	v5.123
     * @version	v1.0.0	Monday, August 30th, 2021.	
     * @version	v1.0.1	Monday, June 3rd, 2024.
     * @access	private static
     * @param	mixed	$testip	
     * @return	boolean
     */
    public static function validate_crawler_ip( $testip ) {
        // Lets check if the IP has already been validated
        $validated_crawlers = get_option( WF_SN_CF_VALIDATED_CRAWLERS );
        if ( $validated_crawlers ) {
            if ( in_array( $testip, $validated_crawlers, true ) ) {
                return true;
            }
        } else {
            $validated_crawlers = array();
        }
        $hostname = strtolower( gethostbyaddr( $testip ) );
        //"crawl-66-249-66-1.googlebot.com"
        $valid_host_names = array(
            '.crawl.baidu.com',
            '.crawl.baidu.jp',
            '.search.msn.com',
            '.google.com',
            '.googlebot.com',
            '.crawl.yahoo.net',
            '.yandex.ru',
            '.yandex.net',
            '.yandex.com',
            '.search.msn.com',
            '.petalsearch.com',
            'applebot.apple.com',
            '.ahrefs.com',
            // Added Ahrefs
            '.semrush.com',
            '.duckduckgo.com',
            'facebookexternalhit.com',
            '.commoncrawl.org',
            '.googleother.com',
            '.google-inspectiontool.com',
            '.swiftype.com',
            '.sogou.com',
            '.yahoo.com',
            '.bing.com',
        );
        foreach ( $valid_host_names as $valid_host ) {
            if ( self::string_ends_with( $hostname, $valid_host ) ) {
                $returned_ip = gethostbyname( $hostname );
                if ( $returned_ip === $testip ) {
                    $validated_crawlers[] = $testip;
                    update_option( WF_SN_CF_VALIDATED_CRAWLERS, $validated_crawlers, false );
                    wf_sn_el_modules::log_event(
                        'security_ninja',
                        'validated_crawler_ip',
                        'Valid Crawler' . esc_attr( $hostname ),
                        '',
                        '',
                        esc_attr( $testip )
                    );
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if an IP is from a service that has been enabled
     *
     * This method checks if the given IP address is whitelisted for services such as Broken Link Checker, WP Rocket, ManageWP, UptimeRobot, and WPCompress.
     * It also checks for IP ranges (CIDR) in the whitelist.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Wednesday, May 8th, 2024.
     * @access	public static
     * @param	mixed	$current_user_ip	The IP address to check against the whitelist.
     * @return	boolean					Returns true if the IP is whitelisted, false otherwise.
     */
    public static function is_whitelisted_service( $current_user_ip ) {
        $whitelist_brokenlink = [
            '94.231.107.9',
            // Broken Link Checker
            '54.191.137.17',
        ];
        $whitelist_wprocket = [];
        if ( isset( self::$options['whitelist_wprocket'] ) && self::$options['whitelist_wprocket'] ) {
            $whitelist_wprocket = [
                '109.234.160.58',
                // WP Rocket - Load CSS async
                '51.83.15.135',
                // WP Rocket - Load CSS async
                '51.210.39.196',
                // WP Rocket - Load CSS async
                '146.59.192.120',
                // WP Rocket - license validation
                '135.125.83.227',
                // WP Rocket - Remove unused CSS
                '146.59.251.59',
            ];
        }
        $extra_whitelist = [
            // Divi Dash
            '67.227.164.200',
            '67.227.164.201',
            '67.227.164.202',
            // Fastpixel
            '23.88.6.90',
            '136.243.103.55',
            '176.9.77.187',
            '5.161.48.189',
            // WPMU Dev
            '18.204.159.253',
            '54.227.51.40',
            '18.219.56.14',
            '45.55.78.242',
            '35.171.56.101',
            '34.196.51.17',
            '35.157.144.199',
            '165.227.251.117',
            '165.227.251.120',
            '140.82.60.49',
            '45.63.10.140',
            '18.219.161.157',
            '165.227.127.103',
            '64.176.196.23',
            '144.202.86.106',
            '3.93.131.0',
            '167.71.93.101',
            '167.71.179.192',
        ];
        /*
        		@todo - 
        IP addresses used by wpcompress.com resolve to rDNS names in the format api.wpcompress.com. To simplify firewall configurations and ensure you're whitelisting the correct IP addresses, you can whitelist IPs based on the domain *.wpcompress.com by resolving the rDNS of our IPs.
        */
        $whitelist_wpcompress = [
            '168.119.147.46',
            '71.19.240.35',
            '216.52.183.178',
            '167.160.91.242',
            '51.79.230.163',
            '51.161.208.134',
            '213.133.103.23',
            '162.55.161.208',
            '213.239.197.231',
            '88.99.209.68',
            '2a01:4f8:251:a11::/64',
            '2605:9f80:c000:240::2/64',
            '2605:9f80:1000:461::2/64',
            '2402:1f00:8001:11a3::/64',
            '2402:1f00:8201:486::/64',
            '2a01:4f8:a0:90d5::/64',
            '2a01:4f8:c012:bb07::/64',
            '2a01:4f8:222:1059::/64',
            '2a01:4f8:10a:3a47::/64'
        ];
        // Hardcoded, not an option - always whitelisted.
        $whitelist_modulards = [
            '54.220.170.248/32',
            '34.249.165.39/32',
            '63.34.51.157/32',
            '54.73.153.210/32',
            '52.210.126.224/32'
        ];
        $whitelist_managewp = [];
        if ( isset( self::$options['whitelist_managewp'] ) && self::$options['whitelist_managewp'] ) {
            $whitelist_managewp_path = 'whitelist-managewp.php';
            if ( file_exists( $whitelist_managewp_path ) ) {
                // Load ranges from a local file.
                $whitelist_managewp = (include $whitelist_managewp_path);
            }
        }
        $whitelist_uptimia = [];
        if ( isset( self::$options['whitelist_uptimia'] ) && self::$options['whitelist_uptimia'] ) {
            $whitelist_uptimia_path = 'whitelist-uptimia.php';
            if ( file_exists( $whitelist_uptimia_path ) ) {
                // Load ranges from a local file.
                $whitelist_uptimia = (include $whitelist_uptimia_path);
            }
        }
        $whitelist_uptimerobot = [];
        if ( isset( self::$options['whitelist_uptimerobot'] ) && self::$options['whitelist_uptimerobot'] ) {
            $whitelist_uptimerobot_path = 'whitelist-uptimia.php';
            if ( file_exists( $whitelist_uptimerobot_path ) ) {
                // Load ranges from a local file.
                $whitelist_uptimerobot = (include $whitelist_uptimerobot_path);
            }
        }
        $whitelist = array_merge(
            $whitelist_brokenlink,
            $whitelist_wprocket,
            $whitelist_managewp,
            $whitelist_uptimia,
            $whitelist_wpcompress,
            $extra_whitelist,
            $whitelist_uptimerobot,
            $whitelist_modulards
        );
        foreach ( $whitelist as $whitelist_item ) {
            // Check if the current whitelist item is an IP range (CIDR)
            if ( strpos( $whitelist_item, '/' ) !== false ) {
                // Use the proper CIDR matching function
                if ( self::ipCIDRMatch( $current_user_ip, $whitelist_item ) ) {
                    return true;
                    // IP is whitelisted
                }
            } else {
                if ( $current_user_ip === $whitelist_item ) {
                    return true;
                    // IP is whitelisted
                }
            }
        }
        return false;
        // IP is not whitelisted
    }

    /**
     * Check visitor and apply firewall rules
     * 
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Monday, January 13th, 2025 - Added additional REST API protection
     * @access  public static
     * @return  void
     */
    public static function check_visitor() {
        global $wpdb;
        // Enhanced REST API protection - check for wp-json in the URL
        $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
        if ( strpos( $request_uri, '/wp-json/' ) !== false ) {
            return;
        }
        // Additional protection for REST API requests that might not have /wp-json/ in the path
        // but are still legitimate REST API calls
        if ( wp_is_json_request() || defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return;
        }
        // Filter out AJAX, cron and admin related requests
        if ( wp_doing_ajax() || wp_doing_cron() || is_admin() ) {
            return;
        }
        $server_host = gethostname();
        $server_ip = gethostbyname( $server_host );
        $whitelisted_user = false;
        $administrator = false;
        // @todo next linie - implementer egen løsning med bonus for at finde land hvis slået til
        $visit_logged = false;
        $current_user_ip = self::get_user_ip();
        if ( $server_ip === $current_user_ip ) {
            return;
        }
        if ( current_user_can( 'manage_options' ) ) {
            // A user with admin privileges
            $administrator = true;
            $whitelisted_user = true;
        }
        // Prevents user from being blocked even from a blocked country if IP is whitelisted
        if ( in_array( $current_user_ip, self::$options['whitelist'], true ) ) {
            $whitelisted_user = true;
        }
        if ( self::is_whitelisted_service( $current_user_ip ) ) {
            $whitelisted_user = true;
        }
        if ( in_array( $current_user_ip, ['::1', '127.0.0.1'], true ) ) {
            $whitelisted_user = false;
            $administrator = false;
        }
        $ua_string = '';
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
        }
        $current_user_country = '';
        // Processing
        // Note: Secret access URL check is handled by do_init_action() for all users
        // Checks if IP is from a known crawler
        if ( !$whitelisted_user && self::validate_crawler_ip( $current_user_ip ) ) {
            // Validated crawler
            $whitelisted_user = true;
        }
        // Check if an IP is banned and blocks
        if ( !$whitelisted_user && 1 === (int) self::$options['active'] ) {
            $ban_reason = self::is_banned_ip( $current_user_ip );
            if ( $ban_reason ) {
                // Check if 'global' setting is enabled - if not, only block from login pages
                if ( !self::$options['global'] ) {
                    // Free version: always block banned IPs
                    wf_sn_el_modules::log_event(
                        'security_ninja',
                        'blocked_ip_banned',
                        __( 'IP is blocked.', 'security-ninja' ),
                        array(
                            'ip'         => $current_user_ip,
                            'ban_reason' => $ban_reason,
                        )
                    );
                    self::update_blocked_count( $current_user_ip );
                    self::kill_request();
                    return;
                }
                // Free version: basic logging
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'blocked_ip_banned',
                    __( 'IP is blocked.', 'security-ninja' ),
                    array(
                        'ip'         => $current_user_ip,
                        'ban_reason' => $ban_reason,
                    )
                );
                self::update_blocked_count( $current_user_ip );
                self::kill_request();
            }
        }
        // Check bad queries only if filterqueries is enabled
        if ( 1 === (int) self::$options['active'] && 1 === (int) self::$options['filterqueries'] ) {
            $bad_query = self::check_bad_queries();
            // Always check for bad queries (even for whitelisted users), but only block non-whitelisted users
            if ( $bad_query !== false ) {
                // Detects if we are importing
                if ( defined( 'WP_IMPORTING' ) && $bad_query ) {
                    // set the query to false, not going to block but we left a notice
                    $bad_query = false;
                }
                if ( $bad_query ) {
                    $extramessage = '';
                    $extraarr = [
                        'ban_type' => '',
                    ];
                    if ( isset( $bad_query['request_uri'] ) ) {
                        $extraarr['ban_reason'] = $bad_query['request_uri'];
                        $extraarr['ban_type'] = 'request_uri';
                        $extramessage = 'request_uri';
                    }
                    if ( isset( $bad_query['query_string'] ) ) {
                        $extraarr['ban_type'] = 'query_string';
                        $extraarr['ban_reason'] = $bad_query['query_string'];
                    }
                    if ( isset( $bad_query['http_user_agent'] ) ) {
                        $extraarr['ban_type'] = 'http_user_agent';
                        $extraarr['ban_reason'] = $bad_query['http_user_agent'];
                    }
                    if ( isset( $bad_query['referrer'] ) ) {
                        $extraarr['ban_type'] = 'referrer';
                        $extraarr['ban_reason'] = $bad_query['referrer'];
                    }
                    if ( isset( $bad_query['blocked_host'] ) ) {
                        $extraarr['ban_type'] = 'blocked_host';
                        $extraarr['ban_reason'] = $bad_query['visitor_host'];
                    }
                    $extraarr = array_merge( $extraarr, $bad_query );
                    $extraarr['ip'] = $current_user_ip;
                    $extraarr['user_agent'] = $ua_string;
                    $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url( $_SERVER['REQUEST_URI'] ) : '' );
                    if ( !empty( $request_uri ) ) {
                        $extraarr['request_uri'] = $request_uri;
                    }
                    $query_string = ( isset( $_SERVER['QUERY_STRING'] ) ? esc_url( $_SERVER['QUERY_STRING'] ) : '' );
                    if ( !empty( $query_string ) ) {
                        $extraarr['query_string'] = $query_string;
                    }
                    $http_referer = ( isset( $_SERVER['HTTP_REFERER'] ) ? esc_url( $_SERVER['HTTP_REFERER'] ) : '' );
                    if ( !empty( $http_referer ) ) {
                        $extraarr['http_referer'] = $http_referer;
                    }
                    $blockedmessage = __( 'Suspicious Request', 'security-ninja' );
                    if ( isset( $extramessage ) ) {
                        $blockedmessage .= ' ' . $extramessage;
                    }
                    // Always log suspicious requests, even for whitelisted users
                    $log_action = ( $whitelisted_user ? 'suspicious_request_whitelisted' : 'blocked_ip_suspicious_request' );
                    $log_message = ( $whitelisted_user ? __( 'Suspicious Request (Whitelisted - Not Blocked)', 'security-ninja' ) . (( $extramessage ? ' ' . $extramessage : '' )) : $blockedmessage );
                    wf_sn_el_modules::log_event(
                        'security_ninja',
                        $log_action,
                        $log_message,
                        $extraarr
                    );
                    $extraarr = array_merge( $extraarr, $bad_query );
                    // Only block non-whitelisted users
                    if ( !$whitelisted_user ) {
                        self::update_blocked_count( $current_user_ip );
                        self::kill_request(
                            $current_user_ip,
                            $extraarr['ban_reason'],
                            1 * HOUR_IN_SECONDS,
                            true
                        );
                    }
                    // For whitelisted users, log but allow the request to continue
                }
            }
        }
    }

    /**
     * Checks for bad queries - CBQ - Taken with a little shame from BBQ - thank you for the superfast firewall
     * Based on 8G Firewall by Jeff Starr - https://perishablepress.com/8g-blacklist/
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  array
     */
    /**
     * Check for suspicious queries and patterns
     * 
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Monday, January 13th, 2025 - Added REST API protection
     * @version v1.0.2  Tuesday, January 14th, 2025 - Improved REST API protection for booking plugins
     * @access  public static
     * @return  array|false Array with match details or false if no match
     */
    public static function check_bad_queries() {
        // Enhanced REST API protection - check for wp-json in the URL
        $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
        if ( strpos( $request_uri, '/wp-json/' ) !== false ) {
            return false;
        }
        // Additional protection for REST API requests that might not have /wp-json/ in the path
        // but are still legitimate REST API calls
        if ( wp_is_json_request() || defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return false;
        }
        $request_uri_array = apply_filters( 'request_uri_items', array(
            '3commas'             => ',{3,}',
            '7_or_more_hyphens'   => '-{7,}',
            'caret_backtick'      => '[\\^`<>\\|]',
            'alnum_long'          => '[a-z0-9]{2000,}',
            'eq_backslash'        => '=?\\\\(\'|%27)/?\\.',
            'special_chars'       => '/(\\*|"|\'|\\.|,|&|&amp;?)/?$',
            'php_file'            => '\\.(php)(\\()?([0-9]+)(\\))?(/)?$',
            'header_cookie'       => '/(.*)(header:|set-cookie:)(.*)=',
            'config_files'        => '\\.(s?ftp-?)config|(s?ftp-?)config\\.',
            'file_editors'        => '/(f?ckfinder|fck/|f?ckeditor|fullclick)',
            'download_framework'  => '/((force-)?download|framework/main)(\\.php)',
            'misc_chars'          => '\\{0\\}|"0"="0|/\\(/\\|\\.\\.\\.|\\+\\+\\+|\\\\"',
            'vbulletin'           => '/(vbull(etin)?|boards|vbforum|vbweb|webvb)(/)?',
            'permalink'           => '(\\.|20)(get|the)(_)(permalink|posts_page_url)\\(',
            'complex_injections'  => '///|\\?\\?|/&&|/\\*(.*)\\*/|/:/|\\\\|0x00|%00|%0d%0a',
            'alfa_cgi'            => '(/)(cgi_?)?alfa(_?cgiapi|_?data|_?v[0-9]+)?(\\.php)',
            'thumbnail_php'       => '(thumbs?(_editor|open)?|tim(thumbs?)?)((\\.|%2e)php)',
            'admin_php'           => '(/)((boot)?_?admin(er|istrator|s)(_events)?)(\\.php)',
            'sensitive_user_dirs' => '(/%7e)(root|ftp|bin|nobody|named|guest|logs|sshd)(/)',
            'backup_files'        => '(archive|backup|db|master|sql|wp|www|wwwroot)\\.(gz|zip)',
            'shell_scripts'       => '(/)(\\.?mad|alpha|c99|php|web)?sh(3|e)ll([0-9]+|\\w)(\\.php)',
            'upload_scripts'      => '(/)(admin-?|file-?)(upload)(bg|_?file|ify|svu|ye)?(\\.php)',
            'sensitive_dirs'      => '(/)(etc|var)(/)(hidden|secret|shadow|ninja|passwd|tmp)(/)?',
            'url_manipulation'    => '(s)?(ftp|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))',
            'query_manipulation'  => '(/)(=|\\$&?|&?(pws|rk)=0|_mm|_vti_|cgi(\\.|-)?|(=|/|;|,)nt\\.)',
            'sensitive_files'     => '(\\.)(ds_store|htaccess|htpasswd|init?|mysql-select-db)(/)?',
            'bin_commands'        => '(/)(bin)(/)(cc|chmod|chsh|cpp|echo|id|kill|mail|nasm|perl|ping|ps|python|tclsh)(/)?',
            'obfuscated_js'       => '(/)?j(\\s+)?a(\\s+)?v(\\s+)?a(\\s+)?s(\\s+)?c(\\s+)?r(\\s+)?i(\\s+)?p(\\s+)?t(\\s+)?(%3a|:)',
            'server_dirs'         => '(/)(filemanager|htdocs|httpdocs|https?|mailman|mailto|msoffice|undefined|usage|var|vhosts|webmaster|www)(/)',
            'injection_attempts'  => '(\\(null\\)|\\{\\$itemURL\\}|cast\\(0x|echo(.*)kae|etc/passwd|eval\\(|null(.*)null|open_basedir|self/environ|\\+union\\+all\\+select)',
            'config_files'        => '(/)(db-?|j-?|my(sql)?-?|setup-?|web-?|wp-?)?(admin-?)?(setup-?)?(conf\\b|conf(ig)?)(uration)?(\\.?bak|\\.inc)?(\\.inc|\\.old|\\.php|\\.txt)',
            'exploit_paths'       => '(/)((.*)crlf-?injection|(.*)xss-?protection|__(inc|jsc)|administrator|author-panel|cgi-bin|database|downloader|(db|mysql)-?admin)(/)',
            'malicious_php'       => '(/)(haders|head|helpear|incahe|includes?|indo(sec)?|infos?|install|ioptimizes?|jmail|js|king|kiss|kodox|kro|legion|libsoft)(\\.php)',
            'info_leak_paths'     => '(/)(awstats|document_root|dologin\\.action|error.log|extension/ext|htaccess\\.|lib/php|listinfo|phpunit/php|remoteview|server/php|www\\.root\\.)',
            'code_execution'      => '(base64_(en|de)code|benchmark|curl_exec|e?chr|eval\\(|function|fwrite|(f|p)open|html|leak|passthru|p?fsockopen|phpinfo)(.*)(\\(|%28)(.*)(\\)|%29)',
            'process_management'  => '(posix_(kill|mkfifo|setpgid|setsid|setuid)|(child|proc)_(close|get_status|nice|open|terminate)|(shell_)?exec|system)(.*)(\\(|%28)(.*)(\\)|%29)',
            'remote_admin_tools'  => '(/)((c99|php|web)?shell|crossdomain|fileditor|locus7|nstview|php(get|remoteview|writer)|r57|remview|sshphp|storm7|webadmin)(.*)(\\.|%2e|\\(|%28)',
            'wp_paths'            => '/((wp-)((201\\d|202\\d|[0-9]{2})|ad|admin(fx|rss|setup)|booking|confirm|crons|data|file|mail|one|plugins?|readindex|reset|setups?|story))(\\.php)',
            'various_php'         => '(/)(^$|-|\\!|\\w|\\.(.*)|100|123|([^iI])?ndex|index\\.php/index|7yn|90sec|aill|ajs\\.delivery|al277|alexuse?|ali|allwrite)(\\.php)',
            'site_management'     => '(/)(analyser|apache|apikey|apismtp|authenticat(e|ing)|autoload_classmap|backup(_index)?|bakup|bkht|black|bogel|bookmark|bypass|cachee?)(\\.php)',
            'cleanup_scripts'     => '(/)(clean|cm(d|s)|con|connector\\.minimal|contexmini|contral|curl(test)?|data(base)?|db|db-cache|db-safe-mode|defau11|defau1t|dompdf|dst)(\\.php)',
            'exploit_scripts'     => '(/)(elements|emails?|error.log|ecscache|edit-form|eval-stdin|export|evil|fbrrchive|filemga|filenetworks?|f0x|gank(\\.php)?|gass|gel|guide)(\\.php)',
            'custom_scripts'      => '(/)(logo_img|lufix|mage|marg|mass|mide|moon|mssqli|mybak|myshe|mysql|mytag_js?|nasgor|newfile|news|nf_?tracking|nginx|ngoi|ohayo|old-?index)(\\.php)',
            'diagnostic_scripts'  => '(/)(olux|owl|pekok|petx|php-?info|phpping|popup-pomo|priv|r3x|radio|rahma|randominit|readindex|readmy|reads|repair-?bak|robot(s\\.txt)?|root)(\\.php)',
            'system_control'      => '(/)(router|savepng|semayan|shell|shootme|sky|socket(c|i|iasrgasf)ontrol|sql(bak|_?dump)?|sym403|sys|system_log|tmp-?(uploads)?)(\\.php)',
            'admin_tools'         => '(/)(traffic-advice|u2p|udd|ukauka|up__uzegp|up14|upa?|upxx?|vega|vip|vu(ln)?(\\w)?|webroot|weki|wikindex|wp_logns?|wp_wrong_datlib)(\\.php)',
            'cms_scripts'         => '(/)((wp-?)?install(ation)?|wp(3|4|5|6)|wpfootes|wpzip|ws0|wsdl|wso(\\w)?|www|(uploads|wp-admin)?xleet(-shell)?|xmlsrpc|xup|xxu|zibi|zipy)(\\.php)',
            'malware_signatures'  => '(bkv74|cachedsimilar|core-stab|crgrvnkb|ctivrc|deadcode|deathshop|e7xue|eqxafaj90zir|exploits|ffmkpcal|filellli7|(fox|sid)wso|gel4y|goog1es|gvqqpinc)',
            'common_exploits'     => '(@md5|00\\.temp00|0byte|0d4y|0xor|wso1337|1h6j5|40dd1d|4price|70bex?|a57bze893|abbrevsprl|abruzi|adminer|aqbmkwwx|archivarix|beez5|bgvzc29)',
            'exploit_keywords'    => '(handler_to_code|hax(0|o)r|hmei7|hnap1|home_url=|ibqyiove|icxbsx|indoxploi|jahat|jijle3|kcrew|laobiao|lock360|mod_(aratic|ariimag))',
            'exploit_tools'       => '(mobiquo|muiebl|nessus|osbxamip|priv8|qcmpecgy|r3vn330|racrew|raiz0|reportserver|r00t|respectmus|rom2823|roseleif|sh3ll|site((.){0,2})copier|sqlpatch|sux0r)',
            'exploit_signatures'  => '(sym403|telerik|uddatasql|utchiha|visualfrontend|w0rm|wangdafa|wpyii2|wsoyanzo|x5cv|xattack|xbaner|xertive|xiaolei|xltavrat|xorz|xsamxad|xsvip|xxxs?s?|zabbix|zebda)',
        ) );
        $query_string_array = apply_filters( 'query_string_items', array(
            'start_hyphen'           => '^(-|%2d)[^=]+$',
            'long_alnum'             => '[a-z0-9]{4000,}',
            'url_obfuscate'          => '(/|%2f)(:|%3a)(/|%2f)',
            'sensitive_files'        => 'etc/(hosts|motd|shadow)',
            'sql_injection_order'    => 'order(\\s|%20)by(\\s|%20)1--',
            'asterisk_injection'     => '(/|%2f)(\\*|%2a)(\\*|%2a)(/|%2f)',
            'special_chars'          => '(`|<|>|\\^|\\||0x00|%00|%0d%0a)',
            'file_tools'             => '(f?ckfinder|f?ckeditor|fullclick)',
            'header_manipulation'    => '((.*)header:|(.*)set-cookie:(.*)=)',
            'local_ip'               => '(localhost|127(\\.|%2e)0(\\.|%2e)0(\\.|%2e)1)',
            'cmd_injection'          => '(cmd|command)(=|%3d)(chdir|mkdir)(.*)(x20)',
            'php_globals'            => '(globals|mosconfig[a-z_]{1,22}|request)(=|\\[)',
            'wp_config_access'       => '(/|%2f)((wp-)?config)((\\.|%2e)inc)?((\\.|%2e)php)',
            'thumb_exploit'          => '(thumbs?(_editor|open)?|tim(thumbs?)?)((\\.|%2e)php)',
            'dir_path_manipulation'  => '(absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?)',
            'url_injection'          => '(s)?(ftp|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))',
            'wp_permalink_injection' => '(\\.|20)(get|the)(_|%5f)(permalink|posts_page_url)(\\(|%28)',
            'critical_file_access'   => '((boot|win)((\\.|%2e)ini)|etc(/|%2f)passwd|self(/|%2f)environ)',
            'path_traversal'         => '(((/|%2f){3,})|((\\.|%2e){3,})|((\\.|%2e){2,})(/|%2f|%u2215))',
            'code_exec_injection'    => '(benchmark|char|exec|fopen|function|html)(.*)(\\(|%28)(.*)(\\)|%29)',
            'php_object_injection'   => '(php)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            'eval_injection'         => '(e|%65|%45)(v|%76|%56)(a|%61|%31)(l|%6c|%4c)(.*)(\\(|%28)(.*)(\\)|%29)',
            'various_injections'     => '(/|%2f)(=|%3d|$&|_mm|cgi(\\.|\\-)|inurl(:|%3a)(/|%2f)|(mod|path)(=|%3d)(\\.|%2e))',
            'html_embed'             => '(<|%3c)(.*)(e|%65|%45)(m|%6d|%4d)(b|%62|%42)(e|%65|%45)(d|%64|%44)(.*)(>|%3e)',
            'iframe_injection'       => '(<|%3c)(.*)(i|%69|%49)(f|%66|%46)(r|%72|%52)(a|%61|%41)(m|%6d|%4d)(e|%65|%45)(.*)(>|%3e)',
            'object_injection'       => '(<|%3c)(.*)(o|%4f|%6f)(b|%62|%42)(j|%4a|%6a)(e|%65|%45)(c|%63|%43)(t|%74|%54)(.*)(>|%3e)',
            'script_injection'       => '(<|%3c)(.*)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(.*)(>|%3e)',
            'space_delete'           => '(\\+|%2b|%20)(d|%64|%44)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(t|%74|%54)(e|%65|%45)(\\+|%2b|%20)',
            'space_insert'           => '(\\+|%2b|%20)(i|%69|%49)(n|%6e|%4e)(s|%73|%53)(e|%65|%45)(r|%72|%52)(t|%74|%54)(\\+|%2b|%20)',
            'space_select'           => '(\\+|%2b|%20)(s|%73|%53)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(c|%63|%43)(t|%74|%54)(\\+|%2b|%20)',
            'space_update'           => '(\\+|%2b|%20)(u|%75|%55)(p|%70|%50)(d|%64|%44)(a|%61|%41)(t|%74|%54)(e|%65|%45)(\\+|%2b|%20)',
            'sql_null_byte'          => '(\\\\x00|(\\"|%22|\'|%27)?0(\\"|%22|\'|%27)?(=|%3d)(\\"|%22|\'|%27)?0|cast(\\(|%28)0x|or%201(=|%3d)1)',
            'php_globals_access'     => '(g|%67|%47)(l|%6c|%4c)(o|%6f|%4f)(b|%62|%42)(a|%61|%41)(l|%6c|%4c)(s|%73|%53)(=|\\[|%[0-9A-Z]{0,2})',
            'request_array_access'   => '(_|%5f)(r|%72|%52)(e|%65|%45)(q|%71|%51)(u|%75|%55)(e|%65|%45)(s|%73|%53)(t|%74|%54)(=|\\[|%[0-9A-Z]{2,})',
            'js_protocol_injection'  => '(j|%6a|%4a)(a|%61|%41)(v|%76|%56)(a|%61|%31)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(:|%3a)(.*)(;|%3b|\\)|%29)',
            'base64_encode_attempt'  => '(b|%62|%42)(a|%61|%41)(s|%73|%53)(e|%65|%45)(6|%36)(4|%34)(_|%5f)(d|%64|%44)(e|%65|%45|n|%6e|%4e)(c|%63|%43)(o|%6f|%4f)(d|%64|%44)(e|%65|%45)(.*)(\\()(.*)(\\))',
        ) );
        $user_agent_array = apply_filters( 'user_agent_items', array(
            'ua_long_alnum'       => '[a-z0-9]{2000,}',
            'ua_encoded_entities' => '(&lt;|%0a|%0d|%27|%3c|%3e|%00|0x00|\\\\x22)',
            'ua_scraping_tools'   => '(curl|libwww-perl|pycurl|scan)',
            'ua_malicious_tools'  => '(oppo\\sa33|(c99|php|web)shell|site((.){0,2})copier)',
            'ua_command_exec'     => '(base64_decode|bin/bash|disconnect|eval|unserializ)',
            'ua_bots_1'           => '(acapbot|acoonbot|alexibot|asterias|attackbot|awario|backdor|becomebot|binlar|blackwidow|blekkobot|blex|blowfish|bullseye|bunnys|butterfly|careerbot|casper)',
            'ua_bots_2'           => '(checkpriv|cheesebot|cherrypick|chinaclaw|choppy|clshttp|cmsworld|copernic|copyrightcheck|cosmos|crescent|datacha|\\bdemon\\b|diavol|discobot|dittospyder)',
            'ua_bots_3'           => '(dotbot|dotnetdotcom|dumbot|econtext|emailcollector|emailsiphon|emailwolf|eolasbot|eventures|extract|eyenetie|feedfinder|flaming|flashget|flicky|foobot|fuck)',
            'ua_bots_4'           => '(g00g1e|getright|gigabot|go-ahead-got|gozilla|grabnet|grafula|harvest|heritrix|httracks?|icarus6j|jetbot|jetcar|jikespider|kmccrew|leechftp|libweb|liebaofast)',
            'ua_bots_5'           => '(linkscan|linkwalker|loader|lwp-download|majestic|masscan|miner|mechanize|mj12bot|morfeus|moveoverbot|netmechanic|netspider|nicerspro|nikto|nominet|nutch)',
            'ua_bots_6'           => '(octopus|pagegrabber|petalbot|planetwork|postrank|proximic|purebot|queryn|queryseeker|radian6|radiation|realdownload|remoteview|rogerbot|scan|scooter|seekerspid)',
            'ua_bots_7'           => '(semalt|siclab|sindice|sistrix|sitebot|siteexplorer|sitesnagger|skygrid|smartdownload|snoopy|sosospider|spankbot|spbot|sqlmap|stackrambler|stripper|sucker|surftbot)',
            'ua_bots_8'           => '(sux0r|suzukacz|suzuran|takeout|telesoft|true_robots|turingos|turnit|vampire|vikspider|voideye|webleacher|webreaper|webstripper|webvac|webviewer|webwhacker)',
            'ua_bots_9'           => '(winhttp|wwwoffle|woxbot|xaldon|xxxyy|yamanalab|yioopbot|youda|zeus|zmeu|zune|zyborg)',
        ) );
        $referrer_array = apply_filters( 'referrer_items', array(
            'ref_100dollars'      => '100dollars',
            'ref_unlink'          => '@unlink',
            'ref_assert'          => 'assert\\(',
            'ref_best_seo'        => 'best-seo',
            'ref_blue_pill'       => 'blue\\s?pill',
            'ref_cocaine'         => 'cocaine',
            'ref_ejaculat'        => 'ejaculat',
            'ref_erectile'        => 'erectile',
            'ref_erections'       => 'erections',
            'ref_hoodia'          => 'hoodia',
            'ref_huronriveracres' => 'huronriveracres',
            'ref_impotence'       => 'impotence',
            'ref_levitra'         => 'levitra',
            'ref_libido'          => 'libido',
            'ref_lipitor'         => 'lipitor',
            'ref_mopub'           => 'mopub\\.com',
            'ref_order_by'        => 'order(\\s|%20)by(\\s|%20)1--',
            'ref_phentermin'      => 'phentermin',
            'ref_pornhelm'        => 'pornhelm',
            'ref_print_r'         => 'print_r\\(',
            'ref_prozac'          => 'pro[sz]ac',
            'ref_sandyauer'       => 'sandyauer',
            'ref_semalt'          => 'semalt\\.com',
            'ref_social_buttons'  => 'social-buttions',
            'ref_todaperfeita'    => 'todaperfeita',
            'ref_tramadol'        => 'tramadol',
            'ref_troyhamby'       => 'troyhamby',
            'ref_ultram'          => 'ultram',
            'ref_unicauca'        => 'unicauca',
            'ref_valium'          => 'valium',
            'ref_viagra'          => 'viagra',
            'ref_vicodin'         => 'vicodin',
            'ref_x00'             => 'x00',
            'ref_xanax'           => 'xanax',
            'ref_xbshell'         => 'xbshell',
            'ref_ypxaieo'         => 'ypxaieo',
        ) );
        $blocked_hosts_array = apply_filters( 'blocked_hosts_items', array(
            'blocked_163data'           => '163data',
            'blocked_colocrossing'      => 'colocrossing',
            'blocked_crimea'            => 'crimea',
            'blocked_g00g1e'            => 'g00g1e',
            'blocked_justhost'          => 'justhost',
            'blocked_kanagawa'          => 'kanagawa',
            'blocked_loopia'            => 'loopia',
            'blocked_masterhost'        => 'masterhost',
            'blocked_onlinehome'        => 'onlinehome',
            'blocked_poneytel'          => 'poneytel',
            'blocked_sprintdatacenter'  => 'sprintdatacenter',
            'blocked_reverse_softlayer' => 'reverse.softlayer',
            'blocked_safenet'           => 'safenet',
            'blocked_ttnet'             => 'ttnet',
            'blocked_woodpecker'        => 'woodpecker',
            'blocked_wowrack'           => 'wowrack',
        ) );
        $request_uri_string = false;
        $query_string_string = false;
        $user_agent_string = false;
        $referrer_string = false;
        $visitor_host = false;
        if ( isset( $_SERVER['REQUEST_URI'] ) && !empty( $_SERVER['REQUEST_URI'] ) ) {
            $request_uri_string = $_SERVER['REQUEST_URI'];
        }
        if ( isset( $_SERVER['QUERY_STRING'] ) && !empty( $_SERVER['QUERY_STRING'] ) ) {
            $query_string_string = $_SERVER['QUERY_STRING'];
        }
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && !empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $user_agent_string = $_SERVER['HTTP_USER_AGENT'];
        }
        if ( isset( $_SERVER['HTTP_REFERER'] ) && !empty( $_SERVER['HTTP_REFERER'] ) ) {
            $referrer_string = $_SERVER['HTTP_REFERER'];
        }
        if ( isset( $_SERVER['REMOTE_ADDR'] ) && !empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $visitor_host = gethostbyaddr( $_SERVER['REMOTE_ADDR'] );
        }
        if ( $request_uri_string || $query_string_string || $user_agent_string || $referrer_string || $visitor_host ) {
            $response = array();
            foreach ( $blocked_hosts_array as $key => $item ) {
                if ( preg_match( '#\\b' . preg_quote( $item, '#' ) . '\\b#i', $visitor_host, $matches ) ) {
                    $response = [
                        'blocked_host' => esc_html( $matches[0] ),
                        'visitor_host' => esc_html( $visitor_host ),
                        'matched_rule' => esc_html( $key ),
                        'message'      => 'A match was found in the blocked hosts.',
                    ];
                    break;
                }
            }
            foreach ( $request_uri_array as $key => $pattern ) {
                // Direct use of pattern in preg_match, without preg_quote
                if ( preg_match( '#' . $pattern . '#i', $request_uri_string, $req_matches ) ) {
                    $response = [
                        'request_uri'  => esc_html( $req_matches[0] ),
                        'matched_rule' => esc_html( $key ),
                        'message'      => 'A match was found in the request URI.',
                    ];
                    break;
                }
            }
            if ( empty( $response ) ) {
                // Proceed only if no match was found previously
                foreach ( $query_string_array as $key => $item ) {
                    // Directly use the pattern without preg_quote() for regex matching
                    if ( preg_match( '#' . $item . '#i', $query_string_string, $query_matches ) ) {
                        $response = [
                            'query_string'        => esc_html( $query_matches[0] ),
                            'query_string_string' => esc_html( $query_string_string ),
                            'matched_rule'        => esc_html( $key ),
                            'message'             => 'A match was found in the query string.',
                        ];
                        break;
                    }
                }
            }
            if ( empty( $response ) ) {
                // Proceed only if no match was found previously
                foreach ( $user_agent_array as $key => $item ) {
                    // Using '#' as delimiter to avoid conflicts with common characters in user agents
                    if ( preg_match( '#' . $item . '#i', $user_agent_string, $ua_matches ) ) {
                        $response = [
                            'http_user_agent'   => esc_html( $ua_matches[0] ),
                            'user_agent_string' => esc_html( $user_agent_string ),
                            'matched_rule'      => esc_html( $key ),
                            'message'           => 'A match was found in the user agent.',
                        ];
                        break;
                    }
                }
            }
            if ( empty( $response ) ) {
                foreach ( $referrer_array as $key => $item ) {
                    if ( preg_match( '/' . preg_quote( $item, '/' ) . '/i', $referrer_string, $rf_matches ) ) {
                        $response = [
                            'referrer'        => esc_html( $rf_matches[0] ),
                            'referrer_string' => esc_html( $referrer_string ),
                            'matched_rule'    => esc_html( $key ),
                            'message'         => 'A match was found in the referrer.',
                        ];
                        break;
                    }
                }
            }
            if ( !empty( $response ) ) {
                return $response;
            }
        }
        return false;
    }

    /**
     * Terminate current request - Checks if option is set to redirect to an URL first
     *
     * @author	Lars Koudal
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Saturday, December 10th, 2022.	
     * @version	v1.0.2	Wednesday, December 20th, 2023.	
     * @version	v1.0.3	Monday, May 12th, 2025.
     * @access	public static
     * @param	mixed  	$current_user_ip	Default: null
     * @param	string 	$reason         	Default: ''
     * @param	mixed  	$time           	Default: null
     * @param	boolean	$register_block 	Should the IP block be registered in the database. Default: false
     * @return	void
     */
    public static function kill_request(
        $current_user_ip = null,
        $reason = '',
        $time = 1 * DAY_IN_SECONDS,
        $register_block = false
    ) {
        // @todo - update the database with new columns -
        /*
        				$table_name = $wpdb->prefix . 'wf_sn_cf_bl_ips';
        				$sql = "CREATE TABLE {$table_name} (tid datetime NOT NULL DEFAULT NOW(),ip varchar(46) NOT NULL, reason varchar(255) NOT NULL, PRIMARY KEY  (ip),KEY tid (tid)) {$charset}";
        */
        // if ($register_block) {
        // 	$wpdb->insert(
        // 		$wpdp->prefix.'wf_sn_cf_bl_ips',
        // 	)
        // }
        // Set the constant to prevent caching
        if ( !defined( 'DONOTCACHEPAGE' ) ) {
            define( 'DONOTCACHEPAGE', true );
        }
        // Add headers to prevent caching on Cloudflare and other proxies
        header( 'Cache-Control: no-cache, no-store, must-revalidate' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );
        // Add Cloudflare specific header to prevent caching
        header( 'Cache-Tag: dontcache' );
        // Cloudflare specific header to control caching
        header( 'CF-Cache-Status: DYNAMIC' );
        // Forces dynamic content, not cacheable
        // Checks if we need to redirect the killed request.
        $redirect_url = esc_url_raw( self::$options['redirect_url'] );
        if ( isset( $redirect_url ) && wp_http_validate_url( $redirect_url ) ) {
            wp_safe_redirect( $redirect_url, 301 );
            exit;
        }
        $message = '<p>' . esc_html( self::$options['message'] ) . '</p>';
        // Add IP info to message
        if ( is_null( $current_user_ip ) ) {
            $current_user_ip = self::get_user_ip();
        }
        $message .= '<p><small>IP: ' . esc_html( $current_user_ip ) . '</small></p>';
        // Removes a couple of filters that uses a check "is_embed()" which is too soon to be available
        // and that creates a PHP warning.
        remove_filter( 'wp_robots', 'wp_robots_noindex_search' );
        remove_filter( 'wp_robots', 'wp_robots_noindex_embeds' );
        wp_die( $message, 'Blocked', array(
            'response' => 403,
        ) );
    }

    /**
     * Updates global blocked visits count
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $ip IP that was blocked - NOT IN USE YET
     * @return  void
     */
    public static function update_blocked_count( $ip ) {
        // @todo - store block count per IP
        $blocked_count = get_option( 'wf_sn_cf_blocked_count' );
        if ( $blocked_count ) {
            $blocked_count++;
        } else {
            $blocked_count = 1;
        }
        update_option( 'wf_sn_cf_blocked_count', $blocked_count, false );
        // Track blocked visits "today" in site timezone, without storing history.
        $today = current_time( 'Y-m-d' );
        $option_name = 'wf_sn_cf_blocked_today';
        $blocked_today = get_option( $option_name, false );
        if ( false === $blocked_today || !is_array( $blocked_today ) ) {
            $blocked_today = array(
                'date'  => $today,
                'count' => 1,
            );
            add_option(
                $option_name,
                $blocked_today,
                '',
                false
            );
            return;
        }
        $stored_date = ( isset( $blocked_today['date'] ) ? (string) $blocked_today['date'] : '' );
        $stored_count = ( isset( $blocked_today['count'] ) ? (int) $blocked_today['count'] : 0 );
        if ( $stored_date === $today ) {
            $blocked_today['count'] = $stored_count + 1;
        } else {
            $blocked_today['date'] = $today;
            $blocked_today['count'] = 1;
        }
        update_option( $option_name, $blocked_today, false );
    }

    /**
     * Get blocked visits for the current day (site timezone).
     *
     * @return int
     */
    public static function get_blocked_today_count() {
        $today = current_time( 'Y-m-d' );
        $blocked_today = get_option( 'wf_sn_cf_blocked_today', array() );
        if ( !is_array( $blocked_today ) ) {
            return 0;
        }
        $stored_date = ( isset( $blocked_today['date'] ) ? (string) $blocked_today['date'] : '' );
        if ( $stored_date !== $today ) {
            return 0;
        }
        return ( isset( $blocked_today['count'] ) ? (int) $blocked_today['count'] : 0 );
    }

    /**
     * Update local list of blocked IPs.
     * First delete expired > 24 hours.
     * Then download and bulk add entries
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Sunday, May 30th, 2021.
     * @version v1.0.1  Wednesday, June 9th, 2021.
     * @access  public static
     * @global
     * @param   boolean $force  Default: false
     * @return  void
     */
    public static function action_update_blocked_ips( $force = false ) {
        $listips = self::get_network_listips();
        // @todo - right place for it?
        if ( !$listips ) {
            wf_sn_el_modules::log_event( 'security_ninja', 'update_blocked_ips', 'Error getting blocked IPs from server' );
            return false;
        }
        global $wpdb;
        // Cleaning up
        $table_name = $wpdb->prefix . 'wf_sn_cf_bl_ips';
        $delquery = "DELETE FROM `{$table_name}` WHERE HOUR(TIMEDIFF(NOW(), tid))>24;";
        $delres = $wpdb->query( $delquery );
        if ( $delres ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'update_blocked_ips',
                sprintf( esc_html__( 'Removed %1$s IPs from the Blocklist - older than 24 hours.', 'security-ninja' ), intval( $delres ) ),
                ''
            );
        } else {
            wf_sn_el_modules::log_event( 'security_ninja', 'update_blocked_ips', 'No old IPs needs to be removed.' );
        }
        $blockedips = json_decode( $listips, true );
        if ( $blockedips && is_array( $blockedips ) && isset( $blockedips['ips'] ) && is_array( $blockedips['ips'] ) ) {
            global $wpdb;
            $current_count = 0;
            $limit = 15;
            $longquery = '';
            $totalcount = 0;
            $timenow = current_time( 'mysql' );
            foreach ( $blockedips['ips'] as $ip ) {
                if ( 0 === $current_count ) {
                    $longquery .= ' INSERT IGNORE INTO `' . $table_name . "` (`ip`) VALUES ('" . esc_sql( $ip ) . "')";
                } else {
                    $longquery .= ",('" . esc_sql( $ip ) . "')";
                }
                $current_count++;
                if ( $current_count > $limit ) {
                    $longquery .= ';';
                    // add ending semicolon before executing
                    $wpdb->query( $longquery );
                    $longquery = '';
                    $current_count = 0;
                }
                $totalcount++;
            }
            // Leftovers?
            if ( $current_count > 0 ) {
                $longquery .= ';';
                // add ending semicolon before executing
                $wpdb->query( $longquery );
                $longquery = '';
                $current_count = 0;
            }
        }
    }

    /**
     * Prune events log table
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   boolean $force  Default: false
     * @return  boolean
     */
    public static function prune_visitor_log( $force = false ) {
        global $wpdb;
        $trackvisits_howlong = intval( self::$options['trackvisits_howlong'] );
        if ( !$trackvisits_howlong ) {
            $trackvisits_howlong = 2;
            // in days
        }
        $table_name = $wpdb->prefix . 'wf_sn_cf_vl';
        if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) ) === $table_name ) {
            $wpdb->query( 'DELETE FROM ' . $wpdb->prefix . 'wf_sn_cf_vl' . " WHERE timestamp < DATE_SUB(NOW(), INTERVAL {$trackvisits_howlong} DAY);" );
            $max_records = 5000;
            // Sane limit for visitor log entries
            $remaining_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
            if ( $remaining_count > $max_records ) {
                // Find the timestamp of the record that would be the $max_records-th newest
                $cutoff_data = $wpdb->get_row( $wpdb->prepare( "SELECT timestamp, id FROM {$table_name} \n\t\t\t\t\tORDER BY timestamp DESC, id DESC \n\t\t\t\t\tLIMIT 1 OFFSET %d", $max_records - 1 ) );
                if ( $cutoff_data ) {
                    // For records with the same timestamp, delete those with lower IDs
                    $wpdb->query( $wpdb->prepare(
                        "DELETE FROM {$table_name} \n\t\t\t\t\t\tWHERE timestamp < %s \n\t\t\t\t\t\tOR (timestamp = %s AND id < %d)",
                        $cutoff_data->timestamp,
                        $cutoff_data->timestamp,
                        $cutoff_data->id
                    ) );
                }
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_visitor_log',
                    sprintf(
                        esc_html__( 'Pruned firewall visitors log - %1$s days, then reduced to %2$s entries (was %3$s).', 'security-ninja' ),
                        $trackvisits_howlong,
                        $max_records,
                        $remaining_count
                    ),
                    ''
                );
            } else {
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_visitor_log',
                    sprintf( esc_html__( 'Pruned firewall visitors log - %1$s days.', 'security-ninja' ), $trackvisits_howlong ),
                    ''
                );
            }
        }
        return true;
    }

    /**
     * clean-up when deactivated
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Thursday, January 14th, 2021.	
     * @version	v1.0.1	Monday, February 21st, 2022.	
     * @version	v1.0.2	Saturday, November 19th, 2022.
     * @access	public static
     * @return	void
     */
    public static function deactivate() {
        //$centraloptions = Wf_Sn::get_options();
        // $centraloptions = $options = Wf_sn_cf::$options;
        if ( !isset( self::$options['remove_settings_deactivate'] ) ) {
            return;
        }
        if ( self::$options['remove_settings_deactivate'] ) {
            global $wpdb;
            $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_cf_vl' );
            $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_cf_bl_ips' );
            delete_option( 'wf_sn_cf_bl_ips' );
            delete_option( 'wf_sn_cf_vl' );
            delete_option( WF_SN_CF_VALIDATED_CRAWLERS );
            delete_option( 'wf_sn_cf_blocked_count' );
            delete_option( WF_SN_CF_OPTIONS_KEY );
            delete_option( 'wf_sn_cf_ips' );
            delete_option( 'wf_sn_banned_ips' );
            // list of locally banned IPs
        }
    }

    /**
     * Schedule cron jobs
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Thursday, January 14th, 2021.
     * @access  public static
     * @return  void
     */
    public static function schedule_cron_jobs() {
        // Update GEOIP database - once a month
        if ( !wp_next_scheduled( 'secnin_update_geoip' ) ) {
            wp_schedule_event( time() + 30, 'weekly', 'secnin_update_geoip' );
        }
        // Update cloud IPs
        if ( !wp_next_scheduled( 'secnin_update_cloud_firewall' ) ) {
            wp_schedule_event( time() + 15, 'twicedaily', 'secnin_update_cloud_firewall' );
        }
        // Prune local banned IPs (hourly; migrate existing twicedaily to hourly)
        $next_prune = wp_next_scheduled( 'secnin_prune_banned' );
        if ( $next_prune ) {
            wp_unschedule_event( $next_prune, 'secnin_prune_banned' );
        }
        wp_schedule_event( time() + 3600, 'hourly', 'secnin_prune_banned' );
        // Prune visitor log
        if ( !wp_next_scheduled( 'secnin_prune_visitor_log' ) ) {
            wp_schedule_event( time() + 3600, 'twicedaily', 'secnin_prune_visitor_log' );
        }
        // Update blocked IPs from central server
        if ( !wp_next_scheduled( 'secnin_update_blocked_ips' ) ) {
            wp_schedule_event( time() + 45, 'twicedaily', 'secnin_update_blocked_ips' );
        }
    }

    /**
     * Wrapper method to update GEOIP database via cron.
     * Loads the SN_Geolocation class only when needed.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @access  public static
     * @return  void
     */
    public static function update_geoip_database() {
        return;
        // Load the class file if not already loaded
        if ( !class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
            require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-sn-geolocation.php';
        }
        // Call the actual method
        if ( class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
            SN_Geolocation::update_database();
        }
    }

    /**
     * Enqueues JS and CSS needed for Firewall tab
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function enqueue_scripts() {
        if ( !Wf_Sn::is_plugin_page() ) {
            return;
        }
        wp_enqueue_style(
            'select2',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/select2/css/select2.min.css',
            array(),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/select2/css/select2.min.css' )
        );
        wp_enqueue_script(
            'select2',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/select2/js/select2.min.js',
            array('jquery'),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/select2/js/select2.min.js' )
        );
        wp_enqueue_style(
            'sn-cf-css',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/css/wf-sn-cf-min.css',
            array(),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/css/wf-sn-cf-min.css' )
        );
        wp_register_script(
            'sn-cf-js',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/js/wf-sn-cf-min.js',
            array('select2'),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/js/wf-sn-cf-min.js' )
        );
        $js_vars = array(
            'nonce' => wp_create_nonce( 'wf_sn_cf' ),
        );
        wp_localize_script( 'sn-cf-js', 'wf_sn_cf', $js_vars );
        wp_enqueue_script( 'sn-cf-js' );
    }

    /**
     * Return firewall options
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function get_options() {
        if ( !is_null( self::$options ) ) {
            return self::$options;
        }
        $options = get_option( 'wf_sn_cf', array() );
        $defaults = array(
            'active'                        => 0,
            'globalbannetwork'              => 1,
            'global'                        => 0,
            'filterqueries'                 => 1,
            'trackvisits'                   => 1,
            'trackvisits_howlong'           => 7,
            'usecloud'                      => 1,
            'protect_login_form'            => 1,
            'hide_login_errors'             => 1,
            'failed_login_email_warning'    => 0,
            'blocked_countries'             => array(),
            'countryblock_loginonly'        => 0,
            'blacklist'                     => array(),
            'whitelist'                     => array(self::get_user_ip()),
            'whitelist_managewp'            => 1,
            'whitelist_wprocket'            => 0,
            'whitelist_uptimia'             => 0,
            'whitelist_uptimerobot'         => 0,
            'max_login_attempts'            => 5,
            'max_login_attempts_time'       => 5,
            'bruteforce_ban_time'           => 120,
            'login_msg'                     => 'Warning: Multiple failed login attempts will get you locked out temporarily.',
            'login_error_msg'               => 'Something went wrong',
            'message'                       => 'You are not allowed to visit this website.',
            'redirect_url'                  => '',
            'blockadminlogin'               => 0,
            'change_login_url'              => 0,
            'new_login_url'                 => 'my-login',
            'unblock_url'                   => '',
            '2fa_enabled'                   => 0,
            '2fa_enabled_timestamp'         => '',
            '2fa_required_roles'            => array('administrator', 'editor'),
            '2fa_methods'                   => array('app'),
            '2fa_grace_period'              => 14,
            '2fa_backup_codes_enabled'      => 1,
            '2fa_intro'                     => 'Secure your account with two-factor authentication.',
            '2fa_enter_code'                => 'Enter the code from your 2FA app to continue logging in.',
            '404guard_enabled'              => 1,
            '404guard_threshold'            => 10,
            '404guard_window'               => 300,
            '404guard_block_time'           => 600,
            'woo_rate_limiting_enabled'     => 0,
            'woo_checkout_rate_limit'       => 3,
            'woo_checkout_window'           => 300,
            'woo_add_to_cart_limit'         => 10,
            'woo_add_to_cart_window'        => 60,
            'woo_order_rate_limit'          => 2,
            'woo_order_window'              => 600,
            'woo_coupon_protection_enabled' => 0,
            'woo_coupon_failed_attempts'    => 3,
            'woo_coupon_window'             => 180,
            'woo_coupon_ban_time'           => 900,
        );
        $return = array_merge( $defaults, $options );
        // Backwards compatibility: normalize all boolean values to integers (0 or 1)
        $boolean_keys = array(
            'active',
            'globalbannetwork',
            'global',
            'filterqueries',
            'trackvisits',
            'usecloud',
            'protect_login_form',
            'hide_login_errors',
            'failed_login_email_warning',
            'countryblock_loginonly',
            'whitelist_managewp',
            'whitelist_wprocket',
            'whitelist_uptimia',
            'whitelist_uptimerobot',
            '2fa_enabled',
            '2fa_backup_codes_enabled',
            '404guard_enabled',
            'woo_rate_limiting_enabled',
            'woo_coupon_protection_enabled',
            'change_login_url',
            'blockadminlogin'
        );
        foreach ( $boolean_keys as $key ) {
            if ( isset( $return[$key] ) ) {
                $return[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $return[$key] );
            }
        }
        return $return;
    }

    /**
     * Enables the firewall - via AJAX
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Monday, February 6th, 2023.
     * @access	public static
     * @return	void
     */
    public static function ajax_enable_firewall() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        self::$options['active'] = 1;
        update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
        if ( class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
            \WPSecurityNinja\Plugin\SN_Geolocation::update_database();
            // updates the geoip when turning on firewall + via cron afterwards.
        }
        // Add notice about whitelist management
        add_settings_error(
            'wf_sn_cf',
            'firewall_activated',
            __( 'Firewall activated. For security best practices, remember to manually review and manage your IP whitelist.', 'security-ninja' ),
            'info'
        );
        wp_send_json_success( array(
            'message' => __( 'Firewall activated successfully.', 'security-ninja' ),
            'notices' => get_settings_errors( 'wf_sn_cf' ),
        ) );
    }

    /**
     * Tests if an IP is banned, via AJAX
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  string
     */
    public static function ajax_test_ip() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['ip'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing IP.', 'security-ninja' ),
            ) );
        }
        $ip = sanitize_text_field( $_POST['ip'] );
        if ( !filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_success( __( 'Please enter a valid IP address to test.', 'security-ninja' ) );
        }
        if ( $reason = self::is_banned_ip( $ip ) ) {
            wp_send_json_success( sprintf( 
                /* translators: 1: IP - 2: The reason, leave as is. */
                __( '%1$s is banned. %2$s', 'security-ninja' ),
                $ip,
                $reason
             ) );
        } else {
            wp_send_json_success( sprintf( 
                /* translators: 1: IP */
                __( '%1$s is NOT banned.', 'security-ninja' ),
                $ip
             ) );
        }
    }

    /**
     * Return domain from full parsed URL
     *
     * https://stackoverflow.com/a/18560043/452515
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $url
     * @return  mixed
     */
    public static function url_to_domain( $url ) {
        return implode( array_slice( explode( '/', preg_replace( '/https?:\\/\\/(www\\.)?/', '', $url ) ), 0, 1 ) );
    }

    /**
     * Clear the blacklist - via AJAX
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function ajax_clear_blacklist() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        self::update_banned_ips( array() );
        // storing an empty array overwrites
        wp_send_json_success();
    }

    /**
     * get_banned_ips.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Wednesday, June 5th, 2024.
     * @access	public static
     * @return	mixed
     */
    public static function get_banned_ips() {
        if ( !is_null( self::$banned_ips ) ) {
            return self::$banned_ips;
        }
        // get the option wf_sn_banned_ips
        $wf_sn_banned_ips = get_option( 'wf_sn_banned_ips' );
        if ( is_array( $wf_sn_banned_ips ) ) {
            return $wf_sn_banned_ips;
        } else {
            return array();
        }
    }

    /**
     * Function to send email with unblock link via AJAX
     * 
     * Moved email sending to seperate function March 2022 - send_secret_access_unblock_url()
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Wednesday, March 16th, 2022.
     * @access	public static
     * @return	void
     */
    public static function ajax_send_unblock_email() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_GET['email'] ) ) {
            $error = new \WP_Error('001', 'No email?');
            wp_send_json_error( $error );
        }
        $sanitized_email = sanitize_email( $_GET['email'] );
        if ( false === is_email( $sanitized_email ) ) {
            $error = new \WP_Error('002', 'Not a valid email!');
            wp_send_json_error( $error );
        }
        if ( !array_key_exists( 'unblock_url', self::$options ) ) {
            self::$options['unblock_url'] = md5( time() );
            update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
        }
        $sendresult = self::send_secret_access_unblock_url( $sanitized_email );
        if ( $sendresult ) {
            wp_send_json_success( array(
                'message' => __( 'Email sent.', 'security-ninja' ),
            ) );
        } else {
            wp_send_json_error( array(
                'message' => __( 'Email could not be sent.', 'security-ninja' ),
            ) );
        }
        die;
    }

    /**
     * send_secret_access_unblock_url.
     *
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Wednesday, March 16th, 2022.
     * @access	public static
     * @param	mixed	$email	
     * @return	boolean
     */
    public static function send_secret_access_unblock_url( $email ) {
        if ( !$email ) {
            return false;
        }
        $sanitized_email = sanitize_email( $email );
        if ( false === is_email( $sanitized_email ) ) {
            $error = new \WP_Error('002', 'Not a valid email!');
            wp_send_json_error( $error );
        }
        $subject = __( 'Security Ninja Firewall secret access link', 'security-ninja' );
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Wl' ) ) {
            if ( \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $pluginname = \WPSecurityNinja\Plugin\Wf_Sn_Wl::get_new_name();
                $subject = $pluginname . ' ' . __( 'Secret access link', 'security-ninja' );
            }
        }
        $body = '<p>Thank you for installing.</p>';
        $body .= '<p>Please keep this email for your records.</p>';
        $body .= '<p>In the unlikely situation that your IP gets banned, you will need the secret access link.</p>';
        $body .= '<p><strong>Your secret access link is ' . self::get_unblock_url() . '</strong></p>';
        $body .= '<p>Copy-paste this URL to your browser to whitelist your IP, allowing you to log back in.</p>';
        $body .= '<p>Please keep it safe and do not share it with others. Use it only if you get blocked by the firewall.</p>';
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Wl' ) ) {
            if ( !\WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $sal_email_link = Utils::generate_sn_web_link( 'secret_access_link', '/docs/firewall-protection/secret-access-link/', array(
                    'utm_medium' => 'email',
                ) );
                $body .= '<p><a href="' . $sal_email_link . '" target="_blank" rel="noopener">Documentation for Secret Access Link</a></p>';
            }
        }
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $emailintrotext = 'Save your secret access link for ' . self::url_to_domain( site_url() );
        $dashboardlink = admin_url( '?page=wf-sn' );
        $dashboardlinkanchor = 'Settings';
        $body .= '<p><a href="' . $dashboardlink . '" target="_blank" rel="noopener">' . $dashboardlinkanchor . '</a></p>';
        $my_replacements = array(
            '%%emailintrotext%%'      => $emailintrotext,
            '%%websitedomain%%'       => site_url(),
            '%%dashboardlink%%'       => $dashboardlink,
            '%%dashboardlinkanchor%%' => $dashboardlinkanchor,
            '%%secninlogourl%%'       => WF_SN_PLUGIN_URL . 'images/security-ninja-logo.png',
            '%%emailtitle%%'          => $subject,
            '%%sentfromtext%%'        => 'This email was sent from ' . self::url_to_domain( site_url() ),
            '%%emailcontent%%'        => nl2br( $body ),
        );
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Wl' ) ) {
            if ( \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $pluginname = \WPSecurityNinja\Plugin\Wf_Sn_Wl::get_new_name();
                $my_replacements['%%sentfromtext%%'] = 'This email was sent by ' . esc_attr( $pluginname ) . ' from ' . esc_url( self::url_to_domain( site_url() ) );
            }
        }
        $template_path = WF_SN_PLUGIN_DIR . 'modules/scheduled-scanner/inc/email-default.php';
        // Use secure file reading with validation
        $html = Wf_Sn_Security_Utils::secure_file_get_contents( $template_path, array(
            'check_readable'     => true,
            'check_size'         => true,
            'max_size'           => 1024 * 1024,
            'check_type'         => true,
            'allowed_extensions' => array('php'),
            'check_mime'         => false,
            'check_path'         => true,
            'allowed_dirs'       => array(WF_SN_PLUGIN_DIR),
        ) );
        if ( $html === false ) {
            // Handle error - template not found
            $html = '<p>Email template not found.</p>';
        }
        foreach ( $my_replacements as $needle => $replacement ) {
            $html = str_replace( $needle, $replacement, $html );
        }
        $sendresult = wp_mail(
            $sanitized_email,
            $subject,
            $html,
            $headers
        );
        wf_sn_el_modules::log_event( 'security_ninja', 'install_wizard', 'Sent unblock URL to email ' . $sanitized_email );
        return $sendresult;
    }

    /**
     * Send failed login warning email to administrator
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 14th, 2025.
     * @access  public static
     * @param   string $username   Username that was attempted
     * @param   string $ip         IP address of the attempt
     * @param   string $user_agent User agent string
     * @return  bool True on success, false on failure
     */
    public static function send_failed_login_warning_email( $username, $ip, $user_agent ) {
        // Check if setting is enabled
        if ( empty( self::$options['failed_login_email_warning'] ) ) {
            return false;
        }
        // Validate username
        if ( empty( $username ) ) {
            return false;
        }
        // Check rate limiting - prevent multiple emails for same username within 15 minutes
        $rate_limit_key = 'wf_sn_failed_login_email_' . md5( $username );
        $last_email_time = get_transient( $rate_limit_key );
        if ( $last_email_time && time() - $last_email_time < 900 ) {
            // Email was sent recently, skip
            return false;
        }
        // Get user by username
        $user = get_user_by( 'login', $username );
        // Check if user exists and is administrator
        if ( !$user || !in_array( 'administrator', (array) $user->roles, true ) ) {
            return false;
        }
        // Get user email
        $user_email = $user->user_email;
        if ( !is_email( $user_email ) ) {
            return false;
        }
        // Build email subject
        $subject = __( 'Was that you trying to log in?', 'security-ninja' );
        // Handle whitelabel plugin name
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Wl' ) ) {
            if ( \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $pluginname = \WPSecurityNinja\Plugin\Wf_Sn_Wl::get_new_name();
                $subject = $pluginname . ' - ' . __( 'Was that you trying to log in?', 'security-ninja' );
            }
        }
        // Build email body
        $body = '<p>' . sprintf( 
            /* translators: 1: Username */
            __( 'Someone just tried to log in to your account with username: %s', 'security-ninja' ),
            esc_html( $username )
         ) . '</p>';
        $body .= '<p><strong>' . __( 'Details:', 'security-ninja' ) . '</strong></p>';
        $body .= '<ul>';
        $body .= '<li>' . sprintf( 
            /* translators: 1: IP address */
            __( 'IP Address: %s', 'security-ninja' ),
            esc_html( $ip )
         ) . '</li>';
        if ( !empty( $user_agent ) ) {
            $body .= '<li>' . sprintf( 
                /* translators: 1: User agent */
                __( 'User Agent: %s', 'security-ninja' ),
                esc_html( $user_agent )
             ) . '</li>';
        }
        $body .= '<li>' . sprintf( 
            /* translators: 1: Timestamp */
            __( 'Time: %s', 'security-ninja' ),
            date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) )
         ) . '</li>';
        $body .= '</ul>';
        $body .= '<p>' . __( 'If this was you, you can ignore this email. If this was not you, we recommend:', 'security-ninja' ) . '</p>';
        $body .= '<ul>';
        $body .= '<li>' . __( 'Change your password immediately', 'security-ninja' ) . '</li>';
        $body .= '<li>' . __( 'Review your account security settings', 'security-ninja' ) . '</li>';
        $body .= '<li>' . __( 'Enable two-factor authentication if available', 'security-ninja' ) . '</li>';
        $body .= '</ul>';
        $dashboardlink = admin_url( '?page=wf-sn' );
        $dashboardlinkanchor = __( 'Security Settings', 'security-ninja' );
        $body .= '<p><a href="' . esc_url( $dashboardlink ) . '" target="_blank" rel="noopener">' . esc_html( $dashboardlinkanchor ) . '</a></p>';
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $emailintrotext = sprintf( 
            /* translators: 1: Site domain */
            __( 'Failed login attempt for %s', 'security-ninja' ),
            self::url_to_domain( site_url() )
         );
        $my_replacements = array(
            '%%emailintrotext%%'      => $emailintrotext,
            '%%websitedomain%%'       => site_url(),
            '%%dashboardlink%%'       => $dashboardlink,
            '%%dashboardlinkanchor%%' => $dashboardlinkanchor,
            '%%secninlogourl%%'       => WF_SN_PLUGIN_URL . 'images/security-ninja-logo.png',
            '%%emailtitle%%'          => $subject,
            '%%sentfromtext%%'        => 'This email was sent from ' . self::url_to_domain( site_url() ),
            '%%emailcontent%%'        => nl2br( $body ),
        );
        // Handle whitelabel plugin name
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Wl' ) ) {
            if ( \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $pluginname = \WPSecurityNinja\Plugin\Wf_Sn_Wl::get_new_name();
                $my_replacements['%%sentfromtext%%'] = 'This email was sent by ' . esc_attr( $pluginname ) . ' from ' . esc_url( self::url_to_domain( site_url() ) );
            }
        }
        $template_path = WF_SN_PLUGIN_DIR . 'modules/scheduled-scanner/inc/email-default.php';
        // Use secure file reading with validation
        $html = Wf_Sn_Security_Utils::secure_file_get_contents( $template_path, array(
            'check_readable'     => true,
            'check_size'         => true,
            'max_size'           => 1024 * 1024,
            'check_type'         => true,
            'allowed_extensions' => array('php'),
            'check_mime'         => false,
            'check_path'         => true,
            'allowed_dirs'       => array(WF_SN_PLUGIN_DIR),
        ) );
        if ( $html === false ) {
            // Handle error - template not found
            $html = '<p>Email template not found.</p>';
        }
        foreach ( $my_replacements as $needle => $replacement ) {
            $html = str_replace( $needle, $replacement, $html );
        }
        $sendresult = wp_mail(
            $user_email,
            $subject,
            $html,
            $headers
        );
        // Log the email sending event
        if ( $sendresult ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'failed_login_email_sent',
                sprintf( 
                    /* translators: 1: Username, 2: Email address */
                    __( 'Failed login warning email sent to %1$s (%2$s)', 'security-ninja' ),
                    esc_html( $username ),
                    esc_html( $user_email )
                 ),
                array(
                    'username'   => $username,
                    'email'      => $user_email,
                    'ip'         => $ip,
                    'user_agent' => $user_agent,
                )
            );
            // Set rate limiting transient
            set_transient( $rate_limit_key, time(), 900 );
        } else {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'failed_login_email_failed',
                sprintf( 
                    /* translators: 1: Username, 2: Email address */
                    __( 'Failed to send failed login warning email to %1$s (%2$s)', 'security-ninja' ),
                    esc_html( $username ),
                    esc_html( $user_email )
                 ),
                array(
                    'username' => $username,
                    'email'    => $user_email,
                    'ip'       => $ip,
                )
            );
        }
        return $sendresult;
    }

    /**
     * Checking if visitor is even allowed to see the login form.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function form_init_check() {
        self::check_visitor();
        $current_user_ip = self::get_user_ip();
        // Check if country blocking is enabled and restricted to login only
        if ( isset( self::$options['countryblock_loginonly'] ) && self::$options['countryblock_loginonly'] ) {
            if ( !empty( $current_user_ip ) && class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
                $geolocate_ip = \WPSecurityNinja\Plugin\SN_Geolocation::geolocate_ip( $current_user_ip, true );
                if ( $geolocate_ip ) {
                    $current_user_country = $geolocate_ip['country'];
                }
            }
            $banned_countries = self::$options['blocked_countries'] ?? array();
            if ( '' !== $current_user_country && !empty( $banned_countries ) && in_array( $current_user_country, $banned_countries, true ) ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'blocked_ip_country_ban_login',
                    $current_user_country . ' is blocked from login.',
                    ''
                );
                self::update_blocked_count( $current_user_ip );
                self::kill_request(
                    $current_user_ip,
                    'blocked_ip_country_ban_login',
                    1 * HOUR_IN_SECONDS,
                    false
                );
            }
        }
        if ( $reason = self::is_banned_ip( $current_user_ip ) ) {
            self::update_blocked_count( $current_user_ip );
            wf_sn_el_modules::log_event( 'security_ninja', 'login_form_blocked_ip', esc_attr( $current_user_ip ) . ' blocked from accessing the login page. ' . esc_attr( $reason ) );
            wp_clear_auth_cookie();
            self::kill_request(
                $current_user_ip,
                'login_form_blocked_ip',
                1 * HOUR_IN_SECONDS,
                false
            );
            return false;
        }
    }

    /**
     * login_filter.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $user
     * @param   mixed   $username
     * @param   mixed   $password
     * @return  mixed
     */
    public static function login_filter( $user, $username, $password ) {
        $protect_login_form = self::$options['protect_login_form'];
        if ( !$protect_login_form ) {
            return $user;
        }
        $blockadminlogin = self::$options['blockadminlogin'];
        $current_user_ip = self::get_user_ip();
        if ( $blockadminlogin && 'admin' === strtolower( $username ) ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'blockadminlogin',
                $current_user_ip . ' Attempt to log in as "admin" blocked.',
                ''
            );
            self::update_blocked_count( $current_user_ip );
            self::kill_request(
                $current_user_ip,
                'attempted_admin_login',
                1 * HOUR_IN_SECONDS,
                true
            );
        }
        if ( $reason = self::is_banned_ip( $current_user_ip ) ) {
            // Gets IP and country array with 'ip' and 'country'
            self::update_blocked_count( $current_user_ip );
            wf_sn_el_modules::log_event( 'security_ninja', 'login_form_blocked_ip', $current_user_ip . ' blocked from logging in. ' . $reason );
            // Kills the request or redirects based on settings
            wp_clear_auth_cookie();
            self::kill_request();
        }
        return $user;
    }

    public static function update_banned_ips( $new_list ) {
        // Check if $new_list is an array
        if ( !is_array( $new_list ) ) {
            return false;
        }
        update_option( 'wf_sn_banned_ips', $new_list, false );
        self::$banned_ips = $new_list;
    }

    /**
     * Prune banned ips
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function prune_banned() {
        $update = false;
        $banned_ips = self::get_banned_ips();
        if ( $banned_ips ) {
            foreach ( $banned_ips as $ip => $time ) {
                if ( $time < current_time( 'timestamp' ) ) {
                    unset($banned_ips[$ip]);
                    $update = true;
                }
            }
        }
        if ( $update ) {
            self::update_banned_ips( $banned_ips );
            if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_banned_ips',
                    'Pruned Firewall local banned IPs.',
                    ''
                );
            }
        } else {
            if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_banned_ips',
                    'No update.',
                    ''
                );
            }
        }
    }

    /**
     * Handle failed login - basic logging for free, advanced protection for premium
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Tuesday, January 14th, 2025 - Consolidated free and premium logic
     * @access  public static
     * @param   mixed   $username
     * @return  void
     */
    public static function failed_login( $username ) {
        if ( !is_string( $username ) ) {
            $username = '';
        }
        $current_user_ip = self::get_user_ip();
        $ua_string = '';
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
        }
        // Basic logging for all versions (free and premium)
        $description = sprintf( 
            /* translators: 1: IP address, 2: Username */
            __( '%1$s failed login attempt. Username: %2$s.', 'security-ninja' ),
            esc_html( $current_user_ip ),
            esc_html( $username )
         );
        $event_data = array(
            'ip'         => $current_user_ip,
            'username'   => sanitize_key( $username ),
            'user_agent' => $ua_string,
        );
        wf_sn_el_modules::log_event(
            'security_ninja',
            'wp_login_failed',
            $description,
            $event_data
        );
    }

    /**
     * Check lost password attempt and log it
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.1.0  Tuesday, January 7th, 2025.
     * @access  public static
     * @param   \WP_Error $errors
     * @return  void
     */
    public static function check_lost_password_attempt( $errors ) {
        // Get the user login from the form
        $user_login = ( isset( $_POST['user_login'] ) ? sanitize_text_field( $_POST['user_login'] ) : '' );
        if ( empty( $user_login ) ) {
            return;
        }
        // Check if user exists
        $user_data = get_user_by( 'login', $user_login );
        if ( !$user_data ) {
            $user_data = get_user_by( 'email', $user_login );
        }
        // If user doesn't exist, log it as a failed attempt
        if ( !$user_data ) {
            // Get the current count before logging this attempt
            $current_user_ip = self::get_user_ip();
            global $wpdb;
            $date = date( 'Y-m-d H:i:m', current_time( 'timestamp' ) );
            $query = $wpdb->prepare(
                'SELECT COUNT(id) FROM ' . $wpdb->prefix . 'wf_sn_el WHERE ip = %s AND action = %s AND timestamp >= DATE_SUB(%s, INTERVAL %s MINUTE)',
                $current_user_ip,
                'wp_lost_password_failed',
                $date,
                self::$options['max_login_attempts_time']
            );
            $previous_attempts = intval( $wpdb->get_var( $query ) );
            // Log the failed attempt (this will increment the count)
            self::failed_lost_password( $user_login );
            // Create structured data for the event with the correct count
            $event_data = array(
                'ip'                  => $current_user_ip,
                'username_email'      => $user_login,
                'previous_attempts'   => $previous_attempts + 1,
                'time_window_minutes' => intval( self::$options['max_login_attempts_time'] ),
                'max_attempts'        => intval( self::$options['max_login_attempts'] ),
                'user_agent'          => ( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '' ),
            );
            // Simple description for the event log
            $description = sprintf( 
                /* translators: 1: IP address, 2: Attempted username/email */
                __( '%1$s lost password error. Username/email: %2$s.', 'security-ninja' ),
                esc_html( $current_user_ip ),
                esc_html( $user_login )
             );
            wf_sn_el_modules::log_event(
                'security_ninja',
                'lost_password_error',
                $description,
                $event_data
            );
        }
    }

    /**
     * log failed lost password attempt - uses same settings as login protection
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 7th, 2025.
     * @access  public static
     * @param   mixed   $user_login
     * @return  void
     */
    public static function failed_lost_password( $user_login ) {
        global $wpdb;
        // To prevent double logging
        $logged = false;
        $my_banned_ips = self::get_banned_ips();
        $current_user_ip = self::get_user_ip();
        $ua_string = '';
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
        }
        // Count lost password attempts for this IP in the specified time window
        // Uses the same settings as login protection
        $date = date( 'Y-m-d H:i:m', current_time( 'timestamp' ) );
        $query = $wpdb->prepare(
            'SELECT COUNT(id) FROM ' . $wpdb->prefix . 'wf_sn_el WHERE ip = %s AND action = %s AND timestamp >= DATE_SUB(%s, INTERVAL %s MINUTE)',
            $current_user_ip,
            'wp_lost_password_failed',
            $date,
            self::$options['max_login_attempts_time']
        );
        $lost_password_attempts = intval( $wpdb->get_var( $query ) );
        if ( $lost_password_attempts >= intval( self::$options['max_login_attempts'] ) && !isset( $my_banned_ips[$current_user_ip] ) ) {
            $my_banned_ips[$current_user_ip] = current_time( 'timestamp' ) + self::$options['bruteforce_ban_time'] * 60;
            self::update_banned_ips( $my_banned_ips );
            // Translators: 1: User IP address, 2: Number of lost password attempts, 3: Time in minutes
            $block_details = sprintf(
                __( '%s blocked due to multiple lost password attempts. %d in %d min.', 'security-ninja' ),
                esc_html( $current_user_ip ),
                intval( $lost_password_attempts ),
                intval( self::$options['max_login_attempts_time'] )
            );
            // Logging to event module (if enabled)
            wf_sn_el_modules::log_event(
                'security_ninja',
                'firewall_ip_banned_lost_password',
                $current_user_ip . ' blocked due to multiple lost password attempts. ' . $lost_password_attempts,
                ''
            );
            wp_clear_auth_cookie();
            update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
            $logged = true;
            self::kill_request( $current_user_ip );
        } else {
            // Increase count of failed lost password attempts for IP
            $lost_password_attempts++;
        }
        update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
        $ban_reason = self::is_banned_ip();
        if ( $ban_reason && !$logged ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'lost_password_denied_banned_IP',
                $current_user_ip . ' blocked from lost password form.',
                ''
            );
            $logged = true;
            // We have logged this event
            wp_clear_auth_cookie();
            self::kill_request();
        }
        if ( !$logged ) {
            // Also log to event module with structured data
            $event_data = array(
                'ip'                  => $current_user_ip,
                'username_email'      => sanitize_key( $user_login ),
                'previous_attempts'   => $lost_password_attempts,
                'time_window_minutes' => intval( self::$options['max_login_attempts_time'] ),
                'max_attempts'        => intval( self::$options['max_login_attempts'] ),
                'user_agent'          => $ua_string,
            );
            $description = sprintf( 
                /* translators: 1: IP address, 2: Username/email */
                __( '%1$s failed lost password attempt. Username/email: %2$s.', 'security-ninja' ),
                esc_html( $current_user_ip ),
                esc_html( $user_login )
             );
            wf_sn_el_modules::log_event(
                'security_ninja',
                'wp_lost_password_failed',
                $description,
                $event_data
            );
        }
    }

    /**
     * ipCIDRMatch.
     *
     * @author  Unknown
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0   Saturday, August 20th, 2022.    
     * @version v1.0.1   Tuesday, August 27th, 2024.
     * @access  public static
     * @param   string $ip   The IP address to check.
     * @param   string $cidr The CIDR range to check against.
     * @return  bool         True if the IP matches the CIDR range, false otherwise.
     */
    public static function ipCIDRMatch( $ip, $cidr ) {
        $c = explode( '/', $cidr );
        $subnet = ( isset( $c[0] ) ? $c[0] : NULL );
        $mask = ( isset( $c[1] ) ? (int) $c[1] : NULL );
        if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $ipVersion = 'v4';
        } elseif ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $ipVersion = 'v6';
        } else {
            return false;
        }
        switch ( $ipVersion ) {
            case 'v4':
                if ( $mask === NULL || $mask < 0 || $mask > 32 ) {
                    return false;
                }
                return self::IPv4Match( $ip, $subnet, $mask );
            case 'v6':
                if ( $mask === NULL || $mask < 0 || $mask > 128 ) {
                    return false;
                }
                return self::IPv6Match( $ip, $subnet, $mask );
            default:
                return false;
        }
    }

    /**
     * inspired by: http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
     *
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, May 14th, 2024.
     * @access	private static
     * @param	mixed	$subnetMask	
     * @return	mixed
     */
    private static function IPv6MaskToByteArray( $subnetMask ) {
        $addr = str_repeat( "f", $subnetMask / 4 );
        switch ( $subnetMask % 4 ) {
            case 0:
                break;
            case 1:
                $addr .= "8";
                break;
            case 2:
                $addr .= "c";
                break;
            case 3:
                $addr .= "e";
                break;
        }
        $addr = str_pad( $addr, 32, '0' );
        $addr = pack( "H*", $addr );
        return $addr;
    }

    /**
     * inspired by: http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
     *
     * @author	Unknown
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, May 14th, 2024.	
     * @version	v1.0.1	Tuesday, August 27th, 2024.
     * @access	private static
     * @param	mixed	$address      	
     * @param	mixed	$subnetAddress	
     * @param	mixed	$subnetMask   	
     * @return	mixed
     */
    private static function IPv6Match( $address, $subnetAddress, $subnetMask ) {
        // Validate the subnet address
        if ( !filter_var( $subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) || $subnetMask === NULL || $subnetMask === "" || $subnetMask < 0 || $subnetMask > 128 ) {
            return false;
        }
        // Convert addresses to binary form
        $subnet = inet_pton( $subnetAddress );
        $addr = inet_pton( $address );
        // Ensure that both addresses were converted correctly
        if ( $subnet === false || $addr === false ) {
            return false;
        }
        // Convert the subnet mask to a binary string
        $binMask = self::IPv6MaskToByteArray( $subnetMask );
        // Perform the bitwise AND operation and compare
        return ($addr & $binMask) === $subnet;
    }

    /**
     * inspired by: http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
     *
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, May 14th, 2024.
     * @access	private static
     * @param	mixed	$address      	
     * @param	mixed	$subnetAddress	
     * @param	mixed	$subnetMask   	
     * @return	mixed
     */
    private static function IPv4Match( $address, $subnetAddress, $subnetMask ) {
        if ( !filter_var( $subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || $subnetMask === NULL || $subnetMask === "" || $subnetMask < 0 || $subnetMask > 32 ) {
            return false;
        }
        $address = ip2long( $address );
        $subnetAddress = ip2long( $subnetAddress );
        $mask = -1 << 32 - $subnetMask;
        $subnetAddress &= $mask;
        # nb: in case the supplied subnet wasn't correctly aligned
        return ($address & $mask) == $subnetAddress;
    }

    /**
     * Checks if an IP is in array
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $needle
     * @param   mixed   $haystack
     * @return  void
     */
    public static function IP_in_array( $needle, $haystack ) {
        // Check if haystack is array and makes sure it is trimmed from apostrophes
        if ( is_array( $haystack ) ) {
            $ip_arr = array();
            foreach ( $haystack as $key => $item ) {
                $ip_arr[] = trim( $item, "'" );
            }
        }
        if ( in_array( $needle, $ip_arr ) ) {
            return true;
        }
        foreach ( $haystack as $key => $item ) {
            if ( $item === $needle ) {
                return true;
            }
        }
    }

    /**
     * Checks a specific IP is banned or not
     *
     * @author	Lars Koudal
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Wednesday, June 9th, 2021.	
     * @version	v1.0.2	Sunday, June 13th, 2021.	
     * @version	v1.0.3	Monday, November 8th, 2021.	
     * @version	v1.0.4	Wednesday, February 9th, 2022.
     * @access	public static
     * @param	boolean	$ip	(defaults to false)
     * @return	boolean
     */
    public static function is_banned_ip( $ip = false ) {
        if ( !$ip ) {
            return false;
        }
        // Checks if IP is set or try to get it - always use $current_user_ip from here
        if ( $ip ) {
            $current_user_ip = $ip;
        } else {
            $current_user_ip = self::get_user_ip();
        }
        $server_host = gethostname();
        $server_ip = gethostbyname( $server_host );
        // If server IP same as referring IP, continue
        if ( $server_ip === $current_user_ip ) {
            return false;
        }
        // Checks if the IP is in local whitelist (supports both exact IPs and CIDR ranges)
        $local_whitelist = self::$options['whitelist'];
        // Ensure $local_whitelist is an array
        if ( !is_array( $local_whitelist ) ) {
            $local_whitelist = array();
        }
        // Use proper CIDR-aware whitelist checking
        if ( self::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
            return false;
        }
        // Check if IP is in blacklist. P.s. could use in_array() but had trouble with spaces ... perhaps trim first.. hmm...
        $blacklist = self::$options['blacklist'];
        if ( is_array( $blacklist ) ) {
            foreach ( $blacklist as $bl ) {
                if ( trim( $bl ) === $ip ) {
                    return 'IP is in local blacklist.';
                }
                if ( self::ipCIDRMatch( $ip, $bl ) ) {
                    return 'IP is in local blacklist mask - ' . $bl;
                }
            }
        }
        $my_banned_list = self::get_banned_ips();
        // IPs are currently stored in the options table
        $ips = get_option( 'wf_sn_cf_ips' );
        if ( !is_array( $ips ) ) {
            $ips = array(
                'ips'     => array(),
                'subnets' => array(),
            );
        }
        $banned_ips = self::get_banned_ips();
        if ( is_array( self::$options['whitelist'] ) && self::is_whitelisted( $current_user_ip, self::$options['whitelist'] ) ) {
            return false;
        } elseif ( array_key_exists( $current_user_ip, $banned_ips ) ) {
            $expiry = $banned_ips[$current_user_ip];
            if ( $expiry > current_time( 'timestamp' ) ) {
                return 'Local blacklist.';
            }
            // Expired: remove from list and treat as not banned.
            $updated = $banned_ips;
            unset($updated[$current_user_ip]);
            self::update_banned_ips( $updated );
            self::$banned_ips = $updated;
            return false;
        } elseif ( '1' === self::$options['usecloud'] && self::IP_in_array( $current_user_ip, $ips['ips'] ) ) {
            return 'IP in cloud blacklist.';
        } else {
            $nework_array = explode( '.', $current_user_ip, 2 );
            // is cloud firewall enabled?
            if ( '1' === self::$options['usecloud'] ) {
                if ( array_key_exists( $nework_array[0], $ips['subnets'] ) ) {
                    foreach ( $ips['subnets'][$nework_array[0]] as $subnet ) {
                        // trim apostrophes
                        $subnet = trim( $subnet, "'" );
                        if ( self::ipCIDRMatch( $current_user_ip, $subnet ) ) {
                            return 'IP in cloud blacklist range.';
                        }
                    }
                }
            }
        }
        // Checks if included in SecNin Global Block network
        global $wpdb;
        $table_name = $wpdb->prefix . 'wf_sn_cf_bl_ips';
        $answer = $wpdb->get_var( $wpdb->prepare( "SELECT tid FROM `{$table_name}` WHERE ip = %s", $ip ) );
        if ( $answer ) {
            return 'SecNin Global Block network.';
        }
        return false;
    }

    /**
     * Checks if an IP is whitelisted
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $ip
     * @param   mixed   $whitelist
     * @return  boolean
     */
    public static function is_whitelisted( $ip, $whitelist ) {
        foreach ( $whitelist as $key => $wip ) {
            if ( strpos( $wip, '/' ) !== false ) {
                if ( self::ipCIDRMatch( $ip, $wip ) ) {
                    return true;
                }
            } else {
                if ( $ip === $wip ) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Update cloud firewall blocked IPs and update server IP to whitelist
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function update_cloud_ips() {
    }

    /**
     * Register module settings.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function register_settings() {
        register_setting( WF_SN_CF_OPTIONS_KEY, 'wf_sn_cf', array(__NAMESPACE__ . '\\wf_sn_cf', 'sanitize_settings') );
    }

    /**
     * Centralized way to get users IP - @todo - replace med opdateret version
     *
     * @author	Lars Koudal
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Tuesday, May 14th, 2024.
     * @access	public static
     * @return	boolean
     * @todo	- replace med opdateret version
     */
    public static function get_user_ip() {
        // Check if we have already cached the IP
        if ( self::$cached_ip !== null ) {
            return self::$cached_ip;
        }
        $headers = array(
            'HTTP_CF_CONNECTING_IP',
            // CloudFlare
            'HTTP_X_FORWARDED_FOR',
            // May contain a comma+space separated list of IP addresses
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_X_COMING_FROM',
            'HTTP_PROXY_CONNECTION',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_COMING_FROM',
            'HTTP_VIA',
            'REMOTE_ADDR',
        );
        foreach ( $headers as $header ) {
            if ( !empty( $_SERVER[$header] ) ) {
                foreach ( explode( ',', $_SERVER[$header] ) as $ip ) {
                    $ip = trim( $ip );
                    // Check if IP is valid, including private/reserved ranges for local/dev environments
                    if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                        // Cache the result
                        self::$cached_ip = $ip;
                        return $ip;
                    }
                }
            }
        }
        // If no valid IP is found, cache and return false
        self::$cached_ip = false;
        return false;
    }

    /**
     * Function runs if WooCommerce installed and you add the account shortcode [woocommerce_my_account] somewhere on the website.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function process_woocommerce_login_form_start() {
        $protect_login_form = self::$options['protect_login_form'];
        if ( !$protect_login_form ) {
            return;
        }
        $show_message = apply_filters( 'secnin_show_woocommerce_login_message', true );
        if ( !$show_message ) {
            return;
        }
        $msg = '<p class="message">' . self::$options['login_msg'] . '</p>';
        echo $msg;
    }

    /**
     * Process login errors and optionally hide detailed error messages.
     *
     * @since   v0.0.1
     * @version v1.3.0
     *
     * @param string|\WP_Error $error The error message or WP_Error object.
     * @return string The processed error message.
     */
    public static function process_login_errors( $error ) : string {
        $current_user_ip = self::get_user_ip();
        $error_message = ( $error instanceof \WP_Error ? $error->get_error_message() : $error );
        // Get attempted username from POST data
        $attempted_username = ( isset( $_POST['log'] ) ? sanitize_text_field( $_POST['log'] ) : '' );
        // Create structured data for the event
        $event_data = array(
            'ip'            => $current_user_ip,
            'username'      => $attempted_username,
            'error_message' => wp_strip_all_tags( $error_message ),
            'user_agent'    => ( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '' ),
        );
        // Simple description for the event log
        $description = sprintf( 
            /* translators: 1: IP address, 2: Error message */
            __( '%1$s login error. Message: %2$s.', 'security-ninja' ),
            esc_html( $current_user_ip ),
            wp_strip_all_tags( $error_message )
         );
        wf_sn_el_modules::log_event(
            'security_ninja',
            'login_error',
            $description,
            $event_data
        );
        // If error hiding is enabled, return generic message
        if ( self::$options['hide_login_errors'] ) {
            $login_error_msg = ( self::$options['login_error_msg'] ?: __( 'Something went wrong', 'security-ninja' ) );
            return sprintf( '<strong>%s</strong>: %s', esc_html__( 'Error', 'security-ninja' ), wp_kses( $login_error_msg, [
                'p'  => [],
                'br' => [],
            ] ) );
        }
        return $error;
    }

    /**
     * Adds warning message above login form
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.1  Tuesday, March 5th, 2024.
     * @access  public static
     * @param   string $msg The existing message content.
     * @return  string Modified message content.
     */
    public static function login_message( $msg ) {
        if ( !self::is_active() || empty( self::$options['protect_login_form'] ) || empty( self::$options['login_msg'] ) ) {
            return $msg;
        }
        $action = ( isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '' );
        if ( !in_array( $action, array('register', 'lostpassword'), true ) ) {
            $custom_msg = '<p class="message">' . esc_html( self::$options['login_msg'] ) . '</p>';
            $msg = $custom_msg . $msg;
        }
        return $msg;
    }

    /**
     * isValidCIDR.
     *
     * @author	Lars Koudal
     * @since	v0.0.1
     * @version	v1.0.0	Tuesday, August 27th, 2024.
     * @access	private static
     * @param	mixed	$cidr	
     * @return	boolean
     */
    private static function isValidCIDR( $cidr ) {
        $parts = explode( '/', $cidr );
        if ( count( $parts ) !== 2 ) {
            return false;
        }
        $subnet = $parts[0];
        $mask = (int) $parts[1];
        if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return $mask >= 0 && $mask <= 32;
        } elseif ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            return $mask >= 0 && $mask <= 128;
        }
        return false;
    }

    /**
     * sanitize settings on save
     *
     * @author	Lars Koudal
     * @author	Unknown
     * @since	v0.0.1
     * @version	v1.0.0	Monday, December 21st, 2020.	
     * @version	v1.0.1	Friday, May 31st, 2024.
     * @access	public static
     * @param	mixed	$values	
     * @return	mixed
     */
    public static function sanitize_settings( $values ) {
        // Handle null or non-array values (WordPress may call this with null)
        if ( !is_array( $values ) ) {
            // Return existing options normalized
            $old_options = get_option( 'wf_sn_cf', array() );
            if ( !is_array( $old_options ) ) {
                $old_options = array();
            }
            // Normalize existing boolean values
            $boolean_keys = array(
                'active',
                'globalbannetwork',
                'global',
                'filterqueries',
                'trackvisits',
                'usecloud',
                'protect_login_form',
                'hide_login_errors',
                'failed_login_email_warning',
                'countryblock_loginonly',
                'whitelist_managewp',
                'whitelist_uptimerobot',
                'whitelist_wprocket',
                'whitelist_uptimia',
                '2fa_enabled',
                '2fa_backup_codes_enabled',
                '404guard_enabled',
                'woo_rate_limiting_enabled',
                'woo_coupon_protection_enabled',
                'change_login_url',
                'blockadminlogin'
            );
            foreach ( $boolean_keys as $key ) {
                if ( isset( $old_options[$key] ) ) {
                    $old_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] );
                }
            }
            return $old_options;
        }
        // Get existing options first (like Events Logger does)
        $old_options = get_option( 'wf_sn_cf', array() );
        if ( !is_array( $old_options ) ) {
            $old_options = array();
        }
        // Start with existing options, then merge with form values
        $new_options = $old_options;
        $defaults = array(
            'active'                        => 0,
            'globalbannetwork'              => 1,
            'global'                        => 1,
            'filterqueries'                 => 1,
            'trackvisits'                   => 1,
            'trackvisits_howlong'           => 7,
            'usecloud'                      => 1,
            'protect_login_form'            => 1,
            'hide_login_errors'             => 1,
            'failed_login_email_warning'    => 0,
            'blocked_countries'             => array(),
            'countryblock_loginonly'        => 0,
            'blacklist'                     => array(),
            'whitelist'                     => array(self::get_user_ip()),
            'whitelist_managewp'            => 1,
            'whitelist_wprocket'            => 0,
            'whitelist_uptimia'             => 0,
            'whitelist_uptimerobot'         => 0,
            'max_login_attempts'            => 5,
            'max_login_attempts_time'       => 5,
            'bruteforce_ban_time'           => 120,
            'login_msg'                     => __( 'Warning: Multiple failed login attempts will get you locked out temporarily.', 'security-ninja' ),
            'login_error_msg'               => __( 'Something went wrong', 'security-ninja' ),
            'message'                       => __( 'You are not allowed to visit this website.', 'security-ninja' ),
            'redirect_url'                  => '',
            'blockadminlogin'               => 0,
            'change_login_url'              => 0,
            'new_login_url'                 => 'my-login',
            'unblock_url'                   => '',
            '2fa_required_roles'            => array(),
            '2fa_methods'                   => array(),
            '2fa_enabled'                   => 0,
            '2fa_enabled_timestamp'         => '',
            '2fa_backup_codes_enabled'      => 0,
            '2fa_grace_period'              => 14,
            '2fa_intro'                     => '',
            '2fa_enter_code'                => '',
            '404guard_enabled'              => 1,
            '404guard_threshold'            => 10,
            '404guard_window'               => 300,
            '404guard_block_time'           => 600,
            'woo_rate_limiting_enabled'     => 0,
            'woo_checkout_rate_limit'       => 3,
            'woo_checkout_window'           => 300,
            'woo_add_to_cart_limit'         => 10,
            'woo_add_to_cart_window'        => 60,
            'woo_order_rate_limit'          => 2,
            'woo_order_window'              => 600,
            'woo_coupon_protection_enabled' => 0,
            'woo_coupon_failed_attempts'    => 5,
            'woo_coupon_window'             => 300,
            'woo_coupon_ban_time'           => 900,
        );
        $current_options = self::get_options();
        $old_2fa_status = $current_options['2fa_enabled'];
        // List of all boolean/flag settings that should be normalized to 0/1
        $boolean_keys = array(
            'active',
            'globalbannetwork',
            'global',
            'filterqueries',
            'trackvisits',
            'usecloud',
            'protect_login_form',
            'hide_login_errors',
            'failed_login_email_warning',
            'countryblock_loginonly',
            'whitelist_managewp',
            'whitelist_uptimerobot',
            'whitelist_wprocket',
            'whitelist_uptimia',
            'whitelist_uptimerobot',
            '2fa_enabled',
            '2fa_backup_codes_enabled',
            '404guard_enabled',
            'woo_rate_limiting_enabled',
            'woo_coupon_protection_enabled',
            'change_login_url',
            'blockadminlogin'
        );
        // Handle boolean keys
        // Fields that are always in the form (free features): filterqueries
        // If these are missing from form submission, they're unchecked = 0
        // Premium-only fields might not be in form for free users, so preserve existing
        $always_in_form_keys = array('filterqueries', 'failed_login_email_warning');
        // Free features / always-in-form toggles
        foreach ( $boolean_keys as $key ) {
            if ( isset( $values[$key] ) ) {
                // Value is in form submission - normalize it
                $new_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $values[$key] );
            } else {
                // Value not in form submission
                if ( $key === 'active' ) {
                    // 'active' is a hidden field - preserve existing value if not in form
                    $new_options[$key] = ( isset( $old_options[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] ) : (( isset( $defaults[$key] ) ? $defaults[$key] : 0 )) );
                } elseif ( in_array( $key, $always_in_form_keys, true ) ) {
                    // Field is always in form - missing = unchecked = 0
                    $new_options[$key] = 0;
                } else {
                    // Premium-only field or field that might not be in form - preserve existing
                    $new_options[$key] = ( isset( $old_options[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] ) : (( isset( $defaults[$key] ) ? $defaults[$key] : 0 )) );
                }
            }
        }
        // Process all other form values (non-boolean)
        foreach ( $values as $key => $value ) {
            // Skip boolean keys as they're already handled above
            if ( in_array( $key, $boolean_keys, true ) ) {
                continue;
            }
            if ( array_key_exists( $key, $defaults ) ) {
                switch ( $key ) {
                    case '2fa_required_roles':
                    case '2fa_methods':
                    case 'blocked_countries':
                        if ( is_array( $value ) ) {
                            $new_options[$key] = array_map( 'sanitize_text_field', $value );
                        } else {
                            $new_options[$key] = sanitize_text_field( $value );
                        }
                        break;
                    case 'blacklist':
                    case 'whitelist':
                        if ( !is_array( $value ) && is_string( $value ) ) {
                            // Split the string into an array by line breaks
                            $ips = explode( "\n", $value );
                            // Trim whitespace, sanitize each IP address or CIDR, and ensure uniqueness
                            $new_options[$key] = array_unique( array_filter( array_map( function ( $ip ) {
                                $sanitized_ip = sanitize_text_field( trim( $ip ) );
                                if ( filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                                    return $sanitized_ip;
                                }
                                if ( strpos( $sanitized_ip, '/' ) !== false && self::isValidCIDR( $sanitized_ip ) ) {
                                    return $sanitized_ip;
                                }
                                // Return null if invalid to filter it out
                                return null;
                            }, $ips ), function ( $ip ) {
                                return !is_null( $ip );
                            } ) );
                        } elseif ( is_array( $value ) ) {
                            // If it's already an array, sanitize and validate each entry
                            $new_options[$key] = array_unique( array_filter( array_map( function ( $ip ) {
                                $sanitized_ip = sanitize_text_field( trim( $ip ) );
                                // Validate IP or CIDR using your existing function
                                if ( filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) || strpos( $sanitized_ip, '/' ) !== false && self::isValidCIDR( $sanitized_ip ) ) {
                                    return $sanitized_ip;
                                }
                                return null;
                            }, $value ), function ( $ip ) {
                                return !is_null( $ip );
                            } ) );
                        } else {
                            // If the value is neither a string nor an array, set an empty array
                            $new_options[$key] = [];
                        }
                        break;
                    case '2fa_grace_period':
                    case 'max_login_attempts':
                    case 'max_login_attempts_time':
                    case 'bruteforce_ban_time':
                    case 'trackvisits_howlong':
                        // number of days to track visits
                        $new_options[$key] = intval( $value );
                        break;
                    case '404guard_threshold':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 5, maximum 50
                        if ( $new_options[$key] < 5 ) {
                            $new_options[$key] = 5;
                        } elseif ( $new_options[$key] > 50 ) {
                            $new_options[$key] = 50;
                        }
                        break;
                    case '404guard_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 60 seconds (1 minute), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 60 ) {
                            $new_options[$key] = 60;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    case '404guard_block_time':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 86400 seconds (24 hours)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 86400 ) {
                            $new_options[$key] = 86400;
                        }
                        break;
                    // WooCommerce protection options
                    case 'woo_rate_limiting_enabled':
                    case 'woo_coupon_protection_enabled':
                        // These are boolean keys, already handled above - skip
                        break;
                    case 'woo_checkout_rate_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 2, maximum 10
                        if ( $new_options[$key] < 2 ) {
                            $new_options[$key] = 2;
                        } elseif ( $new_options[$key] > 10 ) {
                            $new_options[$key] = 10;
                        }
                        break;
                    case 'woo_checkout_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 180 seconds (3 minutes), maximum 1800 seconds (30 minutes)
                        if ( $new_options[$key] < 180 ) {
                            $new_options[$key] = 180;
                        } elseif ( $new_options[$key] > 1800 ) {
                            $new_options[$key] = 1800;
                        }
                        break;
                    case 'woo_add_to_cart_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 5, maximum 20
                        if ( $new_options[$key] < 5 ) {
                            $new_options[$key] = 5;
                        } elseif ( $new_options[$key] > 20 ) {
                            $new_options[$key] = 20;
                        }
                        break;
                    case 'woo_add_to_cart_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 30 seconds, maximum 300 seconds (5 minutes)
                        if ( $new_options[$key] < 30 ) {
                            $new_options[$key] = 30;
                        } elseif ( $new_options[$key] > 300 ) {
                            $new_options[$key] = 300;
                        }
                        break;
                    case 'woo_order_rate_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 1, maximum 5
                        if ( $new_options[$key] < 1 ) {
                            $new_options[$key] = 1;
                        } elseif ( $new_options[$key] > 5 ) {
                            $new_options[$key] = 5;
                        }
                        break;
                    case 'woo_order_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    // Coupon protection options
                    case 'woo_coupon_failed_attempts':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 3, maximum 15
                        if ( $new_options[$key] < 3 ) {
                            $new_options[$key] = 3;
                        } elseif ( $new_options[$key] > 15 ) {
                            $new_options[$key] = 15;
                        }
                        break;
                    case 'woo_coupon_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 180 seconds (3 minutes), maximum 1800 seconds (30 minutes)
                        if ( $new_options[$key] < 180 ) {
                            $new_options[$key] = 180;
                        } elseif ( $new_options[$key] > 1800 ) {
                            $new_options[$key] = 1800;
                        }
                        break;
                    case 'woo_coupon_ban_time':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    case '2fa_intro':
                    case '2fa_enter_code':
                    case '2fa_enabled_timestamp':
                    case 'login_msg':
                    case 'login_error_msg':
                    case 'message':
                    case 'new_login_url':
                        $new_options[$key] = sanitize_text_field( $value );
                        break;
                    case 'redirect_url':
                        $new_options[$key] = esc_url_raw( $value );
                        break;
                    default:
                        $new_options[$key] = sanitize_text_field( $value );
                        break;
                }
            } else {
                // Key not in defaults - don't add it to new_options
            }
        }
        // // Check for user IP whitelisting if the firewall is active
        // $user_ip = self::get_user_ip();
        // if (isset($new_options['active']) && $new_options['active'] && !in_array($user_ip, $new_options['whitelist'], true)) {
        // 	$new_options['whitelist'][] = $user_ip;
        // }
        // Check if 'active' is set to 0 and deactivate 2FA if so
        if ( isset( $new_options['active'] ) && (int) $new_options['active'] === 0 && (int) $new_options['2fa_enabled'] === 1 ) {
            $new_options['2fa_enabled'] = 0;
            // Deactivate 2FA
            $new_options['2fa_enabled_timestamp'] = '';
            // Optionally reset the timestamp
        }
        // Handle 404 Guard status changes
        $old_404guard_status = (int) ($current_options['404guard_enabled'] ?? 0);
        $new_404guard_status = (int) ($new_options['404guard_enabled'] ?? 0);
        // If 404 Guard was just enabled, we need to load it dynamically
        if ( $new_404guard_status === 1 && $old_404guard_status === 0 ) {
            // Load and initialize 404 Guard immediately
            if ( !class_exists( __NAMESPACE__ . '\\SN_404_Guard' ) ) {
                require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-sn-404-guard.php';
            }
            SN_404_Guard::init();
        }
        $current_twofa_status = (int) ($current_options['2fa_enabled'] ?? 0);
        // If the 2fa_enabled is set to 1 and it used to be 0, set the timestamp '2fa_enabled_timestamp' to the current time
        $old_2fa_status = $current_twofa_status;
        // Check if 2FA was just enabled
        if ( isset( $new_options['2fa_enabled'] ) && (int) $new_options['2fa_enabled'] === 1 && $old_2fa_status === 0 ) {
            // Get all users
            $new_options['2fa_enabled_timestamp'] = current_time( 'timestamp' );
            $users = get_users();
            // Loop through all users
            foreach ( $users as $user ) {
                // Cleaning up 2FA metadata for all users
                delete_user_meta( $user->ID, 'secnin_2fa_secret' );
                delete_user_meta( $user->ID, 'secnin_2fa_setup_complete' );
                delete_user_meta( $user->ID, 'secnin_2fa_code_validated' );
            }
        }
        // Ensure a non-empty login URL if the change login URL feature is active
        if ( class_exists( __NAMESPACE__ . '\\SecNin_Rename_WP_Login' ) && isset( $new_options['change_login_url'] ) && $new_options['change_login_url'] && '' === ($new_options['new_login_url'] ?? '') ) {
            $new_options['new_login_url'] = \WPSecurityNinja\Plugin\SecNin_Rename_WP_Login::$default_login_url;
        }
        // Merge sanitized values with defaults to ensure all settings are complete and valid
        // Use $new_options which already has existing values preserved for missing keys
        $merged = array_merge( $defaults, $new_options );
        return $merged;
    }

    /**
     * add new tab
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $tabs
     * @return  mixed
     */
    public static function sn_tabs( $tabs ) {
        $core_tab = array(
            'id'       => 'sn_cf',
            'class'    => '',
            'label'    => 'Firewall',
            'callback' => array(__NAMESPACE__ . '\\wf_sn_cf', 'do_page'),
        );
        $done = 0;
        for ($i = 0; $i < sizeof( $tabs ); $i++) {
            if ( $tabs[$i]['id'] == 'sn_cf' ) {
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
     * add custom message to overlay
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function overlay_content() {
        echo '<div id="sn-cloud-firewall" style="display: none; text-align:center;">';
        echo '<h2 style="font-weight: bold;">' . __( 'Important! Please READ!', 'security-ninja' ) . '</h2>';
        echo '<p>' . __( 'In the unlikely situation that your IP gets banned, you will not be able to login or access the site. In that case you need the secret access link.', 'security-ninja' ) . '</p>';
        echo '<p>' . __( 'It whitelists your IP and enables access. Please store the link in a safe place or use the form below to get it sent to your email address.', 'security-ninja' ) . '</p>';
        echo '<p><code>' . self::get_unblock_url() . '</code></p>';
        echo '<div id="sn-firewall-status">' . __( 'Enabling firewall, please wait', 'security-ninja' ) . '</p><p class="spinner is-active"></div>';
        echo '<p>' . __( 'Enter your email below to receive the secret access link in case you get locked out', 'security-ninja' ) . '</p>';
        echo '<input style="width: 250px;" type="text" id="sn-ublock-email" name="sn-ublock-email" value="' . get_option( 'admin_email' ) . '" placeholder="john@example.com"><br />
																									<p id="sn-unblock-message"></p>';
        ?>
		<input type="button" value="<?php 
        esc_html_e( 'Send secret access link', 'security-ninja' );
        ?>" id="sn-send-unlock-code" class="input-button button button-secondary" />
	<?php 
        echo '<p><br><input type="button" value="Close (3)" id="sn-close-firewall" class="input-button button-primary" /></p>';
        echo '</div>';
    }

    // overlay_content
    /**
     * Checks if the firewall module is active
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function is_active() {
        return (int) self::$options['active'];
    }

    /**
     * Check if 404 Guard is available and enabled
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, January 1st, 2021.
     * @return  boolean
     */
    public static function is_404guard_available() {
        if ( !class_exists( __NAMESPACE__ . '\\SN_404_Guard' ) ) {
            return false;
        }
        return SN_404_Guard::is_loaded_and_enabled();
    }

    /**
     * Returns list of blocked country codes for use with GEOIP.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function get_blocked_countries() {
        $blocked_countries = self::$options['blocked_countries'];
        if ( !$blocked_countries ) {
            return array();
        }
        if ( is_array( $blocked_countries ) ) {
            $bclist = array();
            foreach ( $blocked_countries as $key => $ba ) {
                $bclist[] = $ba;
            }
            return $bclist;
        }
        return array();
    }

    /**
     * Adds an IP address to the whitelist if it's not already present
     *
     * @author  Lars Koudal
     * @since   v1.0.0
     * @version v1.0.0  Monday, January 13th, 2025
     * @access  public static
     * @param   string $ip The IP address to add
     * @return  boolean True if IP was added, false if already exists or invalid
     */
    public static function add_ip_to_whitelist( $ip ) {
        if ( !$ip || !filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return false;
        }
        // Load options if not already loaded
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        // Ensure whitelist is an array
        if ( !is_array( self::$options['whitelist'] ) ) {
            self::$options['whitelist'] = array();
        }
        // Check if IP is already in whitelist
        if ( in_array( $ip, self::$options['whitelist'], true ) ) {
            return false;
            // Already whitelisted
        }
        // Add IP to whitelist
        self::$options['whitelist'][] = $ip;
        update_option( WF_SN_CF_OPTIONS_KEY, self::$options, false );
        // Log the event
        if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'unblocked_ip',
                sprintf( __( 'IP %s automatically added to whitelist.', 'security-ninja' ), $ip ),
                ''
            );
        }
        return true;
    }

    /**
     * get_unblock_url.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function get_unblock_url() {
        $my_options = self::get_options();
        $unblock_url = '';
        if ( isset( $my_options['unblock_url'] ) && !empty( $my_options['unblock_url'] ) ) {
            $unblock_url = $my_options['unblock_url'];
        }
        // check if already set
        if ( !$unblock_url ) {
            $my_options['unblock_url'] = md5( time() );
            update_option( WF_SN_CF_OPTIONS_KEY, $my_options, false );
        }
        $outurl = add_query_arg( array(
            'snf' => $my_options['unblock_url'],
        ), get_site_url() );
        return $outurl;
    }

    /**
     * Return bad IPs from the central API
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Thursday, February 11th, 2021.
     * @access  private static
     * @return  boolean
     */
    private static function get_network_listips() {
        // Check if the feature is enabled
        if ( !self::$options['globalbannetwork'] ) {
            wf_sn_el_modules::log_event( 'security_ninja', 'get_network_listips', 'Global network feature is disabled' );
            return false;
        }
        $license_id = secnin_fs()->_get_license()->id;
        $install_id = secnin_fs()->get_site()->id;
        $site_private_key = secnin_fs()->get_site()->secret_key;
        $nonce = date( 'Y-m-d' );
        $pk_hash = hash( 'sha512', $site_private_key . '|' . $nonce );
        $authentication_string = base64_encode( $pk_hash . '|' . $nonce );
        $url = self::$central_api_url . 'listips/';
        $response = wp_remote_get( 
            // Cannot use wp_safe_remote_get because we need to set the header
            $url,
            array(
                'headers'   => array(
                    'Authorization' => $authentication_string,
                ),
                'body'      => array(
                    'install_id' => $install_id,
                    'license_id' => $license_id,
                ),
                'blocking'  => true,
                'timeout'   => 15,
                'sslverify' => false,
            )
         );
        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            wf_sn_el_modules::log_event( 'security_ninja', 'update_blocked_ips', 'Error getting IPs from network: "' . esc_html( $error_message ) . '"' );
            return false;
        } else {
            $body = wp_remote_retrieve_body( $response );
            $decoded = json_decode( $body );
            $newips = 0;
            if ( is_object( $decoded ) && isset( $decoded->ips ) ) {
                $newips = count( $decoded->ips );
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'update_blocked_ips',
                    sprintf( esc_html__( 'Added/updated %1$s IPs from the blocklist.', 'security-ninja' ), $newips ),
                    ''
                );
            }
            return $body;
        }
        return false;
    }

    /**
     * display results
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function do_page() {
        global $wpdb;
        $ips = get_option( 'wf_sn_cf_ips' );
        if ( $ips && !array_key_exists( 'total', $ips ) ) {
            $total_ips = 0;
            if ( isset( $ips['subnets'] ) ) {
                foreach ( $ips['subnets'] as $prefix => $subnet ) {
                    foreach ( $subnet as $sub ) {
                        $mask = explode( '/', str_replace( '\'', '', $sub ) );
                        $total_ips += pow( 2, 32 - $mask[1] ) - 2;
                    }
                }
            }
            $total_ips = ( isset( $total_ips ) ? intval( $total_ips ) : 0 );
            $banned_ips = self::get_banned_ips();
            $banned_ips_count = ( is_array( $banned_ips ) ? count( $banned_ips ) : 0 );
            $ips['total'] = $total_ips + count( $ips['ips'] ) + $banned_ips_count;
            // update_option('wf_sn_cf_ips', $ips, false);
        }
        ?>
		<div class="sncard settings-card">
			<h2><span class="dashicons dashicons-shield-alt"></span> <?php 
        esc_html_e( 'Firewall', 'security-ninja' );
        ?></h2>
			<p>Protect your website from malicious traffic and attacks</p>

			<div id="snfwtop">
				<div class="col left">
					<?php 
        $blocked_count = get_option( 'wf_sn_cf_blocked_count' );
        if ( $blocked_count ) {
            ?>
						<div class="snfw-blocked-count">Total Blocked Visits <div class="val"><?php 
            echo number_format_i18n( $blocked_count );
            ?></div>
						</div>
					<?php 
        }
        if ( 1 === self::is_active() ) {
            echo '<input type="button" value="' . __( 'Disable Firewall', 'security-ninja' ) . '" id="sn-disable-firewall" class="button snbutton" />';
        } else {
            echo '<input type="button" value="' . __( 'Enable Firewall', 'security-ninja' ) . '" id="sn-enable-firewall-overlay" class="button button-primary button-hero"/>';
        }
        ?>

				</div>
				<div class="col right"><?php 
        if ( (int) self::$options['active'] === 1 ) {
            echo '<h3>' . esc_html__( 'Secret Access URL', 'security-ninja' ) . '</h3>';
            ?>
						<input type="text" id="sn-unblock-url" value="<?php 
            echo esc_url( self::get_unblock_url() );
            ?>" disabled><?php 
            echo '<p class="description">' . esc_html__( 'Do not share this URL! Use it only to access your website if your IP gets banned.', 'security-ninja' ) . '</p>';
        } else {
            echo '<h3>' . esc_html__( 'Firewall is not active', 'security-ninja' ) . '</h3>';
            echo '<p>' . esc_html__( 'Activating the firewall enables protection against outside threats trying to access your website.', 'security-ninja' ) . '</p>';
        }
        ?>
				</div>
			</div>


			<?php 
        global $secnin_fs;
        if ( 1 !== self::is_active() ) {
            ?>
				<div class="sncard infobox">
					<div class="inner">
						<h3><?php 
            esc_html_e( 'Upgrade to Pro for Advanced Firewall Features', 'security-ninja' );
            ?></h3>
						<p><?php 
            esc_html_e( 'The free version provides basic firewall protection with 8G rules. Upgrade to Security Ninja Pro to unlock powerful advanced features:', 'security-ninja' );
            ?></p>
						<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
							<li><?php 
            esc_html_e( 'Control how banned IPs are handled - block completely or only from login', 'security-ninja' );
            ?></li>
							<li><?php 
            esc_html_e( 'Cloud Firewall with 600+ million known bad IPs, automatically updated', 'security-ninja' );
            ?></li>
							<li><?php 
            esc_html_e( 'Participate in global IP threat network and share threat intelligence', 'security-ninja' );
            ?></li>
							<li><?php 
            esc_html_e( 'Block entire countries from accessing your website', 'security-ninja' );
            ?></li>
							<li><?php 
            esc_html_e( 'Customize messages shown to blocked visitors', 'security-ninja' );
            ?></li>
							<li><?php 
            esc_html_e( 'Redirect blocked visitors to any URL using 301 redirects', 'security-ninja' );
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
		</div>
	<?php 
        }
        if ( (int) self::$options['active'] === 1 ) {
            echo '</div>';
            echo '<div class="sncard settings-card">';
            echo '<form action="options.php" id="sn-firewall-settings-form" method="post">';
            settings_fields( 'wf_sn_cf' );
            ?>
		<div class="wf-sn-tab-content">
			<div class="nav-tab-wrapper" id="wf-sn-cf-subtabs">
				<a href="#sn_cf_settings" class="nav-tab nav-tab-active">Settings</a>
				<?php 
            $can_use_premium = false;
            if ( secnin_fs()->can_use_premium_code() ) {
                $can_use_premium = true;
            }
            $pro_class = ( $can_use_premium ? '' : ' profeature' );
            ?>
				<a href="#sn_cf_visitors" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">Visitor Logging</a>
				<a href="#sn_cf_login" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">Login Protection</a>
				<a href="#sn_cf_ip" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">IP Management</a>
				<a href="#sn_cf_404guard" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">404 Guard</a>
				<a href="#sn_cf_woocommerce" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">WooCommerce</a>
			</div>

			<div id="sn_cf_settings" class="wf-sn-subtab">
				<?php 
            // Include settings content from separate file
            $settings_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/settings.php';
            if ( file_exists( $settings_file ) ) {
                require_once $settings_file;
                wf_sn_cf_render_settings_content( self::$options, $ips );
            }
            ?>
			</div>

			<div id="sn_cf_visitors" class="wf-sn-subtab">
				<?php 
            if ( secnin_fs()->can_use_premium_code() ) {
                ?>
					<?php 
                // Include visitor logging content from separate file
                $visitor_logging_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/visitor-logging.php';
                if ( file_exists( $visitor_logging_file ) ) {
                    require_once $visitor_logging_file;
                    wf_sn_cf_render_visitor_logging_content( self::$options, $ips );
                }
                ?>
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
                esc_html_e( 'Upgrade to Pro for Visitor Logging', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock visitor logging features:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Track all visitors and page requests', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Visitor logging with geolocation data', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Detailed visitor analytics and insights', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Customizable log retention periods', 'security-ninja' );
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

			<div id="sn_cf_login" class="wf-sn-subtab">
				<?php 
            if ( secnin_fs()->can_use_premium_code() ) {
                ?>
					<?php 
                // Include login protection content from separate file
                $login_protection_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/login-protection.php';
                if ( file_exists( $login_protection_file ) ) {
                    require_once $login_protection_file;
                    wf_sn_cf_render_login_protection_content( self::$options, $ips );
                }
                ?>
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
                esc_html_e( 'Upgrade to Pro for Advanced Login Protection', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'The free version provides basic login and failed login event logging. Upgrade to Security Ninja Pro to unlock powerful login protection features:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Advanced login form protection with brute force detection', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Auto-ban rules for failed login attempts', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Block "admin" username login attempts', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Hide login errors to prevent username enumeration', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Email warnings for failed login attempts', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Change login URL to hide wp-login.php', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Two-Factor Authentication (2FA) for enhanced security', 'security-ninja' );
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

			<div id="sn_cf_ip" class="wf-sn-subtab">
				<?php 
            if ( secnin_fs()->can_use_premium_code() ) {
                ?>
					<?php 
                $ip_management_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/ip-management.php';
                if ( file_exists( $ip_management_file ) ) {
                    require_once $ip_management_file;
                    wf_sn_cf_render_ip_management_content( self::$options, $ips );
                }
                ?>
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
                esc_html_e( 'Upgrade to Pro for IP Management', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock advanced IP management features:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Manual IP blacklist and whitelist management', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Automatic whitelisting for WP Rocket, Uptimia, UptimeRobot, and ManageWP', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'View and manage locally banned IPs', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Test IP addresses to check ban status', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Clear banned IP lists with one click', 'security-ninja' );
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

			<div id="sn_cf_404guard" class="wf-sn-subtab">
				<?php 
            if ( secnin_fs()->can_use_premium_code() ) {
                ?>
					<?php 
                $fofguard = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/404guard.php';
                if ( file_exists( $fofguard ) ) {
                    require_once $fofguard;
                    wf_sn_cf_render_404guard_content( self::$options, $ips );
                }
                ?>
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
                esc_html_e( 'Upgrade to Pro for 404 Guard', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock 404 Guard features:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Block IPs that generate excessive 404 errors', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Prevent bots from scanning your site for vulnerabilities', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Configurable threshold and time window settings', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Automatic whitelisting of search engines and crawlers', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Temporary blocks that automatically expire', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Comprehensive logging of all blocked IPs', 'security-ninja' );
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

			<div id="sn_cf_woocommerce" class="wf-sn-subtab">
				<?php 
            if ( secnin_fs()->can_use_premium_code() ) {
                ?>
					<?php 
                $woocommerce_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/woocommerce.php';
                if ( file_exists( $woocommerce_file ) ) {
                    require_once $woocommerce_file;
                    wf_sn_cf_render_woocommerce_content( self::$options, $ips );
                }
                ?>
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
                esc_html_e( 'Upgrade to Pro for WooCommerce Protection', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock WooCommerce protection features:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Rate limiting for checkout, add to cart, and order placement', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Coupon code brute force protection with temporary bans', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Automatic blocking of suspicious IPs', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Comprehensive logging of all security events', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Safe for legitimate customers with conservative default settings', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Configurable thresholds for different store sizes', 'security-ninja' );
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
		</div>


		<p class="submit"><br><input type="submit" value="<?php 
            echo esc_html__( 'Save Changes', 'security-ninja' );
            ?>" class="input-button button-primary" name="Submit" /></p>
		</form>
		</div>
	<?php 
        }
        // Only show modal if firewall is not active
        if ( 1 !== self::is_active() ) {
            ?>
	<div id="sn-firewall-modal" class="sn-modal">
		<div class="sn-modal-content">
			<h2><?php 
            esc_html_e( 'Enable Firewall', 'security-ninja' );
            ?></h2>
			<p><?php 
            esc_html_e( 'To ensure you can regain access to your website if you get blocked, please enter your email address. You will be sent a secret access URL to help you regain access.', 'security-ninja' );
            ?></p>

			<div class="sn-input-container">
				<input
					type="email"
					id="sn-firewall-email"
					autocomplete="off"
					placeholder="<?php 
            esc_attr_e( 'Enter your email', 'security-ninja' );
            ?>"
					value="<?php 
            echo esc_attr( wp_get_current_user()->user_email );
            ?>"
					required
					data-1p-ignore
					data-lpignore="true">
				<div class="sn-buttons">
					<a href="#" id="sn-modal-continue" class="button button-large button-primary">
						<?php 
            esc_html_e( 'Send email', 'security-ninja' );
            ?>
					</a>
					<a href="#" id="sn-modal-skip" class="button button-large button-secondary">
						<?php 
            esc_html_e( 'Activate, but no email', 'security-ninja' );
            ?>
					</a>
				</div>
			</div>


			<div id="sn-unblock-message"></div>
			<div id="sn-firewall-status"></div>
		</div>
	</div>
	<?php 
        }
        ?>


<?php 
    }

}

add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\wf_sn_cf', 'init') );
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\wf_sn_cf', 'deactivate') );