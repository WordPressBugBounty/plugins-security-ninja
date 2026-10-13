<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
define( 'WF_SN_CF_OPTIONS_KEY', 'wf_sn_cf' );
// @important - if changed, this is used various places, 2FA, etc.
if ( !defined( 'WF_SN_CF_VALIDATED_CRAWLERS' ) ) {
    define( 'WF_SN_CF_VALIDATED_CRAWLERS', 'wf_sn_cf_validated_crawlers' );
}
if ( !defined( 'WF_SN_CF_NETWORK_REPORT_QUEUE' ) ) {
    define( 'WF_SN_CF_NETWORK_REPORT_QUEUE', 'wf_sn_cf_network_report_queue' );
}
if ( !defined( 'WF_SN_CF_NETWORK_REPORT_BACKOFF' ) ) {
    define( 'WF_SN_CF_NETWORK_REPORT_BACKOFF', 'wf_sn_cf_network_report_backoff' );
}
class Wf_sn_cf {
    /**
     * Cached visitor IP for the current request.
     *
     * @var string|null
     */
    private static $cached_ip = null;

    /**
     * Cloud Firewall options.
     *
     * @var array<string, mixed>|null
     */
    public static $options = null;

    /**
     * Locally banned IPs (IP => expiry timestamp), cached per request.
     *
     * @var array<string, int>|null
     */
    public static $banned_ips = null;

    /**
     * Per-request cache for get_satellite_soften_info() keyed by IP (avoids duplicate ASN lookups).
     *
     * @var array<string, array{applies: bool, asn: int, as_label: string}>
     */
    private static $satellite_soften_info_cache = array();

    /**
     * Per-request keys for satellite soften event logging (md5 of IP + rule).
     *
     * @var array<string, bool>
     */
    private static $satellite_soften_logged = array();

    /**
     * Per-request cache for get_visitor_hostname() keyed by IP.
     *
     * @var array<string, string>
     */
    private static $visitor_hostname_cache = array();

    /**
     * Option flag set when leftover per-IP lookup transients have been removed.
     *
     * @since 5.302
     */
    const IP_LOOKUP_CLEANUP_OPTION = 'wf_sn_cf_ip_lookup_cleanup';

    /**
     * Cleanup generation. Bump when new prefixes must be swept.
     *
     * @since 5.302
     */
    const IP_LOOKUP_CLEANUP_DONE = '5.302';

    /**
     * Whether this request already ran an IP lookup-cache cleanup batch.
     *
     * @var bool
     */
    private static $ip_lookup_cleanup_ran = false;

    /**
     * Per-request cache for cloud IP blocklist option (wf_sn_cf_ips).
     *
     * @var array|null|false null = not loaded; false = missing/invalid; array = decoded option.
     */
    private static $cloud_ips_cache = null;

    public static $central_api_url = 'https://api.wpsecurityninja.com/api/';

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
        add_action( 'init', array(__CLASS__, 'maybe_schedule_ip_lookup_cache_cleanup'), 20 );
        add_action( 'secnin_prune_ip_lookup_transients', array(__CLASS__, 'prune_ip_lookup_transients') );
        add_action( 'security_ninja_firewall_settings_saved', array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all') );
        add_action(
            'update_option_wf_sn_cf',
            array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all'),
            10,
            3
        );
        add_action(
            'update_option_wf_sn_banned_ips',
            array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all'),
            10,
            3
        );
        add_action(
            'update_option_wf_sn_cf_ips',
            array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all'),
            10,
            3
        );
        add_action(
            'activated_plugin',
            array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all_void'),
            10,
            0
        );
        add_action(
            'deactivated_plugin',
            array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all_void'),
            10,
            0
        );
        add_action( 'init', array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'consume_unlock_pending'), 0 );
        add_action( 'init', array(__NAMESPACE__ . '\\Secnin_Waf_Recorder', 'maybe_import_early_queue'), 1 );
        add_action( 'init', array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'maybe_set_admin_cookie'), 20 );
        add_action( 'admin_notices', array(__NAMESPACE__ . '\\Secnin_Waf_Lifecycle', 'maybe_admin_notice') );
        add_action( 'secnin_update_cloud_firewall', array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all') );
        add_action( 'secnin_prune_banned', array(__NAMESPACE__ . '\\Secnin_Waf_Config', 'sync_all') );
        // Basic login/failed login logging for all versions
        add_action(
            'wp_login',
            array(__NAMESPACE__ . '\\wf_sn_cf', 'log_successful_login'),
            10,
            2
        );
        add_action( 'wp_login_failed', array(__NAMESPACE__ . '\\wf_sn_cf', 'failed_login') );
        if ( is_admin() ) {
            require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
            // add tab to Security Ninja tabs
            add_filter( 'sn_tabs', array(__NAMESPACE__ . '\\wf_sn_cf', 'sn_tabs') );
            // Register settings
            add_action( 'admin_init', array(__NAMESPACE__ . '\\wf_sn_cf', 'register_settings') );
            // Register AJAX actions
            add_action( 'wp_ajax_sn_enable_firewall', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_enable_firewall') );
            add_action( 'wp_ajax_sn_disable_firewall', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_disable_firewall') );
            add_action( 'wp_ajax_sn_send_unblock_email', array(__NAMESPACE__ . '\\wf_sn_cf', 'ajax_send_unblock_email') );
            add_action( 'admin_post_sn_save_login_settings', array(__NAMESPACE__ . '\\wf_sn_cf', 'save_login_settings') );
            // Enqueue scripts and styles
            add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\wf_sn_cf', 'enqueue_scripts'), 100 );
        }
    }

    /**
     * Process IP only early.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, May 21st, 2024.
     * @version v1.0.1  Monday, January 13th, 2025 - Added REST API protection
     * @access  public static
     * @return  void
     */
    public static function do_init_action() {
        // Load options if not already loaded
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        // Check for safe URL unlock parameter BEFORE checking bans
        // This allows blocked visitors to whitelist their IP using the secret access URL
        $snf_given = ( isset( $_REQUEST['snf'] ) ? sanitize_key( wp_unslash( $_REQUEST['snf'] ) ) : '' );
        $snf_stored = ( isset( self::$options['unblock_url'] ) ? (string) self::$options['unblock_url'] : '' );
        if ( '' !== $snf_stored && '' !== $snf_given && strlen( $snf_given ) === strlen( $snf_stored ) && hash_equals( $snf_stored, $snf_given ) ) {
            $current_user_ip = self::get_user_ip();
            $local_whitelist = self::$options['whitelist'];
            if ( !is_array( $local_whitelist ) ) {
                $local_whitelist = array();
            }
            // Use CIDR-aware check so secret URL does not append a duplicate IP when already covered by a range.
            if ( !Wf_sn_cf_Utils::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
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
        if ( wp_doing_cron() || defined( 'WP_CLI' ) && WP_CLI ) {
            return;
        }
        // Kill-switch: no ban enforcement or query filtering when firewall is disabled.
        // Secret unlock URL above still works so users can whitelist their IP.
        if ( 1 !== self::is_active() ) {
            return;
        }
        // Early Firewall: skip only capabilities proven complete for this request.
        $skip_ban_enforcement = false;
        if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) && Secnin_Waf_Extended::is_active() ) {
            $skip_ban = Secnin_Waf_Extended::early_capability_complete( 'local_bans' ) && Secnin_Waf_Extended::early_capability_complete( 'cloud_ips' );
            $skip_8g = Secnin_Waf_Extended::early_capability_complete( 'query_filter' );
            if ( $skip_ban && $skip_8g ) {
                return;
            }
            if ( $skip_ban ) {
                $skip_ban_enforcement = true;
            }
        }
        $current_user_ip = self::get_user_ip();
        // Skip expensive ban checks for logged-in admins (all contexts including front-end and REST).
        // (Secret unlock, cron/CLI, and inactive firewall already returned above.)
        if ( !$skip_ban_enforcement ) {
            $skip_ban_enforcement = self::should_skip_ban_enforcement();
        }
        $reason = false;
        if ( !$skip_ban_enforcement ) {
            $reason = self::is_banned_ip( $current_user_ip );
        }
        if ( $reason ) {
            // SureCart cloud webhooks must not be killed by visitor IP/country bans.
            $sc_helper = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/class-secnin-waf-surecart-payment-surface.php';
            if ( !class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) && is_readable( $sc_helper ) ) {
                require_once $sc_helper;
            }
            if ( class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) ) {
                $sc_ctx = \Secnin_Waf_Surecart_Payment_Surface::context_from_server( 
                    $_SERVER,
                    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Detection only.
                    defined( 'SURECART_PLUGIN_FILE' )
                 );
                if ( \Secnin_Waf_Surecart_Payment_Surface::is_webhook_request( $sc_ctx ) ) {
                    return;
                }
            }
            self::update_blocked_count( $current_user_ip );
            $ua_string = '';
            if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
                $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
            }
            $data = array(
                'user_agent' => $ua_string,
                'ip'         => $current_user_ip,
                'reason'     => $reason,
            );
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
            $local_whitelist = self::$options['whitelist'];
            if ( !is_array( $local_whitelist ) ) {
                $local_whitelist = array();
            }
            if ( Wf_sn_cf_Utils::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
                $whitelisted_user = true;
            }
            if ( self::is_whitelisted_service( $current_user_ip ) ) {
                $whitelisted_user = true;
            }
            $validated_crawlers = get_option( WF_SN_CF_VALIDATED_CRAWLERS );
            if ( is_array( $validated_crawlers ) && in_array( $current_user_ip, $validated_crawlers, true ) ) {
                $whitelisted_user = true;
            }
            // Always check for bad queries (even for whitelisted users), but skip AJAX, cron, and admin requests
            if ( !wp_doing_ajax() && !wp_doing_cron() && !is_admin() ) {
                // Skip security checks for temporary login links
                if ( self::is_temporary_login_link() ) {
                    return;
                    // Allow temporary login links through
                }
                $bad_query = self::check_bad_queries();
                if ( $bad_query !== false ) {
                    // Detects if we are importing
                    if ( defined( 'WP_IMPORTING' ) && $bad_query ) {
                        // set the query to false, not going to block but we left a notice
                        $bad_query = false;
                    }
                    if ( $bad_query ) {
                        $extramessage = '';
                        $extraarr = array(
                            'ban_type' => '',
                        );
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
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 14th, 2025.
     * @param   mixed   $user_login
     * @param   mixed   $user
     * @return  void
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
        // Check if login was via temporary login plugin
        $temp_login_plugin = self::get_temporary_login_plugin_name();
        if ( $temp_login_plugin ) {
            $description = sprintf(
                /* translators: 1: User login name, 2: IP address, 3: Temporary login plugin name */
                __( '%1$s logged in successfully from %2$s via temporary login (%3$s)', 'security-ninja' ),
                esc_html( $user_login ),
                esc_html( $current_user_ip ),
                esc_html( $temp_login_plugin )
            );
        } else {
            $description = sprintf( 
                /* translators: 1: User login name, 2: IP address */
                __( '%1$s logged in successfully from %2$s', 'security-ninja' ),
                esc_html( $user_login ),
                esc_html( $current_user_ip )
             );
        }
        $event_data = array(
            'ip'         => $current_user_ip,
            'username'   => $user_login,
            'user_id'    => $user->ID,
            'user_agent' => $ua_string,
        );
        // Add temporary login plugin info if detected
        if ( $temp_login_plugin ) {
            $event_data['temporary_login_plugin'] = $temp_login_plugin;
        }
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
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, February 6th, 2024.
     * @param   mixed   $user_login
     * @param   mixed   $user
     * @return  void
     */
    public static function set_login_timestamp( $user_login, $user ) {
        if ( !is_object( $user ) || !isset( $user->ID ) ) {
            return;
        }
        update_user_meta( $user->ID, 'sn_last_login', current_time( 'mysql' ) );
    }

    /**
     * Reverse DNS hostname for an IP with per-request and object-cache caching.
     *
     * Per-IP values are not stored as WordPress transients in wp_options. On hosts
     * without Redis/Memcached that filled the options table with one row per visitor
     * IP and could stall MySQL. Persistent cache is used only when an external
     * object cache is present.
     *
     * @author  Lars Koudal
     * @since   5.289
     * @param   string $ip IP address.
     * @return  string Lowercase hostname, or the IP on lookup failure (matches gethostbyaddr behavior).
     */
    public static function get_visitor_hostname( $ip ) {
        if ( !is_string( $ip ) || '' === $ip ) {
            return '';
        }
        if ( isset( self::$visitor_hostname_cache[$ip] ) ) {
            return self::$visitor_hostname_cache[$ip];
        }
        $transient_key = 'wf_sn_cf_rdns_' . md5( $ip );
        $cached = Wf_sn_cf_Utils::get_ip_lookup_cache( $transient_key );
        if ( is_string( $cached ) && '' !== $cached ) {
            self::$visitor_hostname_cache[$ip] = $cached;
            return $cached;
        }
        $hostname = gethostbyaddr( $ip );
        if ( !is_string( $hostname ) || '' === $hostname ) {
            $hostname = $ip;
        }
        $hostname = strtolower( $hostname );
        Wf_sn_cf_Utils::set_ip_lookup_cache( $transient_key, $hostname, WEEK_IN_SECONDS );
        self::$visitor_hostname_cache[$ip] = $hostname;
        return $hostname;
    }

    /**
     * Transient key prefixes used for per-IP firewall lookup caches.
     *
     * @since 5.302
     * @return array<int, string>
     */
    public static function get_ip_lookup_transient_prefixes() {
        return array('wf_sn_cf_rdns_', 'sn_cf_asn_v1_', 'sn_cf_geoip_');
    }

    /**
     * Read a per-IP lookup cache entry.
     *
     * Thin wrapper around Wf_sn_cf_Utils for callers and tests.
     *
     * @since 5.302
     * @param string $key Transient key (without _transient_ prefix).
     * @return mixed Cached value, or false on miss.
     */
    public static function get_ip_lookup_cache( $key ) {
        return Wf_sn_cf_Utils::get_ip_lookup_cache( $key );
    }

    /**
     * Store a per-IP lookup cache entry.
     *
     * Thin wrapper around Wf_sn_cf_Utils for callers and tests.
     *
     * @since 5.302
     * @param string $key   Transient key (without _transient_ prefix).
     * @param mixed  $value Value to cache.
     * @param int    $ttl   TTL in seconds.
     * @return void
     */
    public static function set_ip_lookup_cache( $key, $value, $ttl ) {
        Wf_sn_cf_Utils::set_ip_lookup_cache( $key, $value, $ttl );
    }

    /**
     * Schedule leftover per-IP transient cleanup after update, and run one batch.
     *
     * Runs even when the firewall is off so already-bloated options tables recover.
     *
     * @since 5.302
     * @return void
     */
    public static function maybe_schedule_ip_lookup_cache_cleanup() {
        if ( self::IP_LOOKUP_CLEANUP_DONE === get_option( self::IP_LOOKUP_CLEANUP_OPTION ) ) {
            return;
        }
        if ( self::$ip_lookup_cleanup_ran ) {
            return;
        }
        self::$ip_lookup_cleanup_ran = true;
        self::prune_ip_lookup_transients();
    }

    /**
     * Delete leftover per-IP lookup transients in small batches.
     *
     * @since 5.302
     * @return int Number of options rows deleted in this run.
     */
    public static function prune_ip_lookup_transients() {
        $max_batches = ( wp_doing_cron() ? 8 : 1 );
        $batch_limit = 250;
        $deleted = 0;
        $drained = false;
        for ($i = 0; $i < $max_batches; $i++) {
            $n = self::delete_ip_lookup_transient_batch( $batch_limit );
            if ( false === $n ) {
                if ( !wp_next_scheduled( 'secnin_prune_ip_lookup_transients' ) ) {
                    wp_schedule_single_event( time() + 60, 'secnin_prune_ip_lookup_transients' );
                }
                return $deleted;
            }
            $deleted += (int) $n;
            if ( $n < $batch_limit ) {
                $drained = true;
                break;
            }
        }
        if ( $deleted > 0 ) {
            wp_cache_delete( 'alloptions', 'options' );
            wp_cache_delete( 'notoptions', 'options' );
        }
        if ( $drained ) {
            update_option( self::IP_LOOKUP_CLEANUP_OPTION, self::IP_LOOKUP_CLEANUP_DONE, false );
            wp_clear_scheduled_hook( 'secnin_prune_ip_lookup_transients' );
            return $deleted;
        }
        if ( !wp_next_scheduled( 'secnin_prune_ip_lookup_transients' ) ) {
            wp_schedule_single_event( time() + 15, 'secnin_prune_ip_lookup_transients' );
        }
        return $deleted;
    }

    /**
     * Delete remaining per-IP lookup transients (uninstall / one-shot).
     *
     * @since 5.302
     * @param int $max_seconds Time budget in seconds.
     * @return int Total rows deleted.
     */
    public static function delete_all_ip_lookup_transients( $max_seconds = 20 ) {
        $started = time();
        $max_seconds = max( 1, (int) $max_seconds );
        $deleted = 0;
        do {
            $n = self::delete_ip_lookup_transient_batch( 500 );
            if ( false === $n || $n < 1 ) {
                break;
            }
            $deleted += $n;
        } while ( time() - $started < $max_seconds );
        wp_cache_delete( 'alloptions', 'options' );
        wp_cache_delete( 'notoptions', 'options' );
        wp_clear_scheduled_hook( 'secnin_prune_ip_lookup_transients' );
        delete_option( self::IP_LOOKUP_CLEANUP_OPTION );
        return $deleted;
    }

    /**
     * Delete one batch of per-IP lookup transients and their timeout rows.
     *
     * @since 5.302
     * @param int $limit Max rows to delete.
     * @return int|false Rows deleted, 0 if none, false on query failure.
     */
    private static function delete_ip_lookup_transient_batch( $limit = 250 ) {
        global $wpdb;
        $limit = absint( $limit );
        if ( $limit < 1 ) {
            $limit = 250;
        }
        $likes = array();
        foreach ( self::get_ip_lookup_transient_prefixes() as $prefix ) {
            $likes[] = $wpdb->esc_like( '_transient_' . $prefix ) . '%';
            $likes[] = $wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%';
        }
        $placeholders = implode( ' OR ', array_fill( 0, count( $likes ), 'option_name LIKE %s' ) );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $result = $wpdb->query( $wpdb->prepare( 
            "DELETE FROM {$wpdb->options} WHERE {$placeholders} LIMIT {$limit}",
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- placeholders from esc_like prefixes; limit is absint.
            ...$likes
         ) );
        return $result;
    }

    public static function validate_crawler_ip( $testip, $ua = null ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-service-whitelist.php';
        return Wf_Sn_Cf_Service_Whitelist::validate_crawler_ip( $testip, $ua );
    }

    public static function is_whitelisted_service( $current_user_ip ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-service-whitelist.php';
        return Wf_Sn_Cf_Service_Whitelist::is_whitelisted_service( $current_user_ip );
    }

    /**
     * Resolve this server's IP once per request (and cache 1 hour across requests).
     *
     * Used to avoid treating the server itself as a banned visitor.
     *
     * @return string Server IP or empty string on failure.
     */
    public static function get_server_ip() {
        static $server_ip = null;
        if ( null !== $server_ip ) {
            return $server_ip;
        }
        $cached = get_transient( 'wf_sn_cf_server_ip' );
        if ( is_string( $cached ) && filter_var( $cached, FILTER_VALIDATE_IP ) ) {
            $server_ip = $cached;
            return $server_ip;
        }
        $host = gethostname();
        $resolved = ( $host ? gethostbyname( $host ) : '' );
        if ( is_string( $resolved ) && filter_var( $resolved, FILTER_VALIDATE_IP ) ) {
            $server_ip = $resolved;
            set_transient( 'wf_sn_cf_server_ip', $server_ip, HOUR_IN_SECONDS );
        } else {
            $server_ip = '';
        }
        return $server_ip;
    }

    /**
     * Cloud IP blocklist option, cached for the current request.
     *
     * @return array|false Decoded option array, or false if missing/invalid.
     */
    private static function get_cloud_ips_data() {
        if ( null !== self::$cloud_ips_cache ) {
            return self::$cloud_ips_cache;
        }
        $ips = get_option( 'wf_sn_cf_ips' );
        self::$cloud_ips_cache = ( is_array( $ips ) ? $ips : false );
        return self::$cloud_ips_cache;
    }

    /**
     * Clear the per-request cloud IP cache after the option is updated.
     *
     * @return void
     */
    public static function clear_cloud_ips_cache() {
        self::$cloud_ips_cache = null;
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
        // Filter out AJAX, cron and admin related requests
        if ( wp_doing_ajax() || wp_doing_cron() || is_admin() ) {
            return;
        }
        $server_ip = self::get_server_ip();
        $whitelisted_user = false;
        $visit_logged = false;
        $current_user_ip = self::get_user_ip();
        if ( $server_ip === $current_user_ip ) {
            return;
        }
        if ( current_user_can( 'manage_options' ) ) {
            // A user with admin privileges
            $whitelisted_user = true;
        }
        // Prevents user from being blocked even from a blocked country if IP is whitelisted (exact IP or CIDR range).
        $local_whitelist = self::$options['whitelist'];
        if ( !is_array( $local_whitelist ) ) {
            $local_whitelist = array();
        }
        if ( Wf_sn_cf_Utils::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
            $whitelisted_user = true;
        }
        if ( self::is_whitelisted_service( $current_user_ip ) ) {
            $whitelisted_user = true;
        }
        if ( in_array( $current_user_ip, array('::1', '127.0.0.1'), true ) ) {
            // Do not auto-trust localhost for WAF/logging unless explicitly whitelisted.
            if ( !Wf_sn_cf_Utils::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
                $whitelisted_user = false;
            }
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
        // Check if an IP is banned and blocks (skip when Extended WAF already ran).
        $skip_early_waf_dup = class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) && Secnin_Waf_Extended::is_active() && Secnin_Waf_Extended::early_capability_complete( 'local_bans' ) && Secnin_Waf_Extended::early_capability_complete( 'cloud_ips' );
        if ( !$whitelisted_user && 1 === (int) self::$options['active'] && !$skip_early_waf_dup ) {
            $ban_reason = self::is_banned_ip( $current_user_ip );
            if ( $ban_reason ) {
                // Free build: when global is OFF, block here (free has no login-only helper).
                // Premium continues below for login pages or full-site bans.
                if ( !self::$options['global'] ) {
                    $is_premium_build = false;
                    if ( !$is_premium_build ) {
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
                }
                // Login-related request in login-only mode, or full-site ban — proceed with blocking.
                $premium_logged = false;
                if ( !$premium_logged ) {
                    wf_sn_el_modules::log_event(
                        'security_ninja',
                        'blocked_ip_banned',
                        __( 'IP is blocked.', 'security-ninja' ),
                        array(
                            'ip'         => $current_user_ip,
                            'ban_reason' => $ban_reason,
                        )
                    );
                }
                self::update_blocked_count( $current_user_ip );
                self::kill_request();
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
        if ( apply_filters( 'wf_sn_cf_skip_bad_query_check', false ) ) {
            return false;
        }
        $helper_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/class-secnin-waf-woo-payment-surface.php';
        if ( !class_exists( '\\Secnin_Waf_Woo_Payment_Surface', false ) && is_readable( $helper_file ) ) {
            require_once $helper_file;
        }
        $sc_helper = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/class-secnin-waf-surecart-payment-surface.php';
        if ( !class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) && is_readable( $sc_helper ) ) {
            require_once $sc_helper;
        }
        $rules_8g = (include WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/rules-8g.php');
        if ( !is_array( $rules_8g ) ) {
            $rules_8g = array();
        }
        $request_uri_array = apply_filters( 'request_uri_items', ( isset( $rules_8g['request_uri'] ) && is_array( $rules_8g['request_uri'] ) ? $rules_8g['request_uri'] : array() ) );
        $query_string_array = apply_filters( 'query_string_items', ( isset( $rules_8g['query_string'] ) && is_array( $rules_8g['query_string'] ) ? $rules_8g['query_string'] : array() ) );
        $user_agent_array = apply_filters( 'user_agent_items', ( isset( $rules_8g['user_agent'] ) && is_array( $rules_8g['user_agent'] ) ? $rules_8g['user_agent'] : array() ) );
        $referrer_array = apply_filters( 'referrer_items', ( isset( $rules_8g['referrer'] ) && is_array( $rules_8g['referrer'] ) ? $rules_8g['referrer'] : array() ) );
        $request_uri_string = false;
        $query_string_string = false;
        $user_agent_string = false;
        $referrer_string = false;
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
        $has_remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) && !empty( $_SERVER['REMOTE_ADDR'] );
        if ( !$request_uri_string && !$query_string_string && !$user_agent_string && !$referrer_string && !$has_remote_addr ) {
            return false;
        }
        if ( $request_uri_string ) {
            if ( !function_exists( 'secnin_waf_request_path' ) ) {
                $login_related = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/secnin-waf-login-related.php';
                if ( is_readable( $login_related ) ) {
                    require_once $login_related;
                }
            }
            if ( function_exists( 'secnin_waf_request_path' ) ) {
                $request_uri_string = secnin_waf_request_path( $request_uri_string );
            }
        }
        $payment = false;
        if ( class_exists( '\\Secnin_Waf_Woo_Payment_Surface', false ) ) {
            $payment_ctx = \Secnin_Waf_Woo_Payment_Surface::context_from_server( 
                $_SERVER,
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Detection only; values are not stored.
                class_exists( 'WooCommerce' )
             );
            $payment = \Secnin_Waf_Woo_Payment_Surface::is_payment_request( $payment_ctx );
        }
        if ( !$payment && class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) ) {
            $sc_ctx = \Secnin_Waf_Surecart_Payment_Surface::context_from_server( 
                $_SERVER,
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Detection only; values are not stored.
                defined( 'SURECART_PLUGIN_FILE' )
             );
            $payment = \Secnin_Waf_Surecart_Payment_Surface::is_payment_request( $sc_ctx );
        }
        $response = array();
        if ( $request_uri_string ) {
            foreach ( $request_uri_array as $key => $pattern ) {
                // Direct use of pattern in preg_match, without preg_quote
                if ( preg_match( '#' . $pattern . '#i', $request_uri_string, $req_matches ) ) {
                    $response = array(
                        'request_uri'  => esc_html( $req_matches[0] ),
                        'matched_rule' => esc_html( $key ),
                        'message'      => 'A match was found in the request URI.',
                    );
                    break;
                }
            }
        }
        if ( empty( $response ) && $query_string_string ) {
            foreach ( $query_string_array as $key => $item ) {
                $skip_q = $payment && (class_exists( '\\Secnin_Waf_Woo_Payment_Surface', false ) && \Secnin_Waf_Woo_Payment_Surface::should_skip_query_rule( $key ) || class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) && \Secnin_Waf_Surecart_Payment_Surface::should_skip_query_rule( $key ));
                if ( $skip_q ) {
                    continue;
                }
                // Directly use the pattern without preg_quote() for regex matching
                if ( preg_match( '#' . $item . '#i', $query_string_string, $query_matches ) ) {
                    $response = array(
                        'query_string'        => esc_html( $query_matches[0] ),
                        'query_string_string' => esc_html( $query_string_string ),
                        'matched_rule'        => esc_html( $key ),
                        'message'             => 'A match was found in the query string.',
                    );
                    break;
                }
            }
        }
        if ( empty( $response ) && $user_agent_string ) {
            foreach ( $user_agent_array as $key => $item ) {
                if ( $payment ) {
                    if ( class_exists( '\\Secnin_Waf_Woo_Payment_Surface', false ) ) {
                        $item = \Secnin_Waf_Woo_Payment_Surface::ua_pattern_for_surface( $key, $item );
                    } elseif ( class_exists( '\\Secnin_Waf_Surecart_Payment_Surface', false ) ) {
                        $item = \Secnin_Waf_Surecart_Payment_Surface::ua_pattern_for_surface( $key, $item );
                    }
                }
                // Using '#' as delimiter to avoid conflicts with common characters in user agents
                if ( preg_match( '#' . $item . '#i', $user_agent_string, $ua_matches ) ) {
                    $response = array(
                        'http_user_agent'   => esc_html( $ua_matches[0] ),
                        'user_agent_string' => esc_html( $user_agent_string ),
                        'matched_rule'      => esc_html( $key ),
                        'message'           => 'A match was found in the user agent.',
                    );
                    break;
                }
            }
        }
        if ( empty( $response ) && $referrer_string ) {
            foreach ( $referrer_array as $key => $item ) {
                if ( preg_match( '#' . $item . '#i', $referrer_string, $rf_matches ) ) {
                    $response = array(
                        'referrer'        => esc_html( $rf_matches[0] ),
                        'referrer_string' => esc_html( $referrer_string ),
                        'matched_rule'    => esc_html( $key ),
                        'message'         => 'A match was found in the referrer.',
                    );
                    break;
                }
            }
        }
        if ( empty( $response ) && $has_remote_addr && apply_filters( 'secnin_cf_check_blocked_hosts', false ) ) {
            $blocked_hosts_array = self::get_blocked_hosts_array();
            $visitor_host = self::get_visitor_hostname( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) );
            foreach ( $blocked_hosts_array as $key => $item ) {
                if ( preg_match( '#\\b' . preg_quote( $item, '#' ) . '\\b#i', $visitor_host, $matches ) ) {
                    $response = array(
                        'blocked_host' => esc_html( $matches[0] ),
                        'visitor_host' => esc_html( $visitor_host ),
                        'matched_rule' => esc_html( $key ),
                        'message'      => 'A match was found in the blocked hosts.',
                    );
                    break;
                }
            }
        }
        if ( !empty( $response ) ) {
            return $response;
        }
        return false;
    }

    /**
     * Default blocked-hosts hostname patterns, after the blocked_hosts_items filter.
     *
     * Permanently strips removed rules (e.g. blocked_kanagawa) so a future 8G sync
     * or a filter cannot restore them. Ticket #8215: "kanagawa" is a Japanese
     * prefecture and matched legitimate OCN ISP hostnames.
     *
     * @since 5.300
     * @return array<string, string>
     */
    private static function get_blocked_hosts_array() {
        $blocked_hosts_array = apply_filters( 'blocked_hosts_items', array(
            'blocked_163data'           => '163data',
            'blocked_colocrossing'      => 'colocrossing',
            'blocked_crimea'            => 'crimea',
            'blocked_g00g1e'            => 'g00g1e',
            'blocked_justhost'          => 'justhost',
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
        if ( !is_array( $blocked_hosts_array ) ) {
            return array();
        }
        // Do not re-add: Japanese prefecture / OCN false positives (ticket #8215).
        $removed_keys = array('blocked_kanagawa');
        foreach ( $removed_keys as $removed_key ) {
            unset($blocked_hosts_array[$removed_key]);
        }
        return $blocked_hosts_array;
    }

    public static function is_temporary_login_link() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-temp-login.php';
        return Wf_Sn_Cf_Temp_Login::is_temporary_login_link();
    }

    public static function get_temporary_login_plugin_name() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-temp-login.php';
        return Wf_Sn_Cf_Temp_Login::get_temporary_login_plugin_name();
    }

    /**
     * Terminate current request - Checks if option is set to redirect to an URL first
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Saturday, December 10th, 2022.
     * @version v1.0.2  Wednesday, December 20th, 2023.
     * @version v1.0.3  Monday, May 12th, 2025.
     * @access  public static
     * @param   mixed   $current_user_ip    Default: null
     * @param   string  $reason             Default: ''
     * @param   mixed   $time               Reserved for backward compatibility.
     * @param   boolean $register_block     Reserved for backward compatibility.
     * @return  void
     */
    public static function kill_request(
        $current_user_ip = null,
        $reason = '',
        $time = 1 * DAY_IN_SECONDS,
        $register_block = false
    ) {
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
        if ( !empty( $redirect_url ) && wp_http_validate_url( $redirect_url ) ) {
            $redirect_scheme = wp_parse_url( $redirect_url, PHP_URL_SCHEME );
            $redirect_scheme = ( is_string( $redirect_scheme ) ? strtolower( $redirect_scheme ) : '' );
            if ( in_array( $redirect_scheme, array('http', 'https'), true ) ) {
                // Redirect target is admin-configured and validated above.
                wp_redirect( $redirect_url, 301 );
                // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
                exit;
            }
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
        wp_die( wp_kses_post( $message ), esc_html__( 'Blocked', 'security-ninja' ), array(
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
     * @param   mixed   $ip Reserved for backward compatibility; counts are aggregate.
     * @return  void
     */
    public static function update_blocked_count( $ip ) {
        $blocked_count = get_option( 'wf_sn_cf_blocked_count' );
        if ( $blocked_count ) {
            ++$blocked_count;
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

    public static function prune_visitor_log( $force = false ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-cron.php';
        return Wf_Sn_Cf_Cron::prune_visitor_log( $force );
    }

    /**
     * Table name built from the WordPress prefix and a fixed suffix.
     *
     * %i identifiers need WordPress 6.2. This plugin still supports 4.7, so callers
     * interpolate this only after the name matches [A-Za-z0-9_].
     *
     * @param string $suffix Table name without the prefix.
     * @return string Empty when the name is not a safe identifier.
     */
    private static function validated_table( $suffix ) {
        global $wpdb;
        $name = $wpdb->prefix . $suffix;
        if ( !is_string( $name ) || !preg_match( '/^[A-Za-z0-9_]+$/', $name ) ) {
            return '';
        }
        return $name;
    }

    public static function clear_visitor_log() {
        global $wpdb;
        $table_name = self::validated_table( 'wf_sn_cf_vl' );
        if ( '' === $table_name ) {
            return false;
        }
        if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) !== $table_name ) {
            return false;
        }
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- identifier from validated_table().
        $wpdb->query( "TRUNCATE TABLE `{$table_name}`" );
        if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'cleared_visitor_log',
                esc_html__( 'Manually cleared firewall visitor log.', 'security-ninja' ),
                ''
            );
        }
        return true;
    }

    /**
     * clean-up when deactivated
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Thursday, January 14th, 2021.
     * @version v1.0.1  Monday, February 21st, 2022.
     * @version v1.0.2  Saturday, November 19th, 2022.
     * @access  public static
     * @return  void
     */
    public static function deactivate() {
        // Staged Early Firewall cleanup: remove owned markers; keep proxy until PHP stops prepend.
        if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
            Secnin_Waf_Lifecycle::safe_deactivate_cleanup();
        }
        $cron_hooks = array(
            'secnin_update_geoip',
            'secnin_update_cloud_firewall',
            'secnin_prune_visitor_log',
            'secnin_prune_banned',
            'secnin_update_blocked_ips',
            'secnin_flush_network_reports',
            'secnin_prune_ip_lookup_transients',
            'secnin_geoip_updater'
        );
        foreach ( $cron_hooks as $cron_hook ) {
            wp_clear_scheduled_hook( $cron_hook );
        }
        delete_option( WF_SN_CF_NETWORK_REPORT_QUEUE );
        if ( !\WPSecurityNinja\Plugin\Utils::should_remove_settings_on_deactivate() ) {
            return;
        }
        global $wpdb;
        $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_cf_vl' );
        $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_cf_bl_ips' );
        delete_option( 'wf_sn_cf_bl_ips' );
        delete_option( 'wf_sn_cf_vl' );
        delete_option( WF_SN_CF_VALIDATED_CRAWLERS );
        delete_option( WF_SN_CF_AI_CRAWLER_RANGES );
        delete_option( 'wf_sn_cf_blocked_count' );
        delete_option( 'wf_sn_cf_blocked_today' );
        delete_option( WF_SN_CF_OPTIONS_KEY );
        delete_option( 'wf_sn_cf_ips' );
        delete_option( 'wf_sn_cf_extended' );
        delete_option( 'wf_sn_cf_waf_cookie_key' );
        delete_option( 'wf_sn_cf_waf_recovery' );
        delete_option( 'wf_sn_cf_waf_event_receipts' );
        if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
            Secnin_Waf_Lifecycle::wipe_data_dir_if_safe();
        }
        self::clear_cloud_ips_cache();
        self::delete_all_ip_lookup_transients();
        delete_option( 'wf_sn_banned_ips' );
        // list of locally banned IPs
    }

    /**
     * Refresh Early Firewall runtime after plugin update / version mismatch.
     *
     * @return void
     */
    public static function maybe_refresh_waf_runtime_bundle() {
    }

    /**
     * After Security Ninja plugin upgrade, republish Early Firewall runtime.
     *
     * @param \WP_Upgrader $upgrader Upgrader.
     * @param array        $options  Options.
     * @return void
     */
    public static function on_plugin_upgrader_complete( $upgrader, $options ) {
    }

    public static function schedule_cron_jobs() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-cron.php';
        return Wf_Sn_Cf_Cron::schedule_cron_jobs();
    }

    public static function enqueue_scripts() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::enqueue_scripts();
    }

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
            'trackvisits'                   => 0,
            'trackvisits_howlong'           => 7,
            'usecloud'                      => 1,
            'protect_login_form'            => 1,
            'hide_login_errors'             => 1,
            'failed_login_email_warning'    => 0,
            'blocked_countries'             => array(),
            'countryblock_loginonly'        => 0,
            'blacklist'                     => array(),
            'whitelist'                     => array(self::get_user_ip()),
            'blacklist_notes'               => array(),
            'whitelist_notes'               => array(),
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
            '2fa_required_roles'            => array(),
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
            'satellite_soft_enabled'        => 1,
            'satellite_soft_asns'           => array('14593'),
            'ip_source'                     => 'auto',
            'trusted_proxy_cidrs'           => array(),
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
            'satellite_soft_enabled',
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
        $two_fa_on = !empty( $return['2fa_enabled'] );
        $return['2fa_required_roles'] = self::normalize_2fa_required_roles( $return['2fa_required_roles'] ?? array(), $two_fa_on );
        $return['2fa_methods'] = self::normalize_2fa_methods( $return['2fa_methods'] ?? array() );
        $return['ip_source'] = self::normalize_ip_source( $return['ip_source'] ?? 'auto' );
        $return['trusted_proxy_cidrs'] = Wf_sn_cf_Utils::sanitize_trusted_proxy_cidrs( $return['trusted_proxy_cidrs'] ?? array() );
        return $return;
    }

    /**
     * Drop the in-request options cache so the next get_options() reads from the database.
     *
     * @return void
     */
    public static function reset_cached_options() {
        self::$options = null;
    }

    public static function sanitize_2fa_required_role_slugs( $raw ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::sanitize_2fa_required_role_slugs( $raw );
    }

    public static function normalize_2fa_required_roles( $raw, $two_fa_enabled ) {
        unset($two_fa_enabled);
        return self::sanitize_2fa_required_role_slugs( $raw );
    }

    public static function sanitize_2fa_methods_list( $raw ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::sanitize_2fa_methods_list( $raw );
    }

    public static function normalize_2fa_methods( $raw ) {
        $out = self::sanitize_2fa_methods_list( $raw );
        if ( empty( $out ) ) {
            return array('app');
        }
        return $out;
    }

    /**
     * Clear 2FA user meta when 2FA is first enabled, preserving voluntary opt-in enrollments.
     *
     * @return void
     */
    public static function clear_2fa_user_meta_on_first_enable() {
        $users = get_users();
        foreach ( $users as $user ) {
            if ( '1' === get_user_meta( $user->ID, 'secnin_2fa_optin', true ) ) {
                continue;
            }
            delete_user_meta( $user->ID, 'secnin_2fa_secret' );
            delete_user_meta( $user->ID, 'secnin_2fa_setup_complete' );
            delete_user_meta( $user->ID, 'secnin_2fa_code_validated' );
            delete_user_meta( $user->ID, 'secnin_2fa_session_validated' );
            delete_user_meta( $user->ID, 'secnin_2fa_method' );
        }
    }

    public static function ajax_enable_firewall() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_enable_firewall();
    }

    public static function ajax_disable_firewall() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_disable_firewall();
    }

    public static function ajax_test_ip() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_test_ip();
    }

    public static function url_to_domain( $url ) {
        return implode( array_slice( explode( '/', preg_replace( '/https?:\\/\\/(www\\.)?/', '', $url ) ), 0, 1 ) );
    }

    /**
     * Reject IP Management AJAX when premium code is unavailable.
     *
     * @return void
     */
    public static function require_premium_ip_management_ajax() {
        $denied = true;
        if ( $denied ) {
            wp_send_json_error( array(
                'message' => __( 'IP Management is not available.', 'security-ninja' ),
            ) );
        }
    }

    public static function ajax_add_ip_rule() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_add_ip_rule();
    }

    public static function ajax_edit_ip_rule() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_edit_ip_rule();
    }

    public static function ajax_remove_ip_rule() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_remove_ip_rule();
    }

    public static function ajax_bulk_add_ip_rules() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_bulk_add_ip_rules();
    }

    public static function get_banned_ips() {
        if ( !is_null( self::$banned_ips ) ) {
            return self::$banned_ips;
        }
        if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Ban_Clock' ) ) {
            self::$banned_ips = Secnin_Waf_Ban_Clock::maybe_migrate();
            return self::$banned_ips;
        }
        // get the option wf_sn_banned_ips
        $wf_sn_banned_ips = get_option( 'wf_sn_banned_ips' );
        self::$banned_ips = ( is_array( $wf_sn_banned_ips ) ? $wf_sn_banned_ips : array() );
        return self::$banned_ips;
    }

    public static function ajax_send_unblock_email() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::ajax_send_unblock_email();
    }

    public static function send_secret_access_unblock_url( $email ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-mail.php';
        return Wf_Sn_Cf_Mail::send_secret_access_unblock_url( $email );
    }

    public static function send_failed_login_warning_email( $username, $ip, $user_agent ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-mail.php';
        return Wf_Sn_Cf_Mail::send_failed_login_warning_email( $username, $ip, $user_agent );
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
        if ( 1 !== self::is_active() ) {
            return;
        }
        self::check_visitor();
        $current_user_ip = self::get_user_ip();
        // Check if country blocking is enabled and restricted to login only
        if ( self::is_active() && isset( self::$options['countryblock_loginonly'] ) && self::$options['countryblock_loginonly'] ) {
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
        if ( 1 !== self::is_active() ) {
            return $user;
        }
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

    /**
     * Update the locally cached banned IP list.
     *
     * @param array<string, int> $new_list IP => expiry timestamp.
     * @return bool False when $new_list is not an array.
     */
    public static function update_banned_ips( $new_list ) {
        // Check if $new_list is an array
        if ( !is_array( $new_list ) ) {
            return false;
        }
        update_option( 'wf_sn_banned_ips', $new_list, false );
        self::$banned_ips = $new_list;
    }

    public static function prune_banned() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-cron.php';
        return Wf_Sn_Cf_Cron::prune_banned();
    }

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
        $user_login = ( isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '' );
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
            $events_table = self::validated_table( 'wf_sn_el' );
            $previous_attempts = 0;
            if ( '' !== $events_table ) {
                $previous_attempts = (int) $wpdb->get_var( $wpdb->prepare(
                    "SELECT COUNT(id) FROM `{$events_table}` WHERE ip = %s AND action = %s AND timestamp >= DATE_SUB(%s, INTERVAL %d MINUTE)",
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- identifier from validated_table().
                    $current_user_ip,
                    'wp_lost_password_failed',
                    current_time( 'mysql' ),
                    (int) self::$options['max_login_attempts_time']
                ) );
            }
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
        $events_table = self::validated_table( 'wf_sn_el' );
        $lost_password_attempts = 0;
        if ( '' !== $events_table ) {
            $lost_password_attempts = (int) $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(id) FROM `{$events_table}` WHERE ip = %s AND action = %s AND timestamp >= DATE_SUB(%s, INTERVAL %d MINUTE)",
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- identifier from validated_table().
                $current_user_ip,
                'wp_lost_password_failed',
                current_time( 'mysql' ),
                (int) self::$options['max_login_attempts_time']
            ) );
        }
        if ( $lost_password_attempts >= intval( self::$options['max_login_attempts'] ) && !isset( $my_banned_ips[$current_user_ip] ) ) {
            $my_banned_ips[$current_user_ip] = Secnin_Waf_Ban_Clock::expiry_from_minutes( self::$options['bruteforce_ban_time'] );
            self::update_banned_ips( $my_banned_ips );
            // Translators: 1: User IP address, 2: Number of lost password attempts, 3: Time in minutes
            $block_details = sprintf(
                __( '%1$s blocked due to multiple lost password attempts. %2$d in %3$d min.', 'security-ninja' ),
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
            ++$lost_password_attempts;
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
        $ip_arr = array();
        // Check if haystack is array and makes sure it is trimmed from apostrophes
        if ( is_array( $haystack ) ) {
            foreach ( $haystack as $key => $item ) {
                $ip_arr[] = trim( $item, "'" );
            }
            if ( in_array( $needle, $ip_arr ) ) {
                return true;
            }
        }
        if ( is_iterable( $haystack ) ) {
            foreach ( $haystack as $key => $item ) {
                if ( $item === $needle ) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Satellite ASN softening metadata for an IP (single resolution per request via static cache).
     *
     * @param string $ip Client IP.
     * @return array{applies: bool, asn: int, as_label: string}
     */
    public static function get_satellite_soften_info( $ip ) {
        $empty = array(
            'applies'  => false,
            'asn'      => 0,
            'as_label' => '',
        );
        return $empty;
    }

    /**
     * Whether satellite/residential ASN softening applies for reputation/geo-style blocks (not manual blacklist / WAF).
     *
     * @param string $ip Client IP.
     * @return bool
     */
    public static function should_soften_satellite_network_for_ip( $ip ) {
        $info = self::get_satellite_soften_info( $ip );
        return !empty( $info['applies'] );
    }

    /**
     * Cloud reputation block reason for an IP (no ASN softening).
     *
     * @param string $ip Client IP.
     * @return string Empty string if not blocked by cloud lists.
     */
    private static function compute_cloud_block_reason( $ip ) {
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        if ( '1' !== (string) (self::$options['usecloud'] ?? '') ) {
            return '';
        }
        // Cloud reputation applies to public routable IPs only.
        if ( Wf_sn_cf_Utils::is_non_public_ip( $ip ) ) {
            return '';
        }
        $ips = self::get_cloud_ips_data();
        if ( !is_array( $ips ) ) {
            return '';
        }
        $cloud_ips = ( isset( $ips['ips'] ) && is_array( $ips['ips'] ) ? $ips['ips'] : array() );
        if ( self::IP_in_array( $ip, $cloud_ips ) ) {
            return 'IP in cloud blacklist.';
        }
        if ( isset( $ips['subnets'] ) && is_array( $ips['subnets'] ) ) {
            $nework_array = explode( '.', $ip, 2 );
            if ( isset( $nework_array[0] ) && array_key_exists( $nework_array[0], $ips['subnets'] ) ) {
                foreach ( $ips['subnets'][$nework_array[0]] as $subnet ) {
                    $subnet = trim( $subnet, "'" );
                    if ( Wf_sn_cf_Utils::ipCIDRMatch( $ip, $subnet ) ) {
                        return 'IP in cloud blacklist range.';
                    }
                }
            }
        }
        return '';
    }

    /**
     * Checks a specific IP is banned or not
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Wednesday, June 9th, 2021.
     * @version v1.0.2  Sunday, June 13th, 2021.
     * @version v1.0.3  Monday, November 8th, 2021.
     * @version v1.0.4  Wednesday, February 9th, 2022.
     * @access  public static
     * @param   string|false $ip Client IP (required).
     * @return  string|false Ban reason string or false if not banned.
     */
    public static function is_banned_ip( $ip = false ) {
        if ( !$ip ) {
            return false;
        }
        if ( is_null( self::$options ) ) {
            self::$options = self::get_options();
        }
        // Checks if IP is set or try to get it - always use $current_user_ip from here
        if ( $ip ) {
            $current_user_ip = $ip;
        } else {
            $current_user_ip = self::get_user_ip();
        }
        $server_ip = self::get_server_ip();
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
        if ( Wf_sn_cf_Utils::is_whitelisted( $current_user_ip, $local_whitelist ) ) {
            return false;
        }
        // Kill-switch: no ban checks when firewall is disabled.
        if ( 1 !== self::is_active() ) {
            return false;
        }
        $blacklist = self::$options['blacklist'];
        if ( is_array( $blacklist ) ) {
            foreach ( $blacklist as $bl ) {
                if ( trim( $bl ) === $ip ) {
                    return 'IP is in local blacklist.';
                }
                if ( Wf_sn_cf_Utils::ipCIDRMatch( $ip, $bl ) ) {
                    return 'IP is in local blacklist mask - ' . $bl;
                }
            }
        }
        $banned_ips = self::get_banned_ips();
        if ( array_key_exists( $current_user_ip, $banned_ips ) ) {
            $expiry = $banned_ips[$current_user_ip];
            if ( $expiry > Secnin_Waf_Ban_Clock::now() ) {
                return 'Local blacklist.';
            }
            $updated = $banned_ips;
            unset($updated[$current_user_ip]);
            self::update_banned_ips( $updated );
            self::$banned_ips = $updated;
        }
        $cloud_block_reason = '';
        $use_compute_cloud = true;
        if ( $use_compute_cloud ) {
            $cloud_block_reason = self::compute_cloud_block_reason( $current_user_ip );
        }
        if ( '' !== $cloud_block_reason ) {
            return $cloud_block_reason;
        }
        // Allow known social/link-preview crawlers through Block IP Network (e.g. Facebook, LinkedIn).
        if ( Wf_sn_cf_Utils::is_social_crawler_ua() ) {
            return false;
        }
        // Checks if included in SecNin Global Block network
        global $wpdb;
        $table_name = self::validated_table( 'wf_sn_cf_bl_ips' );
        $answer = false;
        if ( '' !== $table_name ) {
            $answer = $wpdb->get_var( $wpdb->prepare( "SELECT tid FROM `{$table_name}` WHERE ip = %s", $current_user_ip ) );
        }
        if ( $answer ) {
            return 'SecNin Global Block network.';
        }
        return false;
    }

    public static function register_settings() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::register_settings();
    }

    public static function get_ip_source_modes() {
        return array(
            'auto',
            'remote_addr',
            'cf_connecting_ip',
            'x_forwarded_for',
            'x_real_ip'
        );
    }

    /**
     * Normalize and validate an IP source setting.
     *
     * @param mixed $source Raw option value.
     * @return string
     */
    public static function normalize_ip_source( $source ) {
        $source = ( is_string( $source ) ? sanitize_key( $source ) : 'auto' );
        if ( !in_array( $source, self::get_ip_source_modes(), true ) ) {
            return 'auto';
        }
        return $source;
    }

    /**
     * Sanitize trusted proxy CIDR list for storage.
     *
     * @param mixed $raw Raw value.
     * @return string[]
     */
    public static function sanitize_trusted_proxy_cidrs( $raw ) {
        return Wf_sn_cf_Utils::sanitize_trusted_proxy_cidrs( $raw );
    }

    /**
     * Whether the current user should skip IP ban enforcement (logged-in site admin).
     *
     * @return bool
     */
    public static function should_skip_ban_enforcement() {
        return current_user_can( 'manage_options' );
    }

    /**
     * Whether the current request is a WordPress REST API request.
     *
     * @return bool
     */
    public static function is_rest_request() {
        if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
            return true;
        }
        if ( isset( $_GET['rest_route'] ) ) {
            return true;
        }
        $request_uri = ( isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '' );
        if ( '' !== $request_uri && false !== strpos( $request_uri, '/wp-json/' ) ) {
            return true;
        }
        return function_exists( 'wp_is_json_request' ) && wp_is_json_request();
    }

    /**
     * Resolve visitor IP for a given source mode (no static cache).
     *
     * @param string|null $source One of get_ip_source_modes(); null uses saved option.
     * @return string|false
     */
    public static function resolve_user_ip_for_source( $source = null ) {
        if ( null === $source ) {
            if ( is_null( self::$options ) ) {
                // Read ip_source only — get_options() defaults call get_user_ip() and would recurse.
                $raw = get_option( 'wf_sn_cf', array() );
                $source = ( is_array( $raw ) && isset( $raw['ip_source'] ) ? $raw['ip_source'] : 'auto' );
            } else {
                $source = ( isset( self::$options['ip_source'] ) ? self::$options['ip_source'] : 'auto' );
            }
        }
        $source = self::normalize_ip_source( $source );
        $remote_addr = self::get_server_ip_from_key( 'REMOTE_ADDR' );
        if ( false === $remote_addr ) {
            $remote_addr = '127.0.0.1';
        }
        $user_proxy_cidrs = array();
        if ( is_null( self::$options ) ) {
            $raw_opts = get_option( 'wf_sn_cf', array() );
            if ( is_array( $raw_opts ) && isset( $raw_opts['trusted_proxy_cidrs'] ) ) {
                $user_proxy_cidrs = $raw_opts['trusted_proxy_cidrs'];
            }
        } elseif ( isset( self::$options['trusted_proxy_cidrs'] ) ) {
            $user_proxy_cidrs = self::$options['trusted_proxy_cidrs'];
        }
        $user_proxy_cidrs = Wf_sn_cf_Utils::sanitize_trusted_proxy_cidrs( $user_proxy_cidrs );
        $resolved = $remote_addr;
        switch ( $source ) {
            case 'remote_addr':
                $resolved = $remote_addr;
                break;
            case 'cf_connecting_ip':
                $cf_ip = self::get_server_ip_from_key( 'HTTP_CF_CONNECTING_IP' );
                if ( false !== $cf_ip && Wf_sn_cf_Utils::is_cloudflare_proxy_ip( $remote_addr ) ) {
                    $resolved = $cf_ip;
                } else {
                    $resolved = $remote_addr;
                }
                break;
            case 'x_forwarded_for':
                $xff = self::get_server_ip_from_key( 'HTTP_X_FORWARDED_FOR' );
                if ( false !== $xff && Wf_sn_cf_Utils::peer_may_forward_client_ip( $remote_addr, $user_proxy_cidrs ) ) {
                    $resolved = $xff;
                } else {
                    $resolved = $remote_addr;
                }
                break;
            case 'x_real_ip':
                $xri = self::get_server_ip_from_key( 'HTTP_X_REAL_IP' );
                if ( false !== $xri && Wf_sn_cf_Utils::peer_may_forward_client_ip( $remote_addr, $user_proxy_cidrs ) ) {
                    $resolved = $xri;
                } else {
                    $resolved = $remote_addr;
                }
                break;
            case 'auto':
            default:
                $cf_ip = self::get_server_ip_from_key( 'HTTP_CF_CONNECTING_IP' );
                if ( false !== $cf_ip && Wf_sn_cf_Utils::is_cloudflare_proxy_ip( $remote_addr ) ) {
                    $resolved = $cf_ip;
                } elseif ( Wf_sn_cf_Utils::is_trusted_proxy_ip( $remote_addr, $user_proxy_cidrs ) ) {
                    $xff = self::get_server_ip_from_key( 'HTTP_X_FORWARDED_FOR' );
                    if ( false !== $xff ) {
                        $resolved = $xff;
                    } else {
                        $xri = self::get_server_ip_from_key( 'HTTP_X_REAL_IP' );
                        $resolved = ( false !== $xri ? $xri : $remote_addr );
                    }
                } else {
                    $resolved = $remote_addr;
                }
                break;
        }
        $resolved = apply_filters(
            'wf_sn_client_ip',
            $resolved,
            $source,
            $remote_addr
        );
        if ( !is_string( $resolved ) || !filter_var( $resolved, FILTER_VALIDATE_IP ) ) {
            return false;
        }
        return $resolved;
    }

    /**
     * Preview resolved IP for each source mode (settings UI).
     *
     * @return array<string, string|false>
     */
    public static function get_ip_source_preview() {
        $preview = array();
        foreach ( self::get_ip_source_modes() as $mode ) {
            $preview[$mode] = self::resolve_user_ip_for_source( $mode );
        }
        return $preview;
    }

    /**
     * Read and validate a single $_SERVER IP key.
     *
     * @param string $key Server key (e.g. REMOTE_ADDR, HTTP_CF_CONNECTING_IP).
     * @return string|false
     */
    private static function get_server_ip_from_key( $key ) {
        if ( !isset( $_SERVER[$key] ) || '' === $_SERVER[$key] ) {
            return false;
        }
        $raw = sanitize_text_field( wp_unslash( (string) $_SERVER[$key] ) );
        if ( 'HTTP_X_FORWARDED_FOR' === $key || 'HTTP_CF_CONNECTING_IP' === $key || 'HTTP_X_REAL_IP' === $key ) {
            return Wf_sn_cf_Utils::first_valid_ip_from_header( $raw );
        }
        return ( filter_var( $raw, FILTER_VALIDATE_IP ) ? $raw : false );
    }

    /**
     * Centralized way to get the visitor IP address.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @access  public static
     * @return  string|false
     */
    public static function get_user_ip() {
        if ( self::$cached_ip !== null ) {
            return self::$cached_ip;
        }
        $ip = self::resolve_user_ip_for_source();
        self::$cached_ip = ( false !== $ip ? $ip : false );
        return self::$cached_ip;
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
        echo '<p class="message">' . esc_html( self::$options['login_msg'] ) . '</p>';
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
        $attempted_username = ( isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '' );
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
            $login_error_msg = ( !empty( self::$options['login_error_msg'] ) ? self::$options['login_error_msg'] : __( 'Something went wrong', 'security-ninja' ) );
            return sprintf( '<strong>%s</strong>: %s', esc_html__( 'Error', 'security-ninja' ), wp_kses( $login_error_msg, array(
                'p'  => array(),
                'br' => array(),
            ) ) );
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
        if ( empty( self::$options['protect_login_form'] ) || empty( self::$options['login_msg'] ) ) {
            return $msg;
        }
        $action = ( isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '' );
        if ( !in_array( $action, array('register', 'lostpassword'), true ) ) {
            $custom_msg = '<p class="message">' . esc_html( self::$options['login_msg'] ) . '</p>';
            $msg = $custom_msg . $msg;
        }
        return $msg;
    }

    /**
     * isValidCIDR.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, August 27th, 2024.
     * @access  private static
     * @param   mixed   $cidr
     * @return  boolean
     */
    public static function isValidCIDR( $cidr ) {
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

    public static function sanitize_settings( $values ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::sanitize_settings( $values );
    }

    public static function sn_tabs( $tabs ) {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::sn_tabs( $tabs );
    }

    public static function do_login_page() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::do_login_page();
    }

    public static function save_login_settings() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::save_login_settings();
    }

    public static function overlay_content() {
        echo '<div id="sn-cloud-firewall" style="display: none; text-align:center;">';
        echo '<h2 style="font-weight: bold;">' . esc_html__( 'Important! Please READ!', 'security-ninja' ) . '</h2>';
        echo '<p>' . esc_html__( 'In the unlikely situation that your IP gets banned, you will not be able to login or access the site. In that case you need the secret access link.', 'security-ninja' ) . '</p>';
        echo '<p>' . esc_html__( 'It whitelists your IP and enables access. Please store the link in a safe place or use the form below to get it sent to your email address.', 'security-ninja' ) . '</p>';
        echo '<p><code>' . esc_html( self::get_unblock_url() ) . '</code></p>';
        echo '<div id="sn-firewall-status">' . esc_html__( 'Enabling firewall, please wait', 'security-ninja' ) . '<span class="spinner is-active"></span></div>';
        echo '<p>' . esc_html__( 'Enter your email below to receive the secret access link in case you get locked out', 'security-ninja' ) . '</p>';
        echo '<input style="width: 250px;" type="text" id="sn-ublock-email" name="sn-ublock-email" value="' . esc_attr( (string) get_option( 'admin_email' ) ) . '" placeholder="john@example.com"><br />';
        echo '<p id="sn-unblock-message"></p>';
        ?>
		<input type="button" value="<?php 
        esc_attr_e( 'Send secret access link', 'security-ninja' );
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
     * @return  int 1 when the firewall is active, 0 otherwise.
     */
    public static function is_active() {
        if ( is_null( self::$options ) ) {
            self::get_options();
        }
        return (int) (1 === (int) self::$options['active']);
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
        // Check if IP is already in whitelist (exact match or covered by a CIDR entry).
        if ( Wf_sn_cf_Utils::is_whitelisted( $ip, self::$options['whitelist'] ) ) {
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
     * Cryptographically random unblock token for ?snf= (32 hex chars).
     *
     * Existing stored tokens are never rotated by this helper. Only create/reset paths call it.
     *
     * @return string
     */
    public static function generate_unblock_token() {
        return bin2hex( random_bytes( 16 ) );
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
            $my_options['unblock_url'] = self::generate_unblock_token();
            update_option( WF_SN_CF_OPTIONS_KEY, $my_options, false );
        }
        $outurl = add_query_arg( array(
            'snf' => $my_options['unblock_url'],
        ), get_site_url() );
        return $outurl;
    }

    /**
     * True when an IP is safe to share on the block list.
     *
     * @param string $ip IP address.
     * @return bool
     */
    public static function is_shared_network_ip( $ip ) {
        $ip = (string) $ip;
        if ( !filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return false;
        }
        if ( !filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return true;
        }
        $long = ip2long( $ip );
        if ( false === $long ) {
            return false;
        }
        $unsigned = (int) sprintf( '%u', $long );
        $first = $unsigned >> 24 & 255;
        if ( $first >= 224 ) {
            return false;
        }
        $start = (int) sprintf( '%u', ip2long( '100.64.0.0' ) );
        $end = (int) sprintf( '%u', ip2long( '100.127.255.255' ) );
        if ( $unsigned >= $start && $unsigned <= $end ) {
            return false;
        }
        return true;
    }

    /**
     * Authorization header for a reportip write. Covers the exact body bytes.
     *
     * @param string $secret    Site secret.
     * @param int    $timestamp Unix time.
     * @param string $body      Raw JSON body.
     * @return string
     */
    public static function build_network_write_authorization( $secret, $timestamp, $body ) {
        $timestamp = (string) $timestamp;
        $body_hash = hash( 'sha256', (string) $body );
        $signed = hash( 'sha512', (string) $secret . '|' . $timestamp . '|' . $body_hash );
        return base64_encode( $signed . '|' . $timestamp . '|' . $body_hash );
    }

    /**
     * Decide which queued IPs to drop after a batch response.
     *
     * @param array<string, mixed>    $queue    Full queue.
     * @param array<int, string>      $sent_ips IPs included in this POST.
     * @param int                     $http_code Response status.
     * @param mixed                   $decoded Decoded JSON body.
     * @param int                     $now     Unix time.
     * @return array{queue: array<string, mixed>, backoff_until: int|null, event: array{name: string, message: string}|null, ok: bool}
     */
    public static function interpret_network_report_response(
        $queue,
        $sent_ips,
        $http_code,
        $decoded,
        $now
    ) {
        $queue = ( is_array( $queue ) ? $queue : array() );
        $sent = array();
        foreach ( (array) $sent_ips as $sent_ip ) {
            $sent[(string) $sent_ip] = true;
        }
        $code = (int) $http_code;
        $now = (int) $now;
        $result = array(
            'queue'         => $queue,
            'backoff_until' => null,
            'event'         => null,
            'ok'            => false,
        );
        if ( in_array( $code, array(
            400,
            401,
            403,
            404
        ), true ) ) {
            $result['backoff_until'] = $now + 6 * HOUR_IN_SECONDS;
            $result['event'] = array(
                'name'    => 'ip_network_submit_error',
                'message' => sprintf( 'Block network rejected the batch (HTTP %d). Will retry in 6 hours.', $code ),
            );
            return $result;
        }
        if ( $code < 200 || $code >= 300 ) {
            $result['event'] = array(
                'name'    => 'ip_network_submit_error',
                'message' => sprintf( 'Error submitting IP batch to network (HTTP %d). Will retry.', $code ),
            );
            return $result;
        }
        if ( !is_array( $decoded ) || !isset( $decoded['accepted_ips'] ) || !is_array( $decoded['accepted_ips'] ) ) {
            $result['event'] = array(
                'name'    => 'ip_network_submit_error',
                'message' => 'Block network response did not confirm which IPs were accepted. Will retry.',
            );
            return $result;
        }
        $accepted = array();
        foreach ( $decoded['accepted_ips'] as $ip ) {
            $accepted[(string) $ip] = true;
        }
        $rejected = array();
        if ( isset( $decoded['rejected'] ) && is_array( $decoded['rejected'] ) ) {
            foreach ( $decoded['rejected'] as $row ) {
                if ( is_array( $row ) && isset( $row['ban_ip'] ) ) {
                    $rejected[(string) $row['ban_ip']] = true;
                }
            }
        }
        $accepted_count = 0;
        $accepted_hits = 0;
        foreach ( array_keys( $sent ) as $ip ) {
            if ( !isset( $queue[$ip] ) ) {
                continue;
            }
            $was_accepted = isset( $accepted[$ip] );
            $was_rejected = isset( $rejected[$ip] );
            if ( !$was_accepted && !$was_rejected ) {
                continue;
            }
            if ( $was_accepted && is_array( $queue[$ip] ) ) {
                ++$accepted_count;
                $accepted_hits += ( isset( $queue[$ip]['count'] ) ? absint( $queue[$ip]['count'] ) : 1 );
            }
            unset($queue[$ip]);
        }
        $result['queue'] = $queue;
        $result['backoff_until'] = 0;
        $result['ok'] = true;
        if ( $accepted_count > 0 ) {
            $result['event'] = array(
                'name'    => 'ip_network_submit_success',
                'message' => sprintf( 'Submitted %d IPs to the block network (%d local hits).', $accepted_count, $accepted_hits ),
            );
        }
        return $result;
    }

    public static function do_page() {
        require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-admin.php';
        return Wf_Sn_Cf_Admin::do_page();
    }

}

add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\wf_sn_cf', 'init') );
register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\wf_sn_cf', 'deactivate') );