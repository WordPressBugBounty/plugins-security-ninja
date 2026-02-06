<?php

/**
 * Geolocation class
 *
 * Handles geolocation and updating the geolocation database.
 *
 * This product includes IP2Location LITE data available from https://lite.ip2location.com.
 *
 * This is forked from WooCommerce 3.4.0 and modified to work with this plugin and updated to work with IP2Location. It used to work with GeoLite2 data from MaxMind, but due to new data regulations they ask for users to register account and get API key.
 */
namespace WPSecurityNinja\Plugin;

use Error;
defined( 'ABSPATH' ) || exit;
/**
 * SN_Geolocation Class.
 */
class SN_Geolocation {
    const IP2LOCATION_DB = 'https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.IPV6.BIN.ZIP';

    /**
     * API endpoints for looking up user IP address.
     *
     * @var array
     */
    private static $ip_lookup_apis = array(
        'ipify'             => 'https://api.ipify.org/',
        'ipecho'            => 'https://ipecho.net/plain',
        'ident'             => 'https://ident.me',
        'whatismyipaddress' => 'https://bot.whatismyipaddress.com',
    );

    /**
     * API endpoints for geolocating an IP address
     *
     * @var array
     */
    private static $geoip_apis = array(
        'ipinfo.io'  => 'https://ipinfo.io/%s/json',
        'ip-api.com' => 'http://ip-api.com/json/%s',
    );

    /**
     * Check if server supports MaxMind GeoLite2 Reader.
     *
     * @since 3.4.0
     * @return bool
     */
    private static function supports_ip2location() {
        return version_compare( PHP_VERSION, '5.4.0', '>=' );
    }

    /**
     * Check if geolocation is enabled.
     *
     * @since 3.4.0
     * @param string $current_settings Current geolocation settings.
     * @return bool
     */
    private static function is_geolocation_enabled( $current_settings ) {
        return true;
        // @todo - check if firewall is enabled
        //return in_array( $current_settings, array( 'geolocation', 'geolocation_ajax' ), true );
    }

    /**
     * Prevent geolocation via MaxMind when using legacy versions of php.
     *
     * @since 3.4.0
     * @param string $default_customer_address current value.
     * @return string
     */
    public static function disable_geolocation_on_legacy_php( $default_customer_address ) {
        if ( self::is_geolocation_enabled( $default_customer_address ) ) {
            $default_customer_address = 'base';
        }
        return $default_customer_address;
    }

    /**
     * Hook in geolocation functionality.
     */
    public static function init() {
        if ( self::supports_ip2location() ) {
            add_action( 'woocommerce_geoip_updater', array(__NAMESPACE__ . '\\SN_Geolocation', 'update_database') );
        }
    }

    /**
     * Get current user IP Address.
     *
     * @return string
     */
    public static function get_ip_address() {
        if ( isset( $_SERVER["HTTP_CF_CONNECTING_IP"] ) ) {
            return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( isset( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            // WPCS: input var ok, CSRF ok.
            return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
            // WPCS: input var ok, CSRF ok.
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            // WPCS: input var ok, CSRF ok.
            // Proxy servers can send through this header like this: X-Forwarded-For: client1, proxy1, proxy2
            // Make sure we always only send through the first IP in the list which should always be the client IP.
            return (string) rest_is_ip_address( trim( current( preg_split( '/,/', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) ) ) ) );
            // WPCS: input var ok, CSRF ok.
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            // @codingStandardsIgnoreLine
            return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
            // @codingStandardsIgnoreLine
        }
        return '';
    }

    /**
     * Get user IP Address using an external service.
     * This can be used as a fallback for users on localhost where
     * get_ip_address() will be a local IP and non-geolocatable.
     *
     * @return string
     */
    public static function get_external_ip_address() {
        $external_ip_address = '0.0.0.0';
        if ( '' !== self::get_ip_address() ) {
            $transient_name = 'external_ip_address_' . self::get_ip_address();
            $external_ip_address = get_transient( $transient_name );
        }
        if ( false === $external_ip_address ) {
            $external_ip_address = '0.0.0.0';
            $ip_lookup_services = self::$ip_lookup_apis;
            // fjernede filter
            $ip_lookup_services_keys = array_keys( $ip_lookup_services );
            shuffle( $ip_lookup_services_keys );
            foreach ( $ip_lookup_services_keys as $service_name ) {
                $service_endpoint = $ip_lookup_services[$service_name];
                $response = wp_safe_remote_get( $service_endpoint, array(
                    'timeout' => 2,
                ) );
                if ( !is_wp_error( $response ) && rest_is_ip_address( $response['body'] ) ) {
                    $external_ip_address = $response['body'];
                    // fjernede apply_filters( 'woocommerce_geolocation_ip_lookup_api_response', wc_clean( $response['body'] ), $service_name );
                    break;
                }
            }
            set_transient( $transient_name, $external_ip_address, WEEK_IN_SECONDS );
        }
        return $external_ip_address;
    }

    /**
     * Geolocate an IP address.
     *
     * @param  string $ip_address   IP Address.
     * @param  bool   $fallback     If true, fallbacks to alternative IP detection (can be slower).
     * @param  bool   $api_fallback If true, uses geolocation APIs if the database file doesn't exist (can be slower).
     * @return array
     */
    public static function geolocate_ip( $ip_address = '', $fallback = false, $api_fallback = true ) {
        // If GEOIP is enabled in CloudFlare, we can use that (Settings -> CloudFlare Settings -> Settings Overview).
        if ( !empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
            // WPCS: input var ok, CSRF ok.
            $country_code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) );
            // WPCS: input var ok, CSRF ok.
        } elseif ( !empty( $_SERVER['GEOIP_COUNTRY_CODE'] ) ) {
            // WPCS: input var ok, CSRF ok.
            // WP.com VIP has a variable available.
            $country_code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['GEOIP_COUNTRY_CODE'] ) ) );
            // WPCS: input var ok, CSRF ok.
        } elseif ( !empty( $_SERVER['HTTP_X_COUNTRY_CODE'] ) ) {
            // WPCS: input var ok, CSRF ok.
            // VIP Go has a variable available also.
            $country_code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_COUNTRY_CODE'] ) ) );
            // WPCS: input var ok, CSRF ok.
        }
        if ( isset( $_SERVER["HTTP_CF_CONNECTING_IP"] ) ) {
            $ip_address = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        }
        if ( !$ip_address ) {
            $ip_address = self::get_ip_address();
        }
        // @todo - allow to disable country look up - can improve space.
        $upload_dir = wp_upload_dir();
        $database = trailingslashit( $upload_dir['basedir'] ) . 'security-ninja/ip2location/IP2LOCATION.DAT';
        if ( file_exists( $database ) ) {
            $country_code = self::geolocate_via_db( $ip_address, $database );
        } elseif ( $api_fallback ) {
            $country_code = self::geolocate_via_api( $ip_address );
        } else {
            $country_code = '';
        }
        if ( !$country_code && $fallback ) {
            // May be a local environment - find external IP.
            return self::geolocate_ip( self::get_external_ip_address(), false, $api_fallback );
        }
        return array(
            'ip'      => $ip_address,
            'country' => $country_code,
        );
    }

    /**
     * Update geoip database.
     *
     * Extract files with PharData. Tool built into PHP since 5.3.
     *
     * Ripped and tweaked with love from WooCommerce
     */
    public static function update_database() {
    }

    /**
     * Use MAXMIND GeoLite database to geolocation the user.
     *
     * @param  string $ip_address IP address.
     * @param  string $database   Database path. - Currently not used
     * @return string
     */
    private static function geolocate_via_db( $ip_address, $database ) {
        $upload_dir = wp_upload_dir();
        $filepath = trailingslashit( $upload_dir['basedir'] ) . 'security-ninja/ip2location/IP2LOCATION.DAT';
        // Check if file exists and is readable
        if ( !file_exists( $filepath ) || !is_readable( $filepath ) ) {
            return '';
        }
        // Check file size - if it's too small, it's likely corrupted
        if ( filesize( $filepath ) < 1024 ) {
            return '';
        }
        try {
            $db = new IP2Location\Database($filepath, 100001);
            $records = $db->lookup( $ip_address, 1001 );
            if ( isset( $records['countryCode'] ) ) {
                return $records['countryCode'];
            }
        } catch ( Exception $e ) {
            // Log the error and return empty string
            error_log( 'Security Ninja IP2Location error: ' . $e->getMessage() );
            return '';
        }
        return '';
    }

    /**
     * Use APIs to Geolocate the user.
     *
     * Geolocation APIs can be added through the use of the woocommerce_geolocation_geoip_apis filter.
     * Provide a name=>value pair for service-slug=>endpoint.
     *
     * If APIs are defined, one will be chosen at random to fulfil the request. After completing, the result
     * will be cached in a transient.
     *
     * @param  string $ip_address IP address.
     * @return string
     */
    private static function geolocate_via_api( $ip_address ) {
        $country_code = get_transient( 'geoip_' . $ip_address );
        if ( false === $country_code ) {
            $geoip_services = apply_filters( 'woocommerce_geolocation_geoip_apis', self::$geoip_apis );
            if ( empty( $geoip_services ) ) {
                return '';
            }
            $geoip_services_keys = array_keys( $geoip_services );
            shuffle( $geoip_services_keys );
            foreach ( $geoip_services_keys as $service_name ) {
                $service_endpoint = $geoip_services[$service_name];
                $response = wp_safe_remote_get( sprintf( $service_endpoint, $ip_address ), array(
                    'timeout' => 2,
                ) );
                if ( !is_wp_error( $response ) && $response['body'] ) {
                    switch ( $service_name ) {
                        case 'ipinfo.io':
                            $data = json_decode( $response['body'] );
                            $country_code = ( isset( $data->country ) ? $data->country : '' );
                            break;
                        case 'ip-api.com':
                            $data = json_decode( $response['body'] );
                            $country_code = ( isset( $data->countryCode ) ? $data->countryCode : '' );
                            // @codingStandardsIgnoreLine
                            break;
                        default:
                            $country_code = $response['body'];
                            // fjernede apply_filters( 'woocommerce_geolocation_geoip_response_' . $service_name, '', $response['body'] );
                            break;
                    }
                    $country_code = sanitize_text_field( strtoupper( $country_code ) );
                    if ( $country_code ) {
                        break;
                    }
                }
            }
            set_transient( 'geoip_' . $ip_address, $country_code, WEEK_IN_SECONDS );
        }
        return $country_code;
    }

}

SN_Geolocation::init();