<?php
/**
 * Detect WooCommerce payment/checkout request surfaces for 8G (no WordPress APIs).
 *
 * Used by Early WAF and WordPress Cloud Firewall. Skip is route/name based, not token values.
 *
 * @package Security_Ninja
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Woo_Payment_Surface
 */
class Secnin_Waf_Woo_Payment_Surface {

	/**
	 * Query-string 8G rule keys skipped on a payment surface.
	 *
	 * Whitelist of skips: new 8G rules stay strict by default.
	 *
	 * @var array<string, bool>
	 */
	private static $skip_query_rules = array(
		'long_alnum'           => true,
		'special_chars'        => true,
		'path_traversal'       => true,
		'code_exec_injection'  => true,
		'php_object_injection' => true,
		'various_injections'   => true,
		'url_obfuscate'        => true,
		'local_ip'             => true,
		'file_tools'           => true,
		'start_hyphen'         => true,
	);

	/**
	 * Build a detection context from a $_SERVER-like bag.
	 *
	 * @param array $server             Server vars.
	 * @param bool  $woocommerce_active Whether WooCommerce is active.
	 * @return array<string, mixed>
	 */
	public static function context_from_server( array $server, $woocommerce_active ) {
		$uri = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '';
		$qs  = isset( $server['QUERY_STRING'] ) ? (string) $server['QUERY_STRING'] : '';
		if ( '' === $qs ) {
			$qpos = strpos( $uri, '?' );
			if ( false !== $qpos ) {
				$qs = (string) substr( $uri, $qpos + 1 );
			}
		}

		$params = array();
		if ( '' !== $qs ) {
			parse_str( $qs, $params );
		}

		$method = isset( $server['REQUEST_METHOD'] ) ? strtoupper( (string) $server['REQUEST_METHOD'] ) : 'GET';
		if ( '' === $method ) {
			$method = 'GET';
		}

		return array(
			'woocommerce_active' => (bool) $woocommerce_active,
			'request_uri'        => $uri,
			'query_string'       => $qs,
			'request_method'     => $method,
			'query_params'       => is_array( $params ) ? $params : array(),
		);
	}

	/**
	 * Request path with the query string removed.
	 *
	 * @param string $request_uri Full REQUEST_URI.
	 * @return string
	 */
	public static function request_path( $request_uri ) {
		$path = (string) $request_uri;
		$qpos = strpos( $path, '?' );
		if ( false !== $qpos ) {
			$path = substr( $path, 0, $qpos );
		}
		return $path;
	}

	/**
	 * Whether this request is a Woo payment/checkout surface.
	 *
	 * @param array $context Context from context_from_server().
	 * @return bool
	 */
	public static function is_payment_request( array $context ) {
		$is = ! empty( $context['woocommerce_active'] ) && self::detect( $context );
		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filter whether the current request is a WooCommerce payment surface.
			 *
			 * @param bool  $is      Detected as payment surface.
			 * @param array $context Detection context.
			 */
			return (bool) apply_filters( 'secnin_cf_is_woo_payment_request', $is, $context );
		}
		return $is;
	}

	/**
	 * Match payment routes and parameter names. Ignores woocommerce_active.
	 *
	 * @param array $context Context from context_from_server().
	 * @return bool
	 */
	public static function detect( array $context ) {
		$path   = self::request_path( isset( $context['request_uri'] ) ? (string) $context['request_uri'] : '' );
		$params = isset( $context['query_params'] ) && is_array( $context['query_params'] ) ? $context['query_params'] : array();
		$method = isset( $context['request_method'] ) ? strtoupper( (string) $context['request_method'] ) : 'GET';
		$rest   = self::normalized_rest_route( $params );

		if ( self::has_valid_wc_api_param( $params ) ) {
			return true;
		}

		if ( self::path_has_wc_api_segment( $path ) ) {
			return true;
		}

		if ( self::path_is_order_received_or_pay( $path ) ) {
			return true;
		}

		if ( self::has_param( $params, 'cancel_order' ) && ( self::has_param( $params, 'order' ) || self::has_param( $params, 'order_id' ) ) ) {
			return true;
		}

		if ( self::has_wc_order_key( $params ) && self::path_is_order_received_or_pay( $path ) ) {
			return true;
		}

		if ( self::is_store_api_path( $path, $rest ) ) {
			return true;
		}

		if ( self::is_mutating_wc_rest( $method, $path, $rest ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Whether a query-string rule key should be skipped on a payment surface.
	 *
	 * @param string $rule_key Rule key from rules-8g.php.
	 * @return bool
	 */
	public static function should_skip_query_rule( $rule_key ) {
		return isset( self::$skip_query_rules[ (string) $rule_key ] );
	}

	/**
	 * User-agent pattern to use on a payment surface.
	 *
	 * Drops curl / libwww-perl / pycurl from ua_scraping_tools. Keeps scan.
	 *
	 * @param string $rule_key Rule key.
	 * @param string $pattern  Original pattern.
	 * @return string
	 */
	public static function ua_pattern_for_surface( $rule_key, $pattern ) {
		if ( 'ua_scraping_tools' === $rule_key ) {
			return '(scan)';
		}
		return (string) $pattern;
	}

	/**
	 * Whether an 8G match should skip GBN reporting.
	 *
	 * Query and UA false positives on payment surfaces must not hit the network.
	 * Path-shell matches may still be reported.
	 *
	 * @param string $ban_type Ban type (request_uri, query_string, http_user_agent, referrer).
	 * @param array  $context  Payment context.
	 * @return bool
	 */
	public static function should_skip_gbn_report( $ban_type, array $context ) {
		if ( 'query_string' !== $ban_type && 'http_user_agent' !== $ban_type ) {
			return false;
		}
		return self::is_payment_request( $context );
	}

	/**
	 * @param array $params Query params.
	 * @return bool
	 */
	private static function has_valid_wc_api_param( array $params ) {
		if ( ! isset( $params['wc-api'] ) || ! is_string( $params['wc-api'] ) ) {
			return false;
		}
		return (bool) preg_match( '/^[A-Za-z0-9_-]{3,80}$/', $params['wc-api'] );
	}

	/**
	 * @param string $path Request path.
	 * @return bool
	 */
	private static function path_has_wc_api_segment( $path ) {
		if ( false !== stripos( $path, '/wc-api/' ) ) {
			return true;
		}
		return (bool) preg_match( '#/wc-api$#i', $path );
	}

	/**
	 * Path-segment match for Woo thank-you / pay-for-order. Avoids /order-received-tips/.
	 *
	 * @param string $path Request path.
	 * @return bool
	 */
	private static function path_is_order_received_or_pay( $path ) {
		return (bool) preg_match( '#(?:^|/)(?:order-received|order-pay)(?:/|$)#i', $path );
	}

	/**
	 * @param array $params Query params.
	 * @return bool
	 */
	private static function has_wc_order_key( array $params ) {
		if ( ! isset( $params['key'] ) || ! is_string( $params['key'] ) ) {
			return false;
		}
		return ( 0 === strpos( $params['key'], 'wc_order_' ) );
	}

	/**
	 * @param string $path Path.
	 * @param string $rest Normalized rest_route.
	 * @return bool
	 */
	private static function is_store_api_path( $path, $rest ) {
		$needles = array(
			'/wp-json/wc/store/',
			'/wp-json/wc-store/',
			'/wc/store/',
			'/wc-store/',
		);
		foreach ( $needles as $needle ) {
			if ( false !== stripos( $path, $needle ) || false !== stripos( $rest, $needle ) ) {
				return true;
			}
		}
		// rest_route is often "/wc/store/v1/checkout" without /wp-json.
		if ( 0 === stripos( $rest, '/wc/store/' ) || 0 === stripos( $rest, '/wc-store/' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Mutating Woo REST (gateways, webhooks). GET catalog stays fully scanned.
	 *
	 * @param string $method Method.
	 * @param string $path   Path.
	 * @param string $rest   Normalized rest_route.
	 * @return bool
	 */
	private static function is_mutating_wc_rest( $method, $path, $rest ) {
		if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			return false;
		}
		if ( false !== stripos( $path, '/wp-json/wc/' ) || false !== stripos( $path, '/wp-json/wc-' ) ) {
			return true;
		}
		if ( 0 === stripos( $rest, '/wc/' ) || 0 === stripos( $rest, '/wc-' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @param array  $params Query params.
	 * @param string $key    Param name.
	 * @return bool
	 */
	private static function has_param( array $params, $key ) {
		return array_key_exists( $key, $params );
	}

	/**
	 * @param array $params Query params.
	 * @return string
	 */
	private static function normalized_rest_route( array $params ) {
		if ( ! isset( $params['rest_route'] ) || ! is_string( $params['rest_route'] ) ) {
			return '';
		}
		$rest = $params['rest_route'];
		if ( '' !== $rest && '/' !== $rest[0] ) {
			$rest = '/' . $rest;
		}
		return $rest;
	}
}
