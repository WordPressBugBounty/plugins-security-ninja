<?php
/**
 * Detect SureCart payment/checkout request surfaces for 8G (no WordPress APIs).
 *
 * Used by Early WAF and WordPress Cloud Firewall. Skip is route/name based, not token values.
 *
 * @package Security_Ninja
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Surecart_Payment_Surface
 */
class Secnin_Waf_Surecart_Payment_Surface {

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
	 * @param array $server           Server vars.
	 * @param bool  $surecart_active Whether SureCart is active.
	 * @return array<string, mixed>
	 */
	public static function context_from_server( array $server, $surecart_active ) {
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
			'surecart_active' => (bool) $surecart_active,
			'request_uri'     => $uri,
			'query_string'    => $qs,
			'request_method'  => $method,
			'query_params'    => is_array( $params ) ? $params : array(),
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
	 * Whether this request is a SureCart payment/checkout surface.
	 *
	 * @param array $context Context from context_from_server().
	 * @return bool
	 */
	public static function is_payment_request( array $context ) {
		$is = ! empty( $context['surecart_active'] ) && self::detect( $context );
		if ( function_exists( 'apply_filters' ) ) {
			/**
			 * Filter whether the current request is a SureCart payment surface.
			 *
			 * @param bool  $is      Detected as payment surface.
			 * @param array $context Detection context.
			 */
			return (bool) apply_filters( 'secnin_cf_is_surecart_payment_request', $is, $context );
		}
		return $is;
	}

	/**
	 * Whether this is a signed SureCart webhook POST (ban skip candidate).
	 *
	 * @param array $context Context from context_from_server().
	 * @return bool
	 */
	public static function is_webhook_request( array $context ) {
		if ( empty( $context['surecart_active'] ) ) {
			return false;
		}
		$method = isset( $context['request_method'] ) ? strtoupper( (string) $context['request_method'] ) : 'GET';
		if ( 'POST' !== $method ) {
			return false;
		}
		$path = self::request_path( isset( $context['request_uri'] ) ? (string) $context['request_uri'] : '' );
		return (bool) preg_match( '#(?:^|/)surecart/webhooks(?:/|$)#i', $path );
	}

	/**
	 * Match payment routes. Ignores surecart_active.
	 *
	 * @param array $context Context from context_from_server().
	 * @return bool
	 */
	public static function detect( array $context ) {
		$path   = self::request_path( isset( $context['request_uri'] ) ? (string) $context['request_uri'] : '' );
		$params = isset( $context['query_params'] ) && is_array( $context['query_params'] ) ? $context['query_params'] : array();
		$method = isset( $context['request_method'] ) ? strtoupper( (string) $context['request_method'] ) : 'GET';
		$rest   = self::normalized_rest_route( $params );

		if ( 'POST' === $method && preg_match( '#(?:^|/)surecart/webhooks(?:/|$)#i', $path ) ) {
			return true;
		}

		if ( self::is_surecart_rest_surface( $path, $rest ) ) {
			return true;
		}

		if ( self::path_is_storefront_prefix( $path ) ) {
			return true;
		}

		if ( self::has_line_items_price( $params ) ) {
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
	 * Checkout / cart / payment intent REST paths.
	 *
	 * @param string $path Path.
	 * @param string $rest Normalized rest_route.
	 * @return bool
	 */
	private static function is_surecart_rest_surface( $path, $rest ) {
		$needles = array(
			'/wp-json/surecart/v1/checkouts',
			'/wp-json/surecart/v1/line_items',
			'/wp-json/surecart/v1/payment_intents',
			'/surecart/v1/checkouts',
			'/surecart/v1/line_items',
			'/surecart/v1/payment_intents',
		);
		foreach ( $needles as $needle ) {
			if ( false !== stripos( $path, $needle ) || false !== stripos( $rest, $needle ) ) {
				return true;
			}
		}
		if ( 0 === stripos( $rest, '/surecart/v1/checkouts' )
			|| 0 === stripos( $rest, '/surecart/v1/line_items' )
			|| 0 === stripos( $rest, '/surecart/v1/payment_intents' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Default SureCart storefront permalink bases.
	 *
	 * Includes checkout / checkout-N for Woo+SureCart slug collisions (checkout-2).
	 * Does not match checkout-tips or similar.
	 *
	 * @param string $path Request path.
	 * @return bool
	 */
	private static function path_is_storefront_prefix( $path ) {
		return (bool) preg_match( '#(?:^|/)(?:buy|products|offer|checkout(?:-\d+)?)(?:/|$)#i', $path );
	}

	/**
	 * SureCart Buy Now query: line_items[n][price]=id on any page slug.
	 *
	 * @param array $params Query params.
	 * @return bool
	 */
	private static function has_line_items_price( array $params ) {
		if ( ! isset( $params['line_items'] ) || ! is_array( $params['line_items'] ) ) {
			return false;
		}
		foreach ( $params['line_items'] as $item ) {
			if ( ! is_array( $item ) || ! isset( $item['price'] ) ) {
				continue;
			}
			if ( is_string( $item['price'] ) && '' !== $item['price'] ) {
				return true;
			}
		}
		return false;
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
