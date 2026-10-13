<?php
/**
 * Shared login-related request path matching for Cloud Firewall / WAF.
 *
 * Used by country "login only" blocking and early WAF. Must stay loadable
 * without WordPress bootstrapped (Early Firewall drop-in).
 *
 * @package Security_Ninja
 */

if ( ! function_exists( 'secnin_waf_request_path' ) ) {
	/**
	 * Return the URL path only (no query string).
	 *
	 * @param string $request_uri Full REQUEST_URI.
	 * @return string
	 */
	function secnin_waf_request_path( $request_uri ) {
		$request_uri = (string) $request_uri;
		if ( '' === $request_uri ) {
			return '';
		}

		$path = parse_url( $request_uri, PHP_URL_PATH );
		if ( ! is_string( $path ) || '' === $path ) {
			$qpos = strpos( $request_uri, '?' );
			$path = ( false === $qpos ) ? $request_uri : substr( $request_uri, 0, $qpos );
		}

		return rawurldecode( $path );
	}
}

if ( ! function_exists( 'secnin_waf_is_login_related_request' ) ) {
	/**
	 * Whether a request URI targets login / wp-admin dashboard access.
	 *
	 * Front-end plugins (e.g. LatePoint) call admin-ajax.php / admin-post.php with
	 * query strings; those must not count as dashboard access for login-only
	 * country blocking. Query-string values such as redirect_to=/wp-admin/ must
	 * also be ignored (ticket #9523).
	 *
	 * @param string   $request_uri Full REQUEST_URI.
	 * @param string[] $extra_paths Optional extra path needles (e.g. rename-login slug).
	 * @return bool
	 */
	function secnin_waf_is_login_related_request( $request_uri, $extra_paths = array() ) {
		$path = secnin_waf_request_path( $request_uri );
		if ( '' === $path ) {
			return false;
		}

		$path_lower = strtolower( $path );

		// Public WP endpoints under wp-admin used by front-end forms/AJAX.
		if ( preg_match( '#/wp-admin/(?:admin-ajax|admin-post)\.php$#', $path_lower ) ) {
			return false;
		}

		$needles = array(
			'/wp-login.php',
			'/wp-admin',
			'/login',
			'/admin',
			'/my-account',
			'/wp-json/surecart/v1/login',
			'/surecart/v1/login',
		);

		if ( is_array( $extra_paths ) ) {
			foreach ( $extra_paths as $extra ) {
				$extra = trim( (string) $extra );
				if ( '' === $extra ) {
					continue;
				}
				$needles[] = '/' . trim( $extra, '/' );
			}
		}

		foreach ( $needles as $needle ) {
			$needle = strtolower( (string) $needle );
			if ( '' === $needle || '/' === $needle ) {
				continue;
			}

			$escaped = preg_quote( $needle, '#' );
			if ( false !== strpos( $needle, '.php' ) ) {
				if ( preg_match( '#' . $escaped . '$#', $path_lower ) ) {
					return true;
				}
				continue;
			}

			// Boundary match: /admin must not match /administrator.
			if ( preg_match( '#' . $escaped . '(?:/|$)#', $path_lower ) ) {
				return true;
			}
		}

		// Pretty-permalinks off: ?rest_route=/surecart/v1/login
		$qpos = strpos( (string) $request_uri, '?' );
		if ( false !== $qpos ) {
			parse_str( (string) substr( (string) $request_uri, $qpos + 1 ), $qparams );
			if ( isset( $qparams['rest_route'] ) && is_string( $qparams['rest_route'] ) ) {
				$rest = strtolower( $qparams['rest_route'] );
				if ( '' !== $rest && '/' !== $rest[0] ) {
					$rest = '/' . $rest;
				}
				if ( false !== strpos( $rest, '/surecart/v1/login' ) ) {
					return true;
				}
			}
		}

		return false;
	}
}
