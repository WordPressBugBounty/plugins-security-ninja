<?php
/**
 * Shared Early/WordPress firewall decision engine (no WordPress APIs).
 *
 * @package Security_Ninja
 */

if ( ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

if ( ! class_exists( 'Secnin_Waf_Decision', false ) ) {
	require_once dirname( __FILE__ ) . '/class-secnin-waf-decision.php';
}

if ( ! function_exists( 'secnin_waf_is_login_related_request' ) ) {
	require_once dirname( __FILE__ ) . '/secnin-waf-login-related.php';
}

/**
 * Class Secnin_Waf_Decision_Engine
 */
class Secnin_Waf_Decision_Engine {

	/**
	 * Configuration / lists payload.
	 *
	 * @var array
	 */
	private $config;

	/**
	 * Server vars snapshot.
	 *
	 * @var array
	 */
	private $server;

	/**
	 * Request bag ($_REQUEST-like).
	 *
	 * @var array
	 */
	private $request;

	/**
	 * Cookie bag.
	 *
	 * @var array
	 */
	private $cookies;

	/**
	 * Extra context flags from WordPress adapter.
	 *
	 * @var array
	 */
	private $flags;

	/**
	 * Constructor.
	 *
	 * @param array $config  Config payload.
	 * @param array $server  $_SERVER.
	 * @param array $request $_REQUEST.
	 * @param array $cookies $_COOKIE.
	 * @param array $flags   Extra flags.
	 */
	public function __construct( array $config, array $server = array(), array $request = array(), array $cookies = array(), array $flags = array() ) {
		$this->config  = $config;
		$this->server  = $server;
		$this->request = $request;
		$this->cookies = $cookies;
		$this->flags   = $flags;
	}

	/**
	 * Evaluate request.
	 *
	 * @return Secnin_Waf_Decision
	 */
	public function decide() {
		$decision = Secnin_Waf_Decision::make( Secnin_Waf_Decision::ALLOW );

		if ( empty( $this->config['active'] ) ) {
			return $decision;
		}

		$ip = $this->resolve_ip();
		$decision->mark( 'ip_resolution' );
		$decision->ip = $ip ? $ip : '';
		if ( ! $ip ) {
			return $decision;
		}

		if ( $this->matches_unlock( $ip ) ) {
			$decision->mark( 'unlock_url' );
			$decision->mark( 'whitelist' );
			return $decision;
		}

		if ( $this->has_valid_admin_cookie() || ! empty( $this->flags['wp_admin_logged_in'] ) ) {
			$decision->mark( 'admin_cookie' );
			$decision->mark( 'whitelist' );
			return $decision;
		}

		if ( $this->is_whitelisted( $ip ) || ! empty( $this->flags['service_whitelisted'] ) || ! empty( $this->flags['crawler_validated'] ) || ! empty( $this->flags['temp_login'] ) ) {
			$decision->mark( 'whitelist' );
			return $decision;
		}

		if ( ! empty( $this->flags['wp_importing'] ) ) {
			$decision->action = Secnin_Waf_Decision::DEFER_TO_WORDPRESS;
			$decision->reason = 'wp_importing';
			return $decision;
		}

		$ban = $this->ban_reason( $ip );
		$decision->mark( 'local_bans' );
		$decision->mark( 'cloud_ips' );
		if ( false !== $ban ) {
			if ( ! empty( $this->flags['needs_country'] ) || ! empty( $this->flags['needs_satellite'] ) ) {
				// Caller asked engine to defer geo/ASN-dependent paths.
			}
			if ( $this->should_enforce_ban() ) {
				$blocked = Secnin_Waf_Decision::make( Secnin_Waf_Decision::BLOCK, $ip, 'ban', (string) $ban );
				$blocked->capabilities = $decision->capabilities;
				$blocked->mark( 'blocked' );
				return $blocked;
			}
		}

		if ( ! empty( $this->flags['defer_gbn'] ) ) {
			// GBN table requires WordPress DB in beta unless snapshot provided.
			if ( empty( $this->config['gbn_ips'] ) ) {
				$decision->action = Secnin_Waf_Decision::DEFER_TO_WORDPRESS;
				$decision->reason = 'gbn_unavailable';
				$decision->mark( 'gbn_deferred' );
			}
		} elseif ( ! $this->is_non_public_ip( $ip ) && ! empty( $this->config['gbn_ips'] ) && is_array( $this->config['gbn_ips'] ) && in_array( $ip, $this->config['gbn_ips'], true ) ) {
			if ( empty( $this->flags['social_crawler'] ) && $this->should_enforce_ban() ) {
				$blocked = Secnin_Waf_Decision::make( Secnin_Waf_Decision::BLOCK, $ip, 'gbn', 'Global Block Network.' );
				$blocked->capabilities = $decision->capabilities;
				$blocked->mark( 'gbn' );
				$blocked->mark( 'blocked' );
				return $blocked;
			}
		}

		if ( $this->is_temporary_login_request() ) {
			$decision->mark( 'temporary_login' );
			$decision->mark( 'query_filter' );
			return $decision;
		}

		if ( ! empty( $this->config['filterqueries'] ) ) {
			if ( ! empty( $this->config['skip_query_filter'] ) ) {
				return $decision;
			}
			if ( $this->is_wp_context_skip() || $this->is_allowed_2fa_ajax() || ! empty( $this->flags['is_admin'] ) || ! empty( $this->flags['is_ajax'] ) ) {
				$decision->mark( 'query_filter' );
				return $decision;
			}
			if ( ! empty( $this->flags['needs_query_filters'] ) ) {
				$decision->action = Secnin_Waf_Decision::DEFER_TO_WORDPRESS;
				$decision->reason = 'query_filters';
				$decision->mark( 'query_filter_deferred' );
				return $decision;
			}
			$bad = $this->check_bad_queries();
			$decision->mark( 'query_filter' );
			if ( false !== $bad ) {
				$rule = isset( $bad['matched_rule'] ) ? (string) $bad['matched_rule'] : 'bad_query';
				$blocked = Secnin_Waf_Decision::make( Secnin_Waf_Decision::BLOCK, $ip, 'query_filter', 'Suspicious query: ' . $rule );
				$blocked->capabilities = $decision->capabilities;
				$blocked->matched_rule = $rule;
				$blocked->ban_type     = isset( $bad['message'] ) ? (string) $bad['message'] : '';
				$blocked->mark( 'blocked' );
				return $blocked;
			}
		}

		return $decision;
	}

	/**
	 * Resolve IP.
	 *
	 * @return string|false
	 */
	public function resolve_ip() {
		$source      = isset( $this->config['ip_source'] ) ? (string) $this->config['ip_source'] : 'auto';
		$remote_addr = $this->server_ip( 'REMOTE_ADDR' );
		if ( false === $remote_addr ) {
			$remote_addr = '127.0.0.1';
		}
		$trusted = isset( $this->config['trusted_proxy_cidrs'] ) && is_array( $this->config['trusted_proxy_cidrs'] )
			? $this->config['trusted_proxy_cidrs']
			: array();
		$cf_cidrs = isset( $this->config['cloudflare_cidrs'] ) && is_array( $this->config['cloudflare_cidrs'] )
			? $this->config['cloudflare_cidrs']
			: array();

		switch ( $source ) {
			case 'remote_addr':
				$resolved = $remote_addr;
				break;
			case 'cf_connecting_ip':
				$cf = $this->server_ip( 'HTTP_CF_CONNECTING_IP' );
				if ( false !== $cf && $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
					$resolved = $cf;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'x_forwarded_for':
				$xff = $this->server_ip( 'HTTP_X_FORWARDED_FOR' );
				if ( false !== $xff && $this->peer_may_forward_client_ip( $remote_addr, $trusted, $cf_cidrs ) ) {
					$resolved = $xff;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'x_real_ip':
				$xri = $this->server_ip( 'HTTP_X_REAL_IP' );
				if ( false !== $xri && $this->peer_may_forward_client_ip( $remote_addr, $trusted, $cf_cidrs ) ) {
					$resolved = $xri;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'auto':
			default:
				$cf = $this->server_ip( 'HTTP_CF_CONNECTING_IP' );
				if ( false !== $cf && $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
					$resolved = $cf;
				} elseif ( $this->ip_in_any_cidr( $remote_addr, $trusted ) || $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
					$xff = $this->server_ip( 'HTTP_X_FORWARDED_FOR' );
					if ( false !== $xff ) {
						$resolved = $xff;
					} else {
						$xri      = $this->server_ip( 'HTTP_X_REAL_IP' );
						$resolved = ( false !== $xri ) ? $xri : $remote_addr;
					}
				} else {
					$resolved = $remote_addr;
				}
				break;
		}
		return filter_var( $resolved, FILTER_VALIDATE_IP ) ? $resolved : false;
	}

	/**
	 * @param string $key Key.
	 * @return string|false
	 */
	private function server_ip( $key ) {
		if ( empty( $this->server[ $key ] ) || ! is_string( $this->server[ $key ] ) ) {
			return false;
		}
		foreach ( explode( ',', $this->server[ $key ] ) as $part ) {
			$ip = trim( $part );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}
		return false;
	}

	/**
	 * @param string $ip IP.
	 * @return bool
	 */
	private function matches_unlock( $ip ) {
		$hash = isset( $this->config['unblock_secret_hash'] ) ? (string) $this->config['unblock_secret_hash'] : '';
		if ( '' === $hash || empty( $this->server['QUERY_STRING'] ) && empty( $this->request['snf'] ) ) {
			if ( empty( $this->request['snf'] ) ) {
				return false;
			}
		}
		if ( empty( $this->request['snf'] ) ) {
			return false;
		}
		$provided  = (string) $this->request['snf'];
		$candidate = hash_hmac( 'sha256', $provided, 'secnin-waf-unblock' );
		if ( hash_equals( $hash, $candidate ) ) {
			return true;
		}
		if ( ! empty( $this->config['unblock_secret'] ) && hash_equals( (string) $this->config['unblock_secret'], $provided ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @return bool
	 */
	private function has_valid_admin_cookie() {
		$key = isset( $this->config['cookie_key'] ) ? (string) $this->config['cookie_key'] : '';
		if ( '' === $key || empty( $this->cookies['secnin_waf_admin'] ) ) {
			return false;
		}
		$parts = explode( '|', (string) $this->cookies['secnin_waf_admin'], 3 );
		if ( 3 !== count( $parts ) ) {
			return false;
		}
		list( $uid, $exp, $sig ) = $parts;
		if ( ! ctype_digit( $uid ) || ! ctype_digit( $exp ) || (int) $exp < time() ) {
			return false;
		}
		return hash_equals( hash_hmac( 'sha256', $uid . '|' . $exp, $key ), $sig );
	}

	/**
	 * @param string $ip IP.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		$lists = array();
		foreach ( array( 'whitelist', 'service_whitelist', 'validated_crawlers' ) as $key ) {
			if ( ! empty( $this->config[ $key ] ) && is_array( $this->config[ $key ] ) ) {
				$lists = array_merge( $lists, $this->config[ $key ] );
			}
		}
		return $this->ip_matches_list( $ip, $lists );
	}

	/**
	 * @param string $ip IP.
	 * @return string|false
	 */
	private function ban_reason( $ip ) {
		$blacklist = isset( $this->config['blacklist'] ) && is_array( $this->config['blacklist'] ) ? $this->config['blacklist'] : array();
		if ( $this->ip_matches_list( $ip, $blacklist ) ) {
			return 'IP is in local blacklist.';
		}
		$bans = isset( $this->config['bans'] ) && is_array( $this->config['bans'] ) ? $this->config['bans'] : array();
		if ( isset( $bans[ $ip ] ) && (int) $bans[ $ip ] > time() ) {
			return 'Local blacklist.';
		}
		if ( ! empty( $this->config['usecloud'] ) && ! $this->is_non_public_ip( $ip ) ) {
			$cloud = isset( $this->config['cloud'] ) && is_array( $this->config['cloud'] ) ? $this->config['cloud'] : array();
			$ips   = isset( $cloud['ips'] ) && is_array( $cloud['ips'] ) ? $cloud['ips'] : array();
			if ( in_array( $ip, $ips, true ) ) {
				if ( ! empty( $this->flags['satellite_soften'] ) ) {
					return false;
				}
				return 'Cloud firewall blocklist.';
			}
			$subnets = isset( $cloud['subnets'] ) && is_array( $cloud['subnets'] ) ? $cloud['subnets'] : array();
			foreach ( $subnets as $group ) {
				if ( ! is_array( $group ) ) {
					continue;
				}
				foreach ( $group as $cidr ) {
					$cidr = trim( str_replace( "'", '', (string) $cidr ) );
					if ( '' !== $cidr && $this->ip_cidr_match( $ip, $cidr ) ) {
						if ( ! empty( $this->flags['satellite_soften'] ) ) {
							return false;
						}
						return 'Cloud firewall blocklist subnet.';
					}
				}
			}
		}
		return false;
	}

	/**
	 * Whether an IP is private, loopback, link-local, or otherwise non-public.
	 *
	 * Manual rules still apply to these addresses; cloud reputation does not.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_non_public_ip( $ip ) {
		$flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
		return false === filter_var( $ip, FILTER_VALIDATE_IP, $flags );
	}

	/**
	 * @return bool
	 */
	private function should_enforce_ban() {
		if ( ! empty( $this->config['global'] ) ) {
			return true;
		}
		return $this->is_login_related_request();
	}

	/**
	 * @return bool
	 */
	private function is_login_related_request() {
		$uri  = isset( $this->server['REQUEST_URI'] ) ? (string) $this->server['REQUEST_URI'] : '';
		$slug = isset( $this->config['login_slug'] ) ? trim( (string) $this->config['login_slug'], '/' ) : '';
		$extra = ( '' !== $slug ) ? array( $slug ) : array();
		if ( secnin_waf_is_login_related_request( $uri, $extra ) ) {
			return true;
		}
		return ! empty( $this->flags['is_login_related'] );
	}

	/**
	 * Skip 8G query filtering for admin / AJAX / cron request URIs (matches legacy).
	 *
	 * @return bool
	 */
	private function is_wp_context_skip() {
		$uri = isset( $this->server['REQUEST_URI'] ) ? (string) $this->server['REQUEST_URI'] : '';
		if ( '' === $uri ) {
			return false;
		}
		if ( false !== strpos( $uri, '/wp-admin/' ) ) {
			return true;
		}
		if ( false !== strpos( $uri, 'admin-ajax.php' ) ) {
			return true;
		}
		if ( false !== strpos( $uri, 'wp-cron.php' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @return bool
	 */
	private function is_allowed_2fa_ajax() {
		$uri = isset( $this->server['REQUEST_URI'] ) ? (string) $this->server['REQUEST_URI'] : '';
		if ( false === strpos( $uri, 'admin-ajax.php' ) ) {
			return false;
		}
		$action  = isset( $this->request['action'] ) ? (string) $this->request['action'] : '';
		$allowed = isset( $this->config['ajax_allow'] ) && is_array( $this->config['ajax_allow'] ) ? $this->config['ajax_allow'] : array();
		return in_array( $action, $allowed, true );
	}

	/**
	 * Match a temporary-login parameter materialized from active plugins.
	 *
	 * @return bool
	 */
	private function is_temporary_login_request() {
		$rules = isset( $this->config['temp_login_params'] ) && is_array( $this->config['temp_login_params'] )
			? $this->config['temp_login_params']
			: array();
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['param'] ) ) {
				continue;
			}
			$param = (string) $rule['param'];
			if ( ! empty( $rule['prefix'] ) ) {
				foreach ( array_keys( $this->request ) as $key ) {
					if ( 0 === strpos( (string) $key, $param ) && strlen( (string) $key ) > strlen( $param ) ) {
						return true;
					}
				}
				continue;
			}
			if ( ! array_key_exists( $param, $this->request ) ) {
				continue;
			}
			$requires = isset( $rule['requires'] ) && is_array( $rule['requires'] ) ? $rule['requires'] : array();
			$complete = true;
			foreach ( $requires as $required_param ) {
				if ( ! array_key_exists( (string) $required_param, $this->request ) ) {
					$complete = false;
					break;
				}
			}
			if ( $complete ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return array|false
	 */
	private function check_bad_queries() {
		$rules = array();
		if ( ! empty( $this->config['query_rules'] ) && is_array( $this->config['query_rules'] ) ) {
			$rules = $this->config['query_rules'];
		} else {
			$rules_file = dirname( __FILE__ ) . '/rules-8g.php';
			if ( ! is_readable( $rules_file ) ) {
				return false;
			}
			$loaded = include $rules_file;
			if ( ! is_array( $loaded ) ) {
				return false;
			}
			$rules = $loaded;
		}

		$woo_helper = dirname( __FILE__ ) . '/class-secnin-waf-woo-payment-surface.php';
		if ( ! class_exists( 'Secnin_Waf_Woo_Payment_Surface', false ) && is_readable( $woo_helper ) ) {
			require_once $woo_helper;
		}
		$sc_helper = dirname( __FILE__ ) . '/class-secnin-waf-surecart-payment-surface.php';
		if ( ! class_exists( 'Secnin_Waf_Surecart_Payment_Surface', false ) && is_readable( $sc_helper ) ) {
			require_once $sc_helper;
		}

		$request_uri  = isset( $this->server['REQUEST_URI'] ) ? (string) $this->server['REQUEST_URI'] : '';
		$query_string = isset( $this->server['QUERY_STRING'] ) ? (string) $this->server['QUERY_STRING'] : '';
		$user_agent   = isset( $this->server['HTTP_USER_AGENT'] ) ? (string) $this->server['HTTP_USER_AGENT'] : '';
		$referrer     = isset( $this->server['HTTP_REFERER'] ) ? (string) $this->server['HTTP_REFERER'] : '';

		$woo_active = ! empty( $this->config['woocommerce_active'] );
		$sc_active  = ! empty( $this->config['surecart_active'] );
		$payment    = false;
		$uri_value  = function_exists( 'secnin_waf_request_path' ) ? secnin_waf_request_path( $request_uri ) : $request_uri;
		if ( class_exists( 'Secnin_Waf_Woo_Payment_Surface', false ) ) {
			$payment_ctx = Secnin_Waf_Woo_Payment_Surface::context_from_server( $this->server, $woo_active );
			$payment     = Secnin_Waf_Woo_Payment_Surface::is_payment_request( $payment_ctx );
		}
		if ( ! $payment && class_exists( 'Secnin_Waf_Surecart_Payment_Surface', false ) ) {
			$sc_ctx  = Secnin_Waf_Surecart_Payment_Surface::context_from_server( $this->server, $sc_active );
			$payment = Secnin_Waf_Surecart_Payment_Surface::is_payment_request( $sc_ctx );
		}

		foreach ( array( 'request_uri' => $uri_value, 'query_string' => $query_string, 'user_agent' => $user_agent ) as $surface => $value ) {
			if ( ! $value || empty( $rules[ $surface ] ) || ! is_array( $rules[ $surface ] ) ) {
				continue;
			}
			foreach ( $rules[ $surface ] as $key => $pattern ) {
				if ( $payment && 'query_string' === $surface ) {
					$skip_q = ( class_exists( 'Secnin_Waf_Woo_Payment_Surface', false ) && Secnin_Waf_Woo_Payment_Surface::should_skip_query_rule( $key ) )
						|| ( class_exists( 'Secnin_Waf_Surecart_Payment_Surface', false ) && Secnin_Waf_Surecart_Payment_Surface::should_skip_query_rule( $key ) );
					if ( $skip_q ) {
						continue;
					}
				}
				if ( $payment && 'user_agent' === $surface ) {
					if ( class_exists( 'Secnin_Waf_Woo_Payment_Surface', false ) ) {
						$pattern = Secnin_Waf_Woo_Payment_Surface::ua_pattern_for_surface( $key, $pattern );
					} elseif ( class_exists( 'Secnin_Waf_Surecart_Payment_Surface', false ) ) {
						$pattern = Secnin_Waf_Surecart_Payment_Surface::ua_pattern_for_surface( $key, $pattern );
					}
				}
				if ( @preg_match( '#' . $pattern . '#i', $value ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return array(
						'matched_rule' => (string) $key,
						'message'      => $surface,
					);
				}
			}
		}
		if ( $referrer && ! empty( $rules['referrer'] ) && is_array( $rules['referrer'] ) ) {
			foreach ( $rules['referrer'] as $key => $pattern ) {
				if ( @preg_match( '#' . $pattern . '#i', $referrer ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return array(
						'matched_rule' => (string) $key,
						'message'      => 'referrer',
					);
				}
			}
		}
		return false;
	}

	/**
	 * @param string $ip   IP.
	 * @param array  $list List.
	 * @return bool
	 */
	private function ip_matches_list( $ip, $list ) {
		foreach ( $list as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( false !== strpos( $entry, '/' ) ) {
				if ( $this->ip_cidr_match( $ip, $entry ) ) {
					return true;
				}
			} elseif ( $ip === $entry ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $ip    IP.
	 * @param array  $cidrs CIDRs.
	 * @return bool
	 */
	private function ip_in_any_cidr( $ip, $cidrs ) {
		if ( ! is_array( $cidrs ) ) {
			return false;
		}
		foreach ( $cidrs as $cidr ) {
			if ( $this->ip_cidr_match( $ip, (string) $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether REMOTE_ADDR may supply X-Forwarded-For / X-Real-IP.
	 *
	 * @param string $remote_addr Peer IP.
	 * @param array  $trusted     Trusted proxy CIDRs.
	 * @param array  $cf_cidrs    Cloudflare CIDRs.
	 * @return bool
	 */
	private function peer_may_forward_client_ip( $remote_addr, $trusted, $cf_cidrs ) {
		if ( $this->is_non_public_ip( $remote_addr ) ) {
			return true;
		}
		if ( $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
			return true;
		}
		return $this->ip_in_any_cidr( $remote_addr, $trusted );
	}

	/**
	 * @param string $ip   IP.
	 * @param string $cidr CIDR.
	 * @return bool
	 */
	public function ip_cidr_match( $ip, $cidr ) {
		$parts  = explode( '/', $cidr, 2 );
		$subnet = isset( $parts[0] ) ? $parts[0] : '';
		$mask   = isset( $parts[1] ) ? (int) $parts[1] : null;
		if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			if ( null === $mask || $mask < 0 || $mask > 32 ) {
				return false;
			}
			$ip_long  = ip2long( $ip );
			$net_long = ip2long( $subnet );
			if ( false === $ip_long || false === $net_long ) {
				return false;
			}
			$mask_long = -1 << ( 32 - $mask );
			return ( $ip_long & $mask_long ) === ( $net_long & $mask_long );
		}
		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			if ( null === $mask || $mask < 0 || $mask > 128 ) {
				return false;
			}
			$ip_bin  = inet_pton( $ip );
			$net_bin = inet_pton( $subnet );
			if ( false === $ip_bin || false === $net_bin ) {
				return false;
			}
			$bytes = intdiv( $mask, 8 );
			$bits  = $mask % 8;
			if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $net_bin, 0, $bytes ) ) {
				return false;
			}
			if ( 0 === $bits ) {
				return true;
			}
			$mask_byte = 0xff << ( 8 - $bits );
			return ( ord( $ip_bin[ $bytes ] ) & $mask_byte ) === ( ord( $net_bin[ $bytes ] ) & $mask_byte );
		}
		return false;
	}
}
