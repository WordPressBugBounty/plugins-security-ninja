<?php
/**
 * Early WAF runner (no WordPress). Fail-open on any error.
 *
 * @package Security_Ninja
 */

if ( ! defined( 'SECNIN_WAF_BOOTSTRAP' ) ) {
	return;
}

/**
 * Class Secnin_Waf_Runner
 *
 * Pure request inspection for auto_prepend_file mode.
 */
class Secnin_Waf_Runner {

	const COOKIE_NAME = 'secnin_waf_admin';

	/**
	 * Active generation payload.
	 *
	 * @var array
	 */
	private $config = array();

	/**
	 * Constructor.
	 *
	 * @param array|string $config_or_dir Generation payload array, or legacy config directory.
	 */
	public function __construct( $config_or_dir ) {
		if ( is_array( $config_or_dir ) ) {
			$this->config = $config_or_dir;
			return;
		}

		// Legacy directory loader (tests / migration). Prefer generation payload.
		$dir = rtrim( (string) $config_or_dir, '/\\' );
		$this->config = $this->load_legacy_json_dir( $dir );
	}

	/**
	 * Whether this process should skip enforcement (CLI tooling).
	 *
	 * Tests may set SECNIN_WAF_FORCE_WEB=1 to exercise the early path under CLI.
	 *
	 * @return bool
	 */
	private static function is_cli_noop() {
		if ( getenv( 'SECNIN_WAF_FORCE_WEB' ) ) {
			return false;
		}
		$sapi = PHP_SAPI;
		return ( 'cli' === $sapi || 'phpdbg' === $sapi || 'cli-server' === $sapi );
	}

	/**
	 * Mark a completed capability for WordPress handoff.
	 *
	 * @param string $name Capability.
	 * @return void
	 */
	private function mark_capability( $name ) {
		if ( ! isset( $GLOBALS['SECNIN_WAF_CAPABILITIES'] ) || ! is_array( $GLOBALS['SECNIN_WAF_CAPABILITIES'] ) ) {
			$GLOBALS['SECNIN_WAF_CAPABILITIES'] = array();
		}
		$GLOBALS['SECNIN_WAF_CAPABILITIES'][ (string) $name ] = true;
	}

	/**
	 * Entry point. Never throws to the request.
	 *
	 * @return void
	 */
	public function run() {
		try {
			if ( self::is_cli_noop() ) {
				return;
			}

			if ( empty( $this->config ) || empty( $this->config['active'] ) ) {
				return;
			}

			$engine_file = dirname( __FILE__ ) . '/class-secnin-waf-decision-engine.php';
			if ( is_readable( $engine_file ) ) {
				require_once $engine_file;
			}
			if ( ! class_exists( 'Secnin_Waf_Decision_Engine', false ) ) {
				return;
			}

			$engine   = new Secnin_Waf_Decision_Engine( $this->config, $_SERVER, $_REQUEST, $_COOKIE, array() );
			$decision = $engine->decide();

			if ( ! empty( $decision->capabilities ) && is_array( $decision->capabilities ) ) {
				foreach ( $decision->capabilities as $cap => $on ) {
					if ( $on ) {
						$this->mark_capability( $cap );
					}
				}
			}

			if ( ! empty( $decision->capabilities['unlock_url'] ) && $decision->ip ) {
				$this->whitelist_ip_runtime( $decision->ip );
			}

			if ( Secnin_Waf_Decision::BLOCK === $decision->action ) {
				$event_rule = $decision->matched_rule ? $decision->matched_rule : $decision->rule;
				$this->block( $decision->ip, $decision->reason, $event_rule ? $event_rule : 'block', (string) $decision->ban_type );
			}
		} catch ( Exception $e ) {
			return;
		} catch ( Throwable $e ) {
			return;
		}
	}

	/**
	 * Pepper for unlock secret hashing (must match WordPress sync).
	 *
	 * @return string
	 */
	private function unblock_pepper() {
		return 'secnin-waf-unblock';
	}

	/**
	 * Load legacy JSON directory into a payload-like array.
	 *
	 * @param string $dir Directory.
	 * @return array
	 */
	private function load_legacy_json_dir( $dir ) {
		$config = $this->read_json( $dir . '/config.json' );
		if ( empty( $config ) ) {
			return array();
		}
		$lists = $this->read_json( $dir . '/lists.json' );
		$bans  = $this->read_json( $dir . '/bans.json' );
		$cloud = $this->read_json( $dir . '/cloud-ips.json' );
		$config['whitelist'] = isset( $lists['whitelist'] ) ? $lists['whitelist'] : array();
		$config['blacklist'] = isset( $lists['blacklist'] ) ? $lists['blacklist'] : array();
		$config['bans']      = $bans;
		$config['cloud']     = $cloud;
		return $config;
	}

	/**
	 * Read a JSON file.
	 *
	 * @param string $path Path.
	 * @return array
	 */
	private function read_json( $path ) {
		if ( ! is_readable( $path ) ) {
			return array();
		}
		$raw = file_get_contents( $path );
		if ( false === $raw || '' === $raw ) {
			return array();
		}
		$decoded = json_decode( $raw, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Resolve visitor IP using config ip_source.
	 *
	 * @return string|false
	 */
	private function resolve_ip() {
		$source      = isset( $this->config['ip_source'] ) ? (string) $this->config['ip_source'] : 'auto';
		$remote_addr = $this->server_ip( 'REMOTE_ADDR' );
		if ( false === $remote_addr ) {
			$remote_addr = '127.0.0.1';
		}

		$trusted = isset( $this->config['trusted_proxy_cidrs'] ) && is_array( $this->config['trusted_proxy_cidrs'] )
			? $this->config['trusted_proxy_cidrs']
			: array();

		switch ( $source ) {
			case 'remote_addr':
				$resolved = $remote_addr;
				break;
			case 'cf_connecting_ip':
				$cf       = $this->server_ip( 'HTTP_CF_CONNECTING_IP' );
				$cf_cidrs = isset( $this->config['cloudflare_cidrs'] ) && is_array( $this->config['cloudflare_cidrs'] )
					? $this->config['cloudflare_cidrs']
					: array();
				if ( false !== $cf && $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
					$resolved = $cf;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'x_forwarded_for':
				$xff = $this->server_ip( 'HTTP_X_FORWARDED_FOR' );
				if ( false !== $xff && $this->peer_may_forward_client_ip( $remote_addr, $trusted ) ) {
					$resolved = $xff;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'x_real_ip':
				$xri = $this->server_ip( 'HTTP_X_REAL_IP' );
				if ( false !== $xri && $this->peer_may_forward_client_ip( $remote_addr, $trusted ) ) {
					$resolved = $xri;
				} else {
					$resolved = $remote_addr;
				}
				break;
			case 'auto':
			default:
				$cf = $this->server_ip( 'HTTP_CF_CONNECTING_IP' );
				if ( false !== $cf && $this->ip_in_any_cidr( $remote_addr, isset( $this->config['cloudflare_cidrs'] ) ? $this->config['cloudflare_cidrs'] : array() ) ) {
					$resolved = $cf;
				} elseif ( $this->ip_in_any_cidr( $remote_addr, $trusted ) || $this->ip_in_any_cidr( $remote_addr, isset( $this->config['cloudflare_cidrs'] ) ? $this->config['cloudflare_cidrs'] : array() ) ) {
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
	 * First valid IP from a $_SERVER key.
	 *
	 * @param string $key Server key.
	 * @return string|false
	 */
	private function server_ip( $key ) {
		if ( empty( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) {
			return false;
		}
		foreach ( explode( ',', $_SERVER[ $key ] ) as $part ) {
			$ip = trim( $part );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}
		return false;
	}

	/**
	 * Whether IP is on whitelist (manual, service, or validated crawlers).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		$lists = array();
		foreach ( array( 'whitelist', 'service_whitelist', 'validated_crawlers' ) as $key ) {
			if ( isset( $this->config[ $key ] ) && is_array( $this->config[ $key ] ) ) {
				$lists = array_merge( $lists, $this->config[ $key ] );
			}
		}
		if ( $this->ip_matches_list( $ip, $lists ) ) {
			return true;
		}
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			$alt = ( '127.0.0.1' === $ip ) ? '::1' : '127.0.0.1';
			if ( in_array( $alt, $lists, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Ban decision for IP.
	 *
	 * @param string $ip IP.
	 * @return string|false Reason or false.
	 */
	private function is_banned_ip( $ip ) {
		$blacklist = isset( $this->config['blacklist'] ) && is_array( $this->config['blacklist'] ) ? $this->config['blacklist'] : array();
		if ( $this->ip_matches_list( $ip, $blacklist ) ) {
			return 'IP is in local blacklist.';
		}

		$bans = isset( $this->config['bans'] ) && is_array( $this->config['bans'] ) ? $this->config['bans'] : array();
		if ( isset( $bans[ $ip ] ) ) {
			$expiry = (int) $bans[ $ip ];
			if ( $expiry > time() ) {
				return 'Local blacklist.';
			}
		}

		if ( ! empty( $this->config['usecloud'] ) ) {
			$cloud_reason = $this->cloud_block_reason( $ip );
			if ( '' !== $cloud_reason ) {
				return $cloud_reason;
			}
		}

		return false;
	}

	/**
	 * Match IP against cloud list.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function cloud_block_reason( $ip ) {
		$cloud = isset( $this->config['cloud'] ) && is_array( $this->config['cloud'] ) ? $this->config['cloud'] : array();
		$ips   = isset( $cloud['ips'] ) && is_array( $cloud['ips'] ) ? $cloud['ips'] : array();
		if ( in_array( $ip, $ips, true ) ) {
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
					return 'Cloud firewall blocklist subnet.';
				}
			}
		}
		return '';
	}

	/**
	 * Exact or CIDR list match.
	 *
	 * @param string $ip   IP.
	 * @param array  $list Entries.
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
	 * Whether IP is in any CIDR.
	 *
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
	 * @return bool
	 */
	private function peer_may_forward_client_ip( $remote_addr, $trusted ) {
		if ( $this->is_non_public_ip( $remote_addr ) ) {
			return true;
		}
		$cf_cidrs = isset( $this->config['cloudflare_cidrs'] ) && is_array( $this->config['cloudflare_cidrs'] )
			? $this->config['cloudflare_cidrs']
			: array();
		if ( $this->ip_in_any_cidr( $remote_addr, $cf_cidrs ) ) {
			return true;
		}
		return $this->ip_in_any_cidr( $remote_addr, $trusted );
	}

	/**
	 * Private, loopback, or reserved IP (local reverse proxy peers).
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	private function is_non_public_ip( $ip ) {
		return is_string( $ip ) && '' !== $ip
			&& (bool) filter_var( $ip, FILTER_VALIDATE_IP )
			&& ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * CIDR match (IPv4/IPv6).
	 *
	 * @param string $ip   IP.
	 * @param string $cidr CIDR.
	 * @return bool
	 */
	private function ip_cidr_match( $ip, $cidr ) {
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

	/**
	 * Signed admin cookie present and valid.
	 *
	 * @return bool
	 */
	private function has_valid_admin_cookie() {
		$key = isset( $this->config['cookie_key'] ) ? (string) $this->config['cookie_key'] : '';
		if ( '' === $key || empty( $_COOKIE[ self::COOKIE_NAME ] ) ) {
			return false;
		}
		$raw   = (string) $_COOKIE[ self::COOKIE_NAME ];
		$parts = explode( '|', $raw, 3 );
		if ( 3 !== count( $parts ) ) {
			return false;
		}
		list( $uid, $exp, $sig ) = $parts;
		if ( ! ctype_digit( $uid ) || ! ctype_digit( $exp ) ) {
			return false;
		}
		if ( (int) $exp < time() ) {
			return false;
		}
		$expected = hash_hmac( 'sha256', $uid . '|' . $exp, $key );
		return hash_equals( $expected, $sig );
	}

	/**
	 * Login-related path (includes rename-login slug).
	 *
	 * @return bool
	 */
	private function is_login_related_request() {
		if ( ! function_exists( 'secnin_waf_is_login_related_request' ) ) {
			$helper = dirname( __FILE__ ) . '/secnin-waf-login-related.php';
			if ( is_readable( $helper ) ) {
				require_once $helper;
			}
		}
		if ( ! function_exists( 'secnin_waf_is_login_related_request' ) ) {
			return false;
		}
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$slug  = isset( $this->config['login_slug'] ) ? trim( (string) $this->config['login_slug'], '/' ) : '';
		$extra = ( '' !== $slug ) ? array( $slug ) : array();
		return secnin_waf_is_login_related_request( $uri, $extra );
	}

	/**
	 * Allow listed 2FA admin-ajax actions through query filter.
	 *
	 * @return bool
	 */
	private function is_allowed_2fa_ajax() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( false === strpos( $uri, 'admin-ajax.php' ) ) {
			return false;
		}
		$action  = isset( $_REQUEST['action'] ) ? (string) $_REQUEST['action'] : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$allowed = isset( $this->config['ajax_allow'] ) && is_array( $this->config['ajax_allow'] )
			? $this->config['ajax_allow']
			: array(
				'secnin_generate_qr_code',
				'secnin_skip_2fa',
				'secnin_verify_2fa_code',
				'secnin_send_2fa_email',
			);
		return in_array( $action, $allowed, true );
	}

	/**
	 * 8G-style query checks.
	 *
	 * @return array|false
	 */
	private function check_bad_queries() {
		$rules_file = dirname( __FILE__ ) . '/rules-8g.php';
		if ( ! is_readable( $rules_file ) ) {
			return false;
		}
		$rules = include $rules_file;
		if ( ! is_array( $rules ) ) {
			return false;
		}

		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';
		$user_agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		$referrer     = isset( $_SERVER['HTTP_REFERER'] ) ? (string) $_SERVER['HTTP_REFERER'] : '';

		if ( $request_uri && ! function_exists( 'secnin_waf_request_path' ) ) {
			$helper = dirname( __FILE__ ) . '/secnin-waf-login-related.php';
			if ( is_readable( $helper ) ) {
				require_once $helper;
			}
		}
		$uri_path = function_exists( 'secnin_waf_request_path' ) ? secnin_waf_request_path( $request_uri ) : $request_uri;

		if ( $uri_path && ! empty( $rules['request_uri'] ) ) {
			foreach ( $rules['request_uri'] as $key => $pattern ) {
				if ( @preg_match( '#' . $pattern . '#i', $uri_path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return array(
						'matched_rule' => (string) $key,
						'message'      => 'request_uri',
					);
				}
			}
		}
		if ( $query_string && ! empty( $rules['query_string'] ) ) {
			foreach ( $rules['query_string'] as $key => $pattern ) {
				if ( @preg_match( '#' . $pattern . '#i', $query_string ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return array(
						'matched_rule' => (string) $key,
						'message'      => 'query_string',
					);
				}
			}
		}
		if ( $user_agent && ! empty( $rules['user_agent'] ) ) {
			foreach ( $rules['user_agent'] as $key => $pattern ) {
				if ( @preg_match( '#' . $pattern . '#i', $user_agent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					return array(
						'matched_rule' => (string) $key,
						'message'      => 'user_agent',
					);
				}
			}
		}
		if ( $referrer && ! empty( $rules['referrer'] ) ) {
			foreach ( $rules['referrer'] as $key => $pattern ) {
				if ( @preg_match( '/' . preg_quote( $pattern, '/' ) . '/i', $referrer ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
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
	 * Add IP to whitelist generation side-channel for unlock URL.
	 *
	 * @param string $ip IP.
	 * @return void
	 */
	private function whitelist_ip_runtime( $ip ) {
		$dir = dirname( __FILE__ );
		// Prefer sibling config dir when running from runtime/.
		$config_dir = dirname( $dir ) . '/config';
		if ( ! is_dir( $config_dir ) ) {
			$config_dir = $dir;
		}
		$flag    = $config_dir . '/unlock-pending.php';
		$content = "<?php\nreturn " . var_export( array( 'ip' => $ip, 'ts' => time() ), true ) . ";\n";
		$tmp     = $flag . '.tmp';
		if ( false !== file_put_contents( $tmp, $content, LOCK_EX ) ) {
			@rename( $tmp, $flag ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
		}
	}

	/**
	 * Emit block response and exit.
	 *
	 * @param string $ip       IP.
	 * @param string $reason   Reason.
	 * @param string $rule     Rule key.
	 * @param string $ban_type 8G surface, or empty for non-8G blocks.
	 * @return void
	 */
	private function block( $ip, $reason, $rule = 'block', $ban_type = '' ) {
		$this->mark_capability( 'blocked' );
		// Queue file for WordPress importer (phase 5 will harden). Best-effort.
		$this->queue_block_event( $ip, $reason, $rule, $ban_type );

		$redirect = isset( $this->config['redirect_url'] ) ? (string) $this->config['redirect_url'] : '';
		if ( '' !== $redirect && filter_var( $redirect, FILTER_VALIDATE_URL ) ) {
			header( 'Location: ' . $redirect, true, 301 );
			exit;
		}
		$message = isset( $this->config['message'] ) ? (string) $this->config['message'] : 'You are not allowed to visit this website.';
		$message = htmlspecialchars( $message, ENT_QUOTES, 'UTF-8' );
		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Content-Type: text/html; charset=UTF-8' );
			header( 'Cache-Control: no-store' );
		}
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>' . $message . '</p></body></html>';
		exit;
	}

	/**
	 * Cut a header to $max bytes without leaving a broken UTF-8 tail.
	 *
	 * Early Firewall runs before WordPress, so this cannot use wp_check_invalid_utf8().
	 * A mid-character cut is what MariaDB rejects when the event is imported.
	 *
	 * @param string $value Raw header value.
	 * @param int    $max   Max bytes.
	 * @return string
	 */
	private static function clip_utf8( $value, $max ) {
		$value = (string) $value;
		if ( strlen( $value ) <= $max ) {
			return $value;
		}
		$value = substr( $value, 0, $max );
		$len   = strlen( $value );
		$i     = $len - 1;
		$cont  = 0;
		while ( $i >= 0 && $cont < 3 && ( ord( $value[ $i ] ) & 0xC0 ) === 0x80 ) {
			++$cont;
			--$i;
		}
		if ( $i < 0 ) {
			return '';
		}
		$lead = ord( $value[ $i ] );
		if ( $lead < 0x80 ) {
			$need = 1;
		} elseif ( $lead < 0xE0 ) {
			$need = 2;
		} elseif ( $lead < 0xF0 ) {
			$need = 3;
		} elseif ( $lead < 0xF8 ) {
			$need = 4;
		} else {
			return substr( $value, 0, $i );
		}
		if ( ( $len - $i ) < $need ) {
			return substr( $value, 0, $i );
		}
		return $value;
	}

	/**
	 * Append a minimal block event for later WordPress import.
	 *
	 * @param string $ip       IP.
	 * @param string $reason   Reason.
	 * @param string $rule     Rule.
	 * @param string $ban_type 8G surface, or empty.
	 * @return void
	 */
	private function queue_block_event( $ip, $reason, $rule, $ban_type = '' ) {
		// Runtime lives in .../security-ninja-waf/runtime/; queue is sibling .../queue/.
		$dir = dirname( dirname( __FILE__ ) ) . '/queue';
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0755, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
		}
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return;
		}
		try {
			$event_id = bin2hex( random_bytes( 16 ) );
		} catch ( Exception $e ) {
			$event_id = uniqid( 'sn', true );
		}
		$event = array(
			'event_id'    => $event_id,
			'ts'          => time(),
			'ip'          => $ip,
			'reason'      => $reason,
			'rule'        => $rule,
			'uri'         => isset( $_SERVER['REQUEST_URI'] ) ? self::clip_utf8( (string) $_SERVER['REQUEST_URI'], 255 ) : '',
			'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? self::clip_utf8( (string) $_SERVER['HTTP_USER_AGENT'], 255 ) : '',
			'source'      => 'early',
			'ban_type'    => (string) $ban_type,
		);
		$file = $dir . '/evt-' . $event_id . '.php';
		$body = "<?php\nreturn " . var_export( $event, true ) . ";\n";
		@file_put_contents( $file, $body, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
	}
}
