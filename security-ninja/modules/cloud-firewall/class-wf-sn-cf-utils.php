<?php
/**
 * Cloud Firewall utility helpers (IP/CIDR, string, crawler UA).
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WF_SN_CF_AI_CRAWLER_RANGES' ) ) {
	define( 'WF_SN_CF_AI_CRAWLER_RANGES', 'wf_sn_cf_ai_crawler_ranges' );
}

if ( ! defined( 'WF_SN_CF_VALIDATED_CRAWLERS' ) ) {
	define( 'WF_SN_CF_VALIDATED_CRAWLERS', 'wf_sn_cf_validated_crawlers' );
}

/**
 * Class Wf_sn_cf_Utils
 *
 * Static helpers for the cloud firewall; used to keep cloud-firewall.php maintainable.
 */
class Wf_sn_cf_Utils {

	/**
	 * Whether the current request's User-Agent is a known social/link-preview crawler.
	 *
	 * Used to allow these crawlers through the Block IP Network (GBN) so link previews
	 * (e.g. Facebook, LinkedIn, Twitter) work without whitelisting IP ranges.
	 *
	 * @since  5.267
	 * @return bool True if UA matches the filterable list (or list is empty after filter), false otherwise.
	 */
	public static function is_social_crawler_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		if ( '' === $ua || ! is_string( $ua ) ) {
			return false;
		}

		$default = array(
			'facebookexternalhit',
			'Facebot',
			'LinkedInBot',
			'Twitterbot',
			'Slackbot-LinkExpanding',
			'Discordbot',
		);
		$list    = apply_filters( 'securityninja_social_crawler_user_agents', $default );
		if ( ! is_array( $list ) ) {
			$list = array();
		}

		foreach ( $list as $item ) {
			if ( '' !== $item && stripos( $ua, $item ) !== false ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if haystack ends with needle.
	 *
	 * @author  javalc6 at gmail dot com
	 * @since   v0.0.1
	 * @param   string $haystack
	 * @param   string $needle
	 * @return  bool
	 */
	public static function string_ends_with( $haystack, $needle ) {
		$length = strlen( $needle );
		return $length > 0 ? substr( $haystack, -$length ) === $needle : true;
	}

	/**
	 * Whether an IP is private, loopback, or otherwise non-public (not routable on the internet).
	 *
	 * @since 5.288
	 * @param mixed $ip IP address string.
	 * @return bool
	 */
	public static function is_non_public_ip( $ip ) {
		return is_string( $ip ) && '' !== $ip
			&& filter_var( $ip, FILTER_VALIDATE_IP )
			&& ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Checks if an IP is whitelisted (exact IP or CIDR).
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @param   mixed $ip        IP address.
	 * @param   mixed $whitelist Array of IPs or CIDR strings.
	 * @return  bool
	 */
	public static function is_whitelisted( $ip, $whitelist ) {
		if ( ! is_array( $whitelist ) ) {
			return false;
		}

		foreach ( $whitelist as $key => $wip ) {
			$wip = trim( (string) $wip );
			if ( '' === $wip ) {
				continue;
			}
			if ( strpos( $wip, '/' ) !== false ) {
				if ( self::ipCIDRMatch( $ip, $wip ) ) {
					return true;
				}
			} elseif ( $ip === $wip ) {
				return true;
			}
		}

		// Loopback equivalence: whitelisting either 127.0.0.1 or ::1 covers both forms.
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			$alternate = ( '127.0.0.1' === $ip ) ? '::1' : '127.0.0.1';
			foreach ( $whitelist as $wip ) {
				$wip = trim( (string) $wip );
				if ( $alternate === $wip ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * ipCIDRMatch.
	 *
	 * @author  Unknown
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @param   string $ip   The IP address to check.
	 * @param   string $cidr The CIDR range to check against.
	 * @return  bool         True if the IP matches the CIDR range, false otherwise.
	 */
	public static function ipCIDRMatch( $ip, $cidr ) {
		$c      = explode( '/', $cidr );
		$subnet = isset( $c[0] ) ? $c[0] : null;
		$mask   = isset( $c[1] ) ? (int) $c[1] : null;

		if ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$ip_version = 'v4';
		} elseif ( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$ip_version = 'v6';
		} else {
			return false;
		}

		switch ( $ip_version ) {
			case 'v4':
				if ( null === $mask || $mask < 0 || $mask > 32 ) {
					return false;
				}
				return self::IPv4Match( $ip, $subnet, $mask );
			case 'v6':
				if ( null === $mask || $mask < 0 || $mask > 128 ) {
					return false;
				}
				return self::IPv6Match( $ip, $subnet, $mask );
			default:
				return false;
		}
	}

	/**
	 * IPv6 mask to byte array (for CIDR matching).
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @param   int $subnet_mask
	 * @return  string
	 */
	private static function IPv6MaskToByteArray( $subnet_mask ) {
		$addr = str_repeat( 'f', intdiv( $subnet_mask, 4 ) );
		switch ( $subnet_mask % 4 ) {
			case 0:
				break;
			case 1:
				$addr .= '8';
				break;
			case 2:
				$addr .= 'c';
				break;
			case 3:
				$addr .= 'e';
				break;
		}
		$addr = str_pad( $addr, 32, '0' );
		$addr = pack( 'H*', $addr );
		return $addr;
	}

	/**
	 * IPv6 address match against subnet.
	 *
	 * @author  Unknown
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @param   string $address       Address to check.
	 * @param   string $subnet_address Subnet address.
	 * @param   int    $subnet_mask   Subnet mask.
	 * @return  bool
	 */
	private static function IPv6Match( $address, $subnet_address, $subnet_mask ) {
		if (
			! filter_var( $subnet_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ||
			null === $subnet_mask ||
			'' === $subnet_mask ||
			$subnet_mask < 0 ||
			$subnet_mask > 128
		) {
			return false;
		}

		$subnet = inet_pton( $subnet_address );
		$addr   = inet_pton( $address );

		if ( false === $subnet || false === $addr ) {
			return false;
		}

		$bin_mask = self::IPv6MaskToByteArray( $subnet_mask );
		return ( $addr & $bin_mask ) === $subnet;
	}

	/**
	 * IPv4 address match against subnet.
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @param   string $address       Address to check.
	 * @param   string $subnet_address Subnet address.
	 * @param   int    $subnet_mask   Subnet mask.
	 * @return  bool
	 */
	private static function IPv4Match( $address, $subnet_address, $subnet_mask ) {
		if ( ! filter_var( $subnet_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || null === $subnet_mask || '' === $subnet_mask || $subnet_mask < 0 || $subnet_mask > 32 ) {
			return false;
		}

		$address         = ip2long( $address );
		$subnet_address  = ip2long( $subnet_address );
		$mask            = -1 << ( 32 - $subnet_mask );
		$subnet_address &= $mask;
		return ( $address & $mask ) === $subnet_address;
	}

	/**
	 * Max IPs remembered in wf_sn_cf_validated_crawlers (FIFO).
	 *
	 * @since 5.302
	 */
	const VALIDATED_CRAWLERS_MAX = 200;

	/**
	 * Read a per-IP lookup cache entry.
	 *
	 * Persistent only when an external object cache is present. Never writes to wp_options.
	 *
	 * @since 5.302
	 * @param string $key Transient key (without _transient_ prefix).
	 * @return mixed Cached value, or false on miss.
	 */
	public static function get_ip_lookup_cache( $key ) {
		if ( ! is_string( $key ) || '' === $key ) {
			return false;
		}
		if ( ! wp_using_ext_object_cache() ) {
			return false;
		}
		return get_transient( $key );
	}

	/**
	 * Store a per-IP lookup cache entry.
	 *
	 * Writes a WordPress transient only when an external object cache is present.
	 *
	 * @since 5.302
	 * @param string $key   Transient key (without _transient_ prefix).
	 * @param mixed  $value Value to cache.
	 * @param int    $ttl   TTL in seconds.
	 * @return void
	 */
	public static function set_ip_lookup_cache( $key, $value, $ttl ) {
		if ( ! is_string( $key ) || '' === $key ) {
			return;
		}
		if ( ! wp_using_ext_object_cache() ) {
			return;
		}
		set_transient( $key, $value, (int) $ttl );
	}

	/**
	 * Classic search/SEO crawler UA tokens that may justify reverse-DNS confirmation.
	 *
	 * Filterable via secnin_cf_crawler_ua_tokens.
	 *
	 * @since 5.302
	 * @return string[]
	 */
	public static function get_classic_crawler_ua_tokens() {
		$default = array(
			'Googlebot',
			'GoogleOther',
			'Google-InspectionTool',
			'bingbot',
			'msnbot',
			'Baiduspider',
			'Applebot',
			'AhrefsBot',
			'SemrushBot',
			'DuckDuckBot',
			'YandexBot',
			'Yandex',
			'Slurp',
			'PetalBot',
			'CCBot',
			'facebookexternalhit',
			'Facebot',
			'Sogou',
			'Swiftbot',
		);

		$list = apply_filters( 'secnin_cf_crawler_ua_tokens', $default );
		if ( ! is_array( $list ) ) {
			return array();
		}

		$out = array();
		foreach ( $list as $token ) {
			if ( is_string( $token ) && '' !== $token ) {
				$out[] = $token;
			}
		}

		return $out;
	}

	/**
	 * Whether the User-Agent looks like a classic crawler that needs PTR confirmation.
	 *
	 * @since 5.302
	 * @param string $ua Sanitized User-Agent.
	 * @return bool
	 */
	public static function ua_looks_like_classic_crawler( $ua ) {
		if ( ! is_string( $ua ) || '' === $ua ) {
			return false;
		}

		foreach ( self::get_classic_crawler_ua_tokens() as $token ) {
			if ( false !== stripos( $ua, $token ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Hostname suffixes accepted for classic crawler reverse-DNS confirmation.
	 *
	 * @since 5.302
	 * @return string[]
	 */
	public static function get_classic_crawler_host_suffixes() {
		return array(
			'.crawl.baidu.com',
			'.crawl.baidu.jp',
			'.search.msn.com',
			'.google.com',
			'.googlebot.com',
			'.crawl.yahoo.net',
			'.yandex.ru',
			'.yandex.net',
			'.yandex.com',
			'.petalsearch.com',
			'applebot.apple.com',
			'.ahrefs.com',
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
	}

	/**
	 * Remember a validated crawler IP with a hard FIFO cap.
	 *
	 * @since 5.302
	 * @param string $ip Client IP.
	 * @return void
	 */
	public static function remember_validated_crawler( $ip ) {
		if ( ! is_string( $ip ) || '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		$list = get_option( WF_SN_CF_VALIDATED_CRAWLERS, array() );
		if ( ! is_array( $list ) ) {
			$list = array();
		}

		if ( in_array( $ip, $list, true ) ) {
			return;
		}

		$list[] = $ip;
		while ( count( $list ) > self::VALIDATED_CRAWLERS_MAX ) {
			array_shift( $list );
		}

		update_option( WF_SN_CF_VALIDATED_CRAWLERS, array_values( $list ), false );
	}

	/**
	 * Map User-Agent substrings to official published-prefix JSON URLs (OpenAI, Perplexity, Anthropic).
	 *
	 * @since 5.277
	 * @param string $ua Sanitized User-Agent.
	 * @return string[] Unique HTTPS feed URLs.
	 */
	public static function get_ai_crawler_feed_urls_for_ua( $ua ) {
		if ( '' === $ua ) {
			return array();
		}

		static $token_to_url = null;
		if ( null === $token_to_url ) {
			$token_to_url = array(
				'GPTBot'           => 'https://openai.com/gptbot.json',
				'ChatGPT-User'     => 'https://openai.com/chatgpt-user.json',
				'OAI-SearchBot'    => 'https://openai.com/searchbot.json',
				'PerplexityBot'    => 'https://www.perplexity.com/perplexitybot.json',
				'Perplexity-User'  => 'https://www.perplexity.com/perplexity-user.json',
				'ClaudeBot'        => 'https://claude.com/crawling/bots.json',
				'Claude-User'      => 'https://claude.com/crawling/bots.json',
				'Claude-SearchBot' => 'https://claude.com/crawling/bots.json',
			);
		}

		$urls = array();
		foreach ( $token_to_url as $token => $url ) {
			if ( false !== strpos( $ua, $token ) ) {
				$urls[ $url ] = true;
			}
		}

		return array_keys( $urls );
	}

	/**
	 * Return CIDRs for a feed: fresh cache, stale cache with opportunistic refresh, or empty.
	 *
	 * @since 5.277
	 * @param string $feed_url HTTPS URL.
	 * @return string[]
	 */
	public static function get_ai_crawler_cidrs_for_feed_url( $feed_url ) {
		$ttl = DAY_IN_SECONDS;

		$option = get_option( WF_SN_CF_AI_CRAWLER_RANGES, array() );
		if ( ! is_array( $option ) ) {
			$option = array();
		}
		$sources = isset( $option['sources'] ) && is_array( $option['sources'] ) ? $option['sources'] : array();

		$cached = isset( $sources[ $feed_url ] ) && is_array( $sources[ $feed_url ] ) ? $sources[ $feed_url ] : null;
		$now    = time();

		if ( $cached && ! empty( $cached['cidrs'] ) && is_array( $cached['cidrs'] ) && isset( $cached['fetched_at'] ) ) {
			$age = $now - (int) $cached['fetched_at'];
			if ( $age < $ttl ) {
				return $cached['cidrs'];
			}
			$fresh = self::fetch_and_store_ai_crawler_ranges( $feed_url );
			if ( is_array( $fresh ) && ! empty( $fresh ) ) {
				return $fresh;
			}
			return $cached['cidrs'];
		}

		$fresh = self::fetch_and_store_ai_crawler_ranges( $feed_url );
		return is_array( $fresh ) ? $fresh : array();
	}

	/**
	 * Extract CIDR strings from OpenAI/Perplexity-style prefix JSON.
	 *
	 * @since 5.277
	 * @param array $data Decoded JSON (top-level).
	 * @return string[]
	 */
	private static function parse_ai_provider_prefixes_json( $data ) {
		if ( ! is_array( $data ) || empty( $data['prefixes'] ) || ! is_array( $data['prefixes'] ) ) {
			return array();
		}

		$cidrs = array();
		foreach ( $data['prefixes'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! empty( $row['ipv4Prefix'] ) && is_string( $row['ipv4Prefix'] ) ) {
				$cidrs[] = $row['ipv4Prefix'];
			}
			if ( ! empty( $row['ipv6Prefix'] ) && is_string( $row['ipv6Prefix'] ) ) {
				$cidrs[] = $row['ipv6Prefix'];
			}
		}

		return array_values( array_unique( array_filter( $cidrs ) ) );
	}

	/**
	 * Fetch provider JSON and persist under WF_SN_CF_AI_CRAWLER_RANGES.
	 *
	 * @since 5.277
	 * @param string $feed_url HTTPS URL only.
	 * @return string[]|null CIDR list on success, null on failure.
	 */
	private static function fetch_and_store_ai_crawler_ranges( $feed_url ) {
		if ( ! is_string( $feed_url ) || '' === $feed_url ) {
			return null;
		}
		if ( 0 !== strpos( $feed_url, 'https://' ) ) {
			return null;
		}

		$response = wp_remote_get(
			$feed_url,
			array(
				'timeout'     => 4,
				'redirection' => 5,
				'user-agent'  => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . home_url( '/' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			self::store_ai_crawler_last_error( $feed_url, $response->get_error_message() );
			return null;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			self::store_ai_crawler_last_error( $feed_url, 'HTTP ' . $code );
			return null;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			self::store_ai_crawler_last_error( $feed_url, 'empty body' );
			return null;
		}

		$data  = json_decode( $body, true );
		$cidrs = self::parse_ai_provider_prefixes_json( $data );
		if ( empty( $cidrs ) ) {
			self::store_ai_crawler_last_error( $feed_url, 'no prefixes' );
			return null;
		}

		$option = get_option( WF_SN_CF_AI_CRAWLER_RANGES, array() );
		if ( ! is_array( $option ) ) {
			$option = array();
		}
		if ( ! isset( $option['sources'] ) || ! is_array( $option['sources'] ) ) {
			$option['sources'] = array();
		}
		$option['sources'][ $feed_url ] = array(
			'fetched_at' => time(),
			'cidrs'      => $cidrs,
		);
		$option['last_error'] = '';
		update_option( WF_SN_CF_AI_CRAWLER_RANGES, $option, false );

		return $cidrs;
	}

	/**
	 * Record last AI crawler range fetch error (debugging).
	 *
	 * @since 5.277
	 * @param string $feed_url Feed URL.
	 * @param string $message  Short error message.
	 */
	private static function store_ai_crawler_last_error( $feed_url, $message ) {
		$option = get_option( WF_SN_CF_AI_CRAWLER_RANGES, array() );
		if ( ! is_array( $option ) ) {
			$option = array();
		}
		$option['last_error'] = array(
			'feed'    => $feed_url,
			'message' => $message,
			'at'      => time(),
		);
		update_option( WF_SN_CF_AI_CRAWLER_RANGES, $option, false );
	}
}
