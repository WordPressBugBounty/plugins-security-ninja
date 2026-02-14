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
	 * Checks if an IP is whitelisted (exact IP or CIDR).
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @param   mixed $ip        IP address.
	 * @param   mixed $whitelist Array of IPs or CIDR strings.
	 * @return  bool
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
		$addr = str_repeat( 'f', $subnet_mask / 4 );
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

		$address        = ip2long( $address );
		$subnet_address = ip2long( $subnet_address );
		$mask           = -1 << ( 32 - $subnet_mask );
		$subnet_address &= $mask;
		return ( $address & $mask ) == $subnet_address;
	}
}
