<?php
/**
 * Service / crawler IP whitelist helpers.
 *
 * Free-shipping. Loaded on demand from wf_sn_cf wrappers.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Cf_Service_Whitelist
 */
class Wf_Sn_Cf_Service_Whitelist {

	/**
	 * Validate a crawler IP against published ranges or reverse-DNS.
	 *
	 * Order: remembered list, AI UA + CIDR (no PTR), classic crawler UA then PTR +
	 * forward confirm. Generic browsers never trigger reverse-DNS.
	 *
	 * @author  Lars Koudal
	 * @since   v5.123
	 * @version v1.0.0  Monday, August 30th, 2021.
	 * @version v1.0.1  Monday, June 3rd, 2024.
	 * @version v1.0.2  Monday, August 31st, 2026. UA-first; no PTR for generic UAs.
	 * @access  private static
	 * @param   mixed       $testip Client IP.
	 * @param   string|null $ua     User-Agent string; null reads HTTP_USER_AGENT when present.
	 * @return  boolean
	 */
	public static function validate_crawler_ip( $testip, $ua = null ) {
		if ( ! is_string( $testip ) || '' === $testip || ! filter_var( $testip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( Wf_sn_cf_Utils::is_non_public_ip( $testip ) ) {
			return false;
		}

		$validated_crawlers = get_option( WF_SN_CF_VALIDATED_CRAWLERS );
		if ( is_array( $validated_crawlers ) && in_array( $testip, $validated_crawlers, true ) ) {
			return true;
		}

		if ( null === $ua ) {
			$ua = '';
			if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
				$ua = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
			}
		} elseif ( ! is_string( $ua ) ) {
			$ua = '';
		}

		// Verified AI crawlers: UA token + IP in provider-published ranges (no PTR).
		$ai_feed_urls = Wf_sn_cf_Utils::get_ai_crawler_feed_urls_for_ua( $ua );
		if ( ! empty( $ai_feed_urls ) ) {
			foreach ( $ai_feed_urls as $feed_url ) {
				$cidrs = Wf_sn_cf_Utils::get_ai_crawler_cidrs_for_feed_url( $feed_url );
				foreach ( $cidrs as $cidr ) {
					if ( Wf_sn_cf_Utils::ipCIDRMatch( $testip, $cidr ) ) {
						Wf_sn_cf_Utils::remember_validated_crawler( $testip );
						wf_sn_el_modules::log_event(
							'security_ninja',
							'validated_crawler_ip',
							__( 'Valid AI crawler (published IP ranges)', 'security-ninja' ),
							array(
								'feed' => $feed_url,
								'ua'   => $ua,
							),
							null,
							$testip
						);
						return true;
					}
				}
			}
			// AI UA did not match published ranges; do not fall through to PTR.
			return false;
		}

		// Classic crawlers: only reverse-DNS when UA claims to be one.
		if ( ! Wf_sn_cf_Utils::ua_looks_like_classic_crawler( $ua ) ) {
			return false;
		}

		$hostname         = wf_sn_cf::get_visitor_hostname( $testip );
		$valid_host_names = Wf_sn_cf_Utils::get_classic_crawler_host_suffixes();

		foreach ( $valid_host_names as $valid_host ) {
			if ( Wf_sn_cf_Utils::string_ends_with( $hostname, $valid_host ) ) {
				$returned_ip = gethostbyname( $hostname );
				if ( $returned_ip === $testip ) {
					Wf_sn_cf_Utils::remember_validated_crawler( $testip );
					wf_sn_el_modules::log_event( 'security_ninja', 'validated_crawler_ip', 'Valid Crawler' . esc_attr( $hostname ), '', '', esc_attr( $testip ) );
					return true;
				}
			}
		}

		return false;
	}




/**
	 * Checks if an IP is from a service that has been enabled
	 *
	 * This method checks if the given IP address is whitelisted for services such as Broken Link Checker, GetTerms, WP Rocket, ManageWP, UptimeRobot, WP Compress, and MonSpark.
	 * It also checks for IP ranges (CIDR) in the whitelist.
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, May 8th, 2024.
	 * @access  public static
	 * @param   mixed   $current_user_ip    The IP address to check against the whitelist.
	 * @return  boolean                 Returns true if the IP is whitelisted, false otherwise.
	 */
	public static function is_whitelisted_service( $current_user_ip ) {
		$whitelist_brokenlink = array(
			'94.231.107.9', // Broken Link Checker
			'54.191.137.17', // Broken Link Checker
		);

		// GetTerms cookie scanner — always whitelisted (getterms.io).
		$whitelist_getterms = array(
			'45.55.125.144', // GetTerms cookie scanner
		);
		$whitelist_wprocket = array();
		if ( isset( wf_sn_cf::$options['whitelist_wprocket'] ) && wf_sn_cf::$options['whitelist_wprocket'] ) {
			$whitelist_wprocket = array(
				'109.234.160.58', // WP Rocket - Load CSS async
				'51.83.15.135', // WP Rocket - Load CSS async
				'51.210.39.196', // WP Rocket - Load CSS async
				'146.59.192.120', // WP Rocket - license validation
				'135.125.83.227', // WP Rocket - Remove unused CSS
				'146.59.251.59', // WP Rocket - RocketCDN
			);
		}

		$extra_whitelist = array(
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
		);

		// Keep this as a static list. Reverse-DNS matching here would add a DNS
		// lookup to ordinary visitor requests on sites without an object cache.
		$whitelist_wpcompress = array(
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
			'109.224.229.186',
			'109.224.229.188',
			'109.224.229.192',
			'109.224.229.241',
			'109.224.230.12',
			'109.224.230.19',
			'2a01:4f8:251:a11::/64',
			'2605:9f80:c000:240::2/64',
			'2605:9f80:1000:461::2/64',
			'2402:1f00:8001:11a3::/64',
			'2402:1f00:8201:486::/64',
			'2a01:4f8:a0:90d5::/64',
			'2a01:4f8:c012:bb07::/64',
			'2a01:4f8:222:1059::/64',
			'2a01:4f8:10a:3a47::/64',
		);

		// Hardcoded, not an option - always whitelisted.
		$whitelist_modulards = array(
			'54.220.170.248/32',
			'34.249.165.39/32',
			'63.34.51.157/32',
			'54.73.153.210/32',
			'52.210.126.224/32',
		);

		// MonSpark uptime monitoring — always whitelisted (see docs.monspark.com IP whitelisting).
		$whitelist_monspark = array(
			'51.15.238.191',   // EU
			'51.15.192.231',   // EU
			'85.111.66.59',    // EU
			'15.235.41.103',   // US
			'148.113.138.118', // US
			'51.79.143.61',    // APAC
			'135.125.246.37',  // EU (legacy)
			'57.129.32.158',   // EU (legacy)
		);

		$whitelist_managewp = array();
		if ( isset( wf_sn_cf::$options['whitelist_managewp'] ) && wf_sn_cf::$options['whitelist_managewp'] ) {
			$whitelist_managewp = self::load_ip_whitelist( 'whitelist-managewp.json' );
		}

		$whitelist_uptimia = array();
		if ( isset( wf_sn_cf::$options['whitelist_uptimia'] ) && wf_sn_cf::$options['whitelist_uptimia'] ) {
			$whitelist_uptimia = self::load_ip_whitelist( 'whitelist-uptimia.json' );
		}

		$whitelist_uptimerobot = array();
		if ( isset( wf_sn_cf::$options['whitelist_uptimerobot'] ) && wf_sn_cf::$options['whitelist_uptimerobot'] ) {
			$whitelist_uptimerobot = self::load_ip_whitelist( 'whitelist-uptimerobot.json' );
		}

		$whitelist = array_merge( $whitelist_brokenlink, $whitelist_getterms, $whitelist_wprocket, $whitelist_managewp, $whitelist_uptimia, $whitelist_wpcompress, $extra_whitelist, $whitelist_uptimerobot, $whitelist_modulards, $whitelist_monspark );

		foreach ( $whitelist as $whitelist_item ) {
			// Check if the current whitelist item is an IP range (CIDR)
			if ( strpos( $whitelist_item, '/' ) !== false ) {
				// Use the proper CIDR matching function
				if ( Wf_sn_cf_Utils::ipCIDRMatch( $current_user_ip, $whitelist_item ) ) {
					return true; // IP is whitelisted
				}
			} elseif ( $current_user_ip === $whitelist_item ) {
					return true; // IP is whitelisted

			}
		}
		return false; // IP is not whitelisted
	}




/**
	 * Loads an IP whitelist from a bundled JSON data file.
	 *
	 * The service whitelist data files (ManageWP, UptimeRobot, Uptimia) contain a
	 * plain JSON array of IP addresses and CIDR ranges. They are shipped as JSON
	 * data rather than executable PHP so that security scanners do not mistake a
	 * static list of IPs for obfuscated/concealed code.
	 *
	 * @author  Lars Koudal
	 * @since   v5.290
	 * @access  private static
	 * @param   string $filename  Filename of the JSON file inside modules/cloud-firewall/.
	 * @return  array             Array of IP/CIDR strings, or empty array on failure.
	 */
	private static function load_ip_whitelist( $filename ) {
		static $cache = array();

		$filename = basename( $filename );
		if ( isset( $cache[ $filename ] ) ) {
			return $cache[ $filename ];
		}

		$path = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/' . $filename;

		if ( ! is_readable( $path ) ) {
			$cache[ $filename ] = array();
			return $cache[ $filename ];
		}

		$contents = file_get_contents( $path );
		if ( false === $contents || '' === $contents ) {
			$cache[ $filename ] = array();
			return $cache[ $filename ];
		}

		$decoded = json_decode( $contents, true );
		if ( ! is_array( $decoded ) ) {
			$cache[ $filename ] = array();
			return $cache[ $filename ];
		}

		$ips = array();
		foreach ( $decoded as $entry ) {
			if ( ! is_string( $entry ) ) {
				continue;
			}
			$entry = trim( $entry );
			if ( '' !== $entry ) {
				$ips[] = $entry;
			}
		}

		$cache[ $filename ] = $ips;
		return $cache[ $filename ];
	}


}
