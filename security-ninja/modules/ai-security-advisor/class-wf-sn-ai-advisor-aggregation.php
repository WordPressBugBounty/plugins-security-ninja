<?php
/**
 * AI Security Advisor – aggregated event counts from wf_sn_el.
 *
 * Provides blocked_logins_7d, xmlrpc_blocks_7d, firewall_events_7d for the privacy-safe payload.
 * Results cached via transient to avoid repeated heavy queries.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Aggregation
 */
class Wf_Sn_Ai_Advisor_Aggregation {

	const TRANSIENT_PREFIX = 'wf_sn_ai_advisor_agg_';
	const CACHE_TTL        = 600; // 10 minutes.

	/**
	 * Get counts for the last 7 days. Uses transient cache.
	 *
	 * @return array{blocked_logins_7d: int, xmlrpc_blocks_7d: int, firewall_events_7d: int, failed_logins_7d: int}
	 */
	public static function get_counts_7d() {
		$key    = self::TRANSIENT_PREFIX . '7d';
		$cached = get_transient( $key );
		if ( is_array( $cached ) && isset( $cached['blocked_logins_7d'], $cached['xmlrpc_blocks_7d'], $cached['firewall_events_7d'], $cached['failed_logins_7d'] ) ) {
			return $cached;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'wf_sn_el';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days' ) );

		// Table may not exist on fresh installs.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			$result = array(
				'blocked_logins_7d'  => 0,
				'xmlrpc_blocks_7d'   => 0,
				'firewall_events_7d' => 0,
				'failed_logins_7d'   => 0,
			);
			set_transient( $key, $result, self::CACHE_TTL );
			return $result;
		}

		$blocked_logins_actions = array(
			'login_form_blocked_ip',
			'login_denied_banned_IP',
			'firewall_ip_banned',
			'firewall_ip_banned_lost_password',
			'login_error',
		);
		$placeholders_blocked   = implode( ', ', array_fill( 0, count( $blocked_logins_actions ), '%s' ) );

		$firewall_actions      = array(
			'do_init_action',
			'blocked_ip_banned',
			'blocked_ip_country_ban',
			'blocked_ip_suspicious_request',
			'blacklisted_IP',
		);
		$placeholders_firewall = implode( ', ', array_fill( 0, count( $firewall_actions ), '%s' ) );

		$blocked_logins_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($placeholders_blocked) AND timestamp >= %s",
				array_merge( $blocked_logins_actions, array( $since ) )
			)
		);

		$xmlrpc_blocks_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'xmlrpc_pingback_blocked' AND timestamp >= %s",
				$since
			)
		);

		$firewall_events_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($placeholders_firewall) AND timestamp >= %s",
				array_merge( $firewall_actions, array( $since ) )
			)
		);

		$failed_logins_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'wp_login_failed' AND timestamp >= %s",
				$since
			)
		);

		$result = array(
			'blocked_logins_7d'  => $blocked_logins_7d,
			'xmlrpc_blocks_7d'   => $xmlrpc_blocks_7d,
			'firewall_events_7d' => $firewall_events_7d,
			'failed_logins_7d'   => $failed_logins_7d,
		);
		set_transient( $key, $result, self::CACHE_TTL );
		return $result;
	}

	/**
	 * Get counts for the previous 7-day window (from -14 days to -7 days).
	 *
	 * @return array{blocked_logins_prev_7d: int, xmlrpc_blocks_prev_7d: int, firewall_events_prev_7d: int, failed_logins_prev_7d: int}
	 */
	public static function get_counts_prev_7d() {
		$key    = self::TRANSIENT_PREFIX . 'prev7d';
		$cached = get_transient( $key );
		if ( is_array( $cached ) && isset( $cached['blocked_logins_prev_7d'], $cached['xmlrpc_blocks_prev_7d'], $cached['firewall_events_prev_7d'], $cached['failed_logins_prev_7d'] ) ) {
			return $cached;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'wf_sn_el';
		$end   = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days' ) );
		$start = gmdate( 'Y-m-d H:i:s', strtotime( '-14 days' ) );

		// Table may not exist on fresh installs.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			$result = array(
				'blocked_logins_prev_7d'  => 0,
				'xmlrpc_blocks_prev_7d'   => 0,
				'firewall_events_prev_7d' => 0,
				'failed_logins_prev_7d'   => 0,
			);
			set_transient( $key, $result, self::CACHE_TTL );
			return $result;
		}

		$blocked_logins_actions = array(
			'login_form_blocked_ip',
			'login_denied_banned_IP',
			'firewall_ip_banned',
			'firewall_ip_banned_lost_password',
			'login_error',
		);
		$placeholders_blocked   = implode( ', ', array_fill( 0, count( $blocked_logins_actions ), '%s' ) );

		$firewall_actions      = array(
			'do_init_action',
			'blocked_ip_banned',
			'blocked_ip_country_ban',
			'blocked_ip_suspicious_request',
			'blacklisted_IP',
		);
		$placeholders_firewall = implode( ', ', array_fill( 0, count( $firewall_actions ), '%s' ) );

		$blocked_logins_prev_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($placeholders_blocked) AND timestamp >= %s AND timestamp < %s",
				array_merge( $blocked_logins_actions, array( $start, $end ) )
			)
		);

		$xmlrpc_blocks_prev_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'xmlrpc_pingback_blocked' AND timestamp >= %s AND timestamp < %s",
				$start,
				$end
			)
		);

		$firewall_events_prev_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($placeholders_firewall) AND timestamp >= %s AND timestamp < %s",
				array_merge( $firewall_actions, array( $start, $end ) )
			)
		);

		$failed_logins_prev_7d = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'wp_login_failed' AND timestamp >= %s AND timestamp < %s",
				$start,
				$end
			)
		);

		$result = array(
			'blocked_logins_prev_7d'  => $blocked_logins_prev_7d,
			'xmlrpc_blocks_prev_7d'   => $xmlrpc_blocks_prev_7d,
			'firewall_events_prev_7d' => $firewall_events_prev_7d,
			'failed_logins_prev_7d'   => $failed_logins_prev_7d,
		);
		set_transient( $key, $result, self::CACHE_TTL );
		return $result;
	}
}
