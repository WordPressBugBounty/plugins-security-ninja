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
	 * Event logger actions counted as blocked login activity.
	 */
	const BLOCKED_LOGINS_ACTIONS = array(
		'login_form_blocked_ip',
		'login_denied_banned_IP',
		'firewall_ip_banned',
		'firewall_ip_banned_lost_password',
		'login_error',
	);

	/**
	 * Event logger actions counted as firewall events.
	 */
	const FIREWALL_ACTIONS = array(
		'do_init_action',
		'blocked_ip_banned',
		'blocked_ip_country_ban',
		'blocked_ip_suspicious_request',
		'blacklisted_IP',
	);

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

		$since  = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days' ) );
		$raw    = self::query_counts_for_window( $since, null );
		$result = array(
			'blocked_logins_7d'  => $raw['blocked_logins'],
			'xmlrpc_blocks_7d'   => $raw['xmlrpc_blocks'],
			'firewall_events_7d' => $raw['firewall_events'],
			'failed_logins_7d'   => $raw['failed_logins'],
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

		$end    = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days' ) );
		$start  = gmdate( 'Y-m-d H:i:s', strtotime( '-14 days' ) );
		$raw    = self::query_counts_for_window( $start, $end );
		$result = array(
			'blocked_logins_prev_7d'  => $raw['blocked_logins'],
			'xmlrpc_blocks_prev_7d'   => $raw['xmlrpc_blocks'],
			'firewall_events_prev_7d' => $raw['firewall_events'],
			'failed_logins_prev_7d'   => $raw['failed_logins'],
		);
		set_transient( $key, $result, self::CACHE_TTL );
		return $result;
	}

	/**
	 * Query the four count buckets for a time window.
	 *
	 * @param string      $start Inclusive start (Y-m-d H:i:s).
	 * @param string|null $end   Exclusive end, or null for open-ended (>= start only).
	 * @return array{blocked_logins: int, xmlrpc_blocks: int, firewall_events: int, failed_logins: int}
	 */
	private static function query_counts_for_window( $start, $end ) {
		$empty = array(
			'blocked_logins'  => 0,
			'xmlrpc_blocks'   => 0,
			'firewall_events' => 0,
			'failed_logins'   => 0,
		);

		global $wpdb;
		$table = $wpdb->prefix . 'wf_sn_el';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return $empty;
		}

		$blocked_placeholders = implode( ', ', array_fill( 0, count( self::BLOCKED_LOGINS_ACTIONS ), '%s' ) );
		$firewall_placeholders = implode( ', ', array_fill( 0, count( self::FIREWALL_ACTIONS ), '%s' ) );

		$blocked_logins = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($blocked_placeholders) AND timestamp >= %s" . ( null !== $end ? ' AND timestamp < %s' : '' ),
				self::merge_window_args( self::BLOCKED_LOGINS_ACTIONS, $start, $end )
			)
		);

		$xmlrpc_blocks = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'xmlrpc_pingback_blocked' AND timestamp >= %s" . ( null !== $end ? ' AND timestamp < %s' : '' ),
				self::merge_window_args( array(), $start, $end )
			)
		);

		$firewall_events = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action IN ($firewall_placeholders) AND timestamp >= %s" . ( null !== $end ? ' AND timestamp < %s' : '' ),
				self::merge_window_args( self::FIREWALL_ACTIONS, $start, $end )
			)
		);

		$failed_logins = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE module = 'security_ninja' AND action = 'wp_login_failed' AND timestamp >= %s" . ( null !== $end ? ' AND timestamp < %s' : '' ),
				self::merge_window_args( array(), $start, $end )
			)
		);

		return array(
			'blocked_logins'  => $blocked_logins,
			'xmlrpc_blocks'   => $xmlrpc_blocks,
			'firewall_events' => $firewall_events,
			'failed_logins'   => $failed_logins,
		);
	}

	/**
	 * Build $wpdb->prepare argument list: actions (if any), start, optional end.
	 *
	 * @param array       $actions Action slugs for IN clause.
	 * @param string      $start   Window start.
	 * @param string|null $end     Window end or null.
	 * @return array<int|string>
	 */
	private static function merge_window_args( array $actions, $start, $end ) {
		$args = array_merge( $actions, array( $start ) );
		if ( null !== $end ) {
			$args[] = $end;
		}
		return $args;
	}
}
