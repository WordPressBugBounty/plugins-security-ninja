<?php
/**
 * Deterministic next-best-action / priority resolver (no AI required).
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin;

use function WPSecurityNinja\Plugin\secnin_fs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Priority_Resolver
 */
class Wf_Sn_Priority_Resolver {

	const MAX_ITEMS = 5;

	/**
	 * Return ordered priority actions.
	 *
	 * @param int $limit Max items.
	 * @return array<int, array{id: string, title: string, severity: string, source: string, summary: string, action_url: string, action_text: string}>
	 */
	public static function get( $limit = self::MAX_ITEMS ) {
		$limit  = max( 1, min( 10, (int) $limit ) );
		$items  = array();
		$recent = (int) apply_filters( 'wf_sn_ai_advisor_recent_days', 7 );
		$recent = max( 1, min( 90, $recent ) );

		self::maybe_add_vulnerabilities( $items );
		self::maybe_add_malware( $items );
		self::maybe_add_core_scanner( $items );
		self::maybe_add_failed_tests( $items );
		self::maybe_add_login_protection( $items );
		self::maybe_add_firewall( $items );
		self::maybe_add_updates( $items );
		self::maybe_add_login_errors( $items );
		self::maybe_add_scheduled_scans( $items );
		self::maybe_add_stale_scans( $items, $recent );

		$items = array_slice( $items, 0, $limit );

		/**
		 * Filter deterministic priority actions.
		 *
		 * @param array $items Priority items.
		 * @param int   $limit Requested limit.
		 */
		return (array) apply_filters( 'wf_sn_priority_resolver_items', $items, $limit );
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_vulnerabilities( array &$items ) {
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Vu' ) ) {
			return;
		}
		$vu = Wf_Sn_Vu::get_scan_summary();
		if ( empty( $vu['has_vulnerabilities'] ) ) {
			return;
		}
		$count = isset( $vu['vuln_count'] ) ? (int) $vu['vuln_count'] : 0;
		if ( $count <= 0 ) {
			return;
		}
		$items[] = array(
			'id'          => 'known_vulnerabilities',
			'title'       => __( 'Review known vulnerabilities', 'security-ninja' ),
			'severity'    => 'high',
			'source'      => 'vulnerabilities',
			'summary'     => sprintf(
				/* translators: %d: vulnerability count */
				_n( '%d known vulnerability needs attention.', '%d known vulnerabilities need attention.', $count, 'security-ninja' ),
				$count
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'vulnerabilities' ),
			'action_text' => __( 'Open vulnerability scanner', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_malware( array &$items ) {
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Ms' ) ) {
			return;
		}
		$count = (int) Wf_Sn_Ms::count_suspicious_files();
		if ( $count <= 0 ) {
			return;
		}
		$items[] = array(
			'id'          => 'malware_suspicious',
			'title'       => __( 'Review suspicious files', 'security-ninja' ),
			'severity'    => 'high',
			'source'      => 'malware',
			'summary'     => sprintf(
				/* translators: %d: file count */
				_n( '%d suspicious file flagged by the malware scanner.', '%d suspicious files flagged by the malware scanner.', $count, 'security-ninja' ),
				$count
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'malware' ),
			'action_text' => __( 'Open malware scanner', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_core_scanner( array &$items ) {
		if ( ! class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Cs_Utils' ) ) {
			require_once WF_SN_PLUGIN_DIR . 'modules/core-scanner/class-wf-sn-cs-utils.php';
		}
		$results = \WPSecurityNinja\Plugin\Wf_Sn_Cs_Utils::get_scan_results( array() );
		if ( ! is_array( $results ) ) {
			return;
		}
		$bad = 0;
		foreach ( array( 'changed_bad', 'missing_bad', 'unknown_bad' ) as $key ) {
			if ( ! empty( $results[ $key ] ) && is_array( $results[ $key ] ) ) {
				$bad += count( $results[ $key ] );
			}
		}
		if ( $bad <= 0 ) {
			return;
		}
		$items[] = array(
			'id'          => 'core_scanner_issues',
			'title'       => __( 'Review core file issues', 'security-ninja' ),
			'severity'    => 'high',
			'source'      => 'core_scanner',
			'summary'     => sprintf(
				/* translators: %d: issue count */
				_n( '%d core file issue needs review.', '%d core file issues need review.', $bad, 'security-ninja' ),
				$bad
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'core_scanner' ),
			'action_text' => __( 'Open core scanner', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_failed_tests( array &$items ) {
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
			return;
		}
		$scores = Wf_Sn::return_test_scores();
		$bad    = isset( $scores['bad'] ) ? (int) $scores['bad'] : 0;
		if ( $bad <= 0 ) {
			return;
		}
		$items[] = array(
			'id'          => 'failed_security_tests',
			'title'       => __( 'Fix high-priority security tests', 'security-ninja' ),
			'severity'    => 'high',
			'source'      => 'security_tests',
			'summary'     => sprintf(
				/* translators: %d: failed test count */
				_n( '%d security test is failing.', '%d security tests are failing.', $bad, 'security-ninja' ),
				$bad
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'tests' ),
			'action_text' => __( 'Open security tests', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_login_protection( array &$items ) {
		$flags = Wf_Sn_Security_Snapshot::get_feature_flags();
		if ( ! empty( $flags['two_factor_enabled'] ) && ! empty( $flags['login_protection_enabled'] ) ) {
			return;
		}
		$issues = array();
		if ( empty( $flags['login_protection_enabled'] ) ) {
			$issues[] = __( 'login protection is not enabled', 'security-ninja' );
		}
		if ( empty( $flags['two_factor_enabled'] ) ) {
			$issues[] = __( '2FA is not enabled for admin users', 'security-ninja' );
		}
		if ( empty( $issues ) ) {
			return;
		}
		$items[] = array(
			'id'          => 'login_protection',
			'title'       => __( 'Strengthen login protection', 'security-ninja' ),
			'severity'    => 'medium',
			'source'      => 'login',
			'summary'     => ucfirst( implode( '; ', $issues ) ) . '.',
			'action_url'  => Wf_Sn_Admin_Links::url( 'login', Wf_Sn_Admin_Links::url( 'firewall' ) ),
			'action_text' => __( 'Open login protection', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_firewall( array &$items ) {
		$flags = Wf_Sn_Security_Snapshot::get_feature_flags();
		if ( ! empty( $flags['firewall_enabled'] ) ) {
			return;
		}
		$items[] = array(
			'id'          => 'firewall_disabled',
			'title'       => __( 'Enable the firewall', 'security-ninja' ),
			'severity'    => 'medium',
			'source'      => 'firewall',
			'summary'     => __( 'The cloud firewall is currently disabled.', 'security-ninja' ),
			'action_url'  => Wf_Sn_Admin_Links::url( 'firewall' ),
			'action_text' => __( 'Open firewall', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_updates( array &$items ) {
		$counts = Wf_Sn_Security_Snapshot::get_update_counts();
		$total  = (int) $counts['total'];
		if ( $total <= 0 ) {
			return;
		}
		$parts = array();
		if ( $counts['plugins'] > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: plugin count */
				_n( '%d plugin', '%d plugins', $counts['plugins'], 'security-ninja' ),
				$counts['plugins']
			);
		}
		if ( $counts['themes'] > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: theme count */
				_n( '%d theme', '%d themes', $counts['themes'], 'security-ninja' ),
				$counts['themes']
			);
		}
		if ( $counts['core'] > 0 ) {
			$parts[] = __( 'WordPress core', 'security-ninja' );
		}
		$items[] = array(
			'id'          => 'update_plugins',
			'title'       => __( 'Review available updates', 'security-ninja' ),
			'severity'    => 'medium',
			'source'      => 'updates',
			'summary'     => sprintf(
				/* translators: 1: total updates, 2: breakdown */
				__( '%1$d updates available: %2$s.', 'security-ninja' ),
				$total,
				implode( ', ', $parts )
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'updates' ),
			'action_text' => __( 'View update details', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_login_errors( array &$items ) {
		global $wpdb;
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_El' ) || ! Wf_Sn_El::is_active() ) {
			return;
		}
		$table = $wpdb->prefix . 'wf_sn_el';
		$failed = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE action = %s AND timestamp >= DATE_SUB( NOW(), INTERVAL 7 DAY )", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				'wp_login_failed'
			)
		);
		if ( $failed <= 0 ) {
			return;
		}
		$items[] = array(
			'id'          => 'login_errors',
			'title'       => __( 'Review recent login activity', 'security-ninja' ),
			'severity'    => 'low',
			'source'      => 'events',
			'summary'     => sprintf(
				/* translators: %d: failed login count */
				_n( '%d failed login attempt recorded in the last 7 days.', '%d failed login attempts recorded in the last 7 days.', $failed, 'security-ninja' ),
				$failed
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'events' ),
			'action_text' => __( 'View events', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 */
	private static function maybe_add_scheduled_scans( array &$items ) {
		if ( ! class_exists( __NAMESPACE__ . '\\wf_sn_ss' ) ) {
			return;
		}
		$opts = get_option( 'wf_sn_ss', array() );
		if ( ! is_array( $opts ) ) {
			return;
		}
		if ( ! empty( $opts['active'] ) ) {
			return;
		}
		$items[] = array(
			'id'          => 'scheduled_scans',
			'title'       => __( 'Configure scheduled scans', 'security-ninja' ),
			'severity'    => 'low',
			'source'      => 'scheduler',
			'summary'     => __( 'Scheduled security scans are not configured.', 'security-ninja' ),
			'action_url'  => Wf_Sn_Admin_Links::url( 'scheduler' ),
			'action_text' => __( 'Open scheduler', 'security-ninja' ),
		);
	}

	/**
	 * @param array<int, array<string, string>> $items Items list (by ref).
	 * @param int                               $recent Days threshold for "recent".
	 */
	private static function maybe_add_stale_scans( array &$items, $recent ) {
		$stale = array();
		$cutoff = time() - ( $recent * DAY_IN_SECONDS );

		$results = get_option( 'wf_sn_results', array() );
		if ( is_array( $results ) && ! empty( $results['last_run'] ) ) {
			if ( (int) $results['last_run'] < $cutoff ) {
				$stale[] = __( 'security tests', 'security-ninja' );
			}
		} elseif ( class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
			$scores = Wf_Sn::return_test_scores();
			if ( 0 === (int) $scores['score'] && 0 === (int) $scores['good'] && 0 === (int) $scores['bad'] ) {
				$stale[] = __( 'security tests', 'security-ninja' );
			}
		}

		$cache_ts = (int) get_option( 'wf_sn_vulnerabilities_cache_timestamp', 0 );
		if ( $cache_ts > 0 && $cache_ts < $cutoff ) {
			$stale[] = __( 'vulnerability scan', 'security-ninja' );
		}

		if ( ! class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Cs_Utils' ) ) {
			require_once WF_SN_PLUGIN_DIR . 'modules/core-scanner/class-wf-sn-cs-utils.php';
		}
		$cs = \WPSecurityNinja\Plugin\Wf_Sn_Cs_Utils::get_scan_results( array() );
		if ( is_array( $cs ) && ! empty( $cs['last_run'] ) && (int) $cs['last_run'] < $cutoff ) {
			$stale[] = __( 'core scanner', 'security-ninja' );
		}

		if ( empty( $stale ) ) {
			return;
		}
		$items[] = array(
			'id'          => 'stale_scan_data',
			'title'       => __( 'Refresh stale scan data', 'security-ninja' ),
			'severity'    => 'low',
			'source'      => 'scanning',
			'summary'     => sprintf(
				/* translators: %s: comma-separated scan names */
				__( 'These scans have not run recently: %s.', 'security-ninja' ),
				implode( ', ', $stale )
			),
			'action_url'  => Wf_Sn_Admin_Links::url( 'tests' ),
			'action_text' => __( 'Run recommended scans', 'security-ninja' ),
		);
	}
}
