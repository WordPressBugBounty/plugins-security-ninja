<?php
/**
 * AI Security Advisor – data readiness panel (non-AI).
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

use WPSecurityNinja\Plugin\Wf_Sn_Admin_Links;
use WPSecurityNinja\Plugin\Wf_Sn_Security_Snapshot;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Readiness
 */
class Wf_Sn_Ai_Advisor_Readiness {

	/**
	 * Build readiness rows for the Advisor page.
	 *
	 * @return array<int, array{key: string, label: string, status: string, detail: string}>
	 */
	public static function get_items() {
		$recent  = (int) apply_filters( 'wf_sn_ai_advisor_recent_days', 7 );
		$recent  = max( 1, min( 90, $recent ) );
		$cutoff  = time() - ( $recent * DAY_IN_SECONDS );
		$items   = array();

		$scores = array(
		'score' => 0,
		'good' => 0,
		'bad' => 0,
		'warning' => 0
		);
		if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn' ) ) {
			$scores = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
		}
		$has_tests = ( (int) $scores['good'] + (int) $scores['bad'] + (int) $scores['warning'] ) > 0;
		$items[]   = array(
			'key'    => 'security_tests',
			'label'  => __( 'Security tests', 'security-ninja' ),
			'status' => $has_tests ? 'ready' : 'missing',
			'detail' => $has_tests ? __( 'Available', 'security-ninja' ) : __( 'Not run yet', 'security-ninja' ),
		);

		$vuln_ready = false;
		if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Vu' ) ) {
			$ts = (int) get_option( 'wf_sn_vulnerabilities_cache_timestamp', 0 );
			$vuln_ready = $ts >= $cutoff;
		}
		$items[] = array(
			'key'    => 'vulnerability_scan',
			'label'  => __( 'Vulnerability scan', 'security-ninja' ),
			'status' => $vuln_ready ? 'ready' : 'stale',
			'detail' => $vuln_ready ? __( 'Available', 'security-ninja' ) : __( 'Not run recently', 'security-ninja' ),
		);

		$flags = Wf_Sn_Security_Snapshot::get_feature_flags();
		$items[] = array(
			'key'    => 'firewall',
			'label'  => __( 'Firewall / event activity', 'security-ninja' ),
			'status' => ! empty( $flags['firewall_enabled'] ) ? 'ready' : 'stale',
			'detail' => ! empty( $flags['firewall_enabled'] ) ? __( 'Firewall enabled', 'security-ninja' ) : __( 'Firewall disabled', 'security-ninja' ),
		);

		$login_ready = class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_El' ) && \WPSecurityNinja\Plugin\Wf_Sn_El::is_active();
		$items[] = array(
			'key'    => 'login_activity',
			'label'  => __( 'Login activity', 'security-ninja' ),
			'status' => $login_ready ? 'ready' : 'stale',
			'detail' => $login_ready ? __( 'Event logging active', 'security-ninja' ) : __( 'Event logging inactive', 'security-ninja' ),
		);

		$cs = get_option( 'wf_sn_cs_results', array() );
		$cs_last = is_array( $cs ) && ! empty( $cs['last_run'] ) ? (int) $cs['last_run'] : 0;
		$items[] = array(
			'key'    => 'core_scanner',
			'label'  => __( 'Core scanner', 'security-ninja' ),
			'status' => ( $cs_last >= $cutoff ) ? 'ready' : 'stale',
			'detail' => ( $cs_last >= $cutoff ) ? __( 'Run recently', 'security-ninja' ) : __( 'Not run recently', 'security-ninja' ),
		);

		$ms_last = 0;
		if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Ms' ) ) {
			$ms_all = \WPSecurityNinja\Plugin\Wf_Sn_Ms::get_results();
			if ( is_array( $ms_all ) && ! empty( $ms_all['last_run'] ) ) {
				$ms_last = (int) $ms_all['last_run'];
			}
		}
		if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Ms' ) ) {
			$items[] = array(
				'key'    => 'malware_scanner',
				'label'  => __( 'Malware scan', 'security-ninja' ),
				'status' => ( $ms_last >= $cutoff ) ? 'ready' : 'stale',
				'detail' => ( $ms_last >= $cutoff ) ? __( 'Run recently', 'security-ninja' ) : __( 'Not run recently', 'security-ninja' ),
			);
		}

		return $items;
	}

	/**
	 * Whether any critical data source is missing.
	 *
	 * @return bool
	 */
	public static function is_limited_data() {
		foreach ( self::get_items() as $item ) {
			if ( 'missing' === $item['status'] || 'stale' === $item['status'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * URL to run recommended scans (tests tab).
	 *
	 * @return string
	 */
	public static function recommended_scans_url() {
		return Wf_Sn_Admin_Links::url( 'tests' );
	}
}
