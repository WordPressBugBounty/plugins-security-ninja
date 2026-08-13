<?php
/**
 * Compare two security snapshots for "What changed" cards.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Security_Snapshot_Diff
 */
class Wf_Sn_Security_Snapshot_Diff {

	/**
	 * Compare current vs previous snapshot.
	 *
	 * @param array<string, mixed>|null $current  Current snapshot.
	 * @param array<string, mixed>|null $previous Previous snapshot.
	 * @return array{new: string[], improved: string[], needs_attention: string[], has_comparison: bool}
	 */
	public static function compare( $current, $previous ) {
		$out = array(
			'new'              => array(),
			'improved'         => array(),
			'needs_attention'  => array(),
			'has_comparison'   => false,
		);

		if ( ! is_array( $current ) || ! is_array( $previous ) ) {
			return $out;
		}

		$out['has_comparison'] = true;

		$cur_updates = (int) ( $current['update_total'] ?? 0 );
		$prev_updates = (int) ( $previous['update_total'] ?? 0 );
		if ( $cur_updates > $prev_updates ) {
			$diff = $cur_updates - $prev_updates;
			$out['new'][] = sprintf(
				/* translators: %d: number of new updates */
				_n( '%d plugin or theme update became available.', '%d plugin or theme updates became available.', $diff, 'security-ninja' ),
				$diff
			);
		}

		if ( ! empty( $current['woocommerce_active'] ) && empty( $previous['woocommerce_active'] ) ) {
			$out['new'][] = __( 'WooCommerce was activated.', 'security-ninja' );
		}

		$cur_failed = isset( $current['failed_test_ids'] ) && is_array( $current['failed_test_ids'] ) ? $current['failed_test_ids'] : array();
		$prev_failed = isset( $previous['failed_test_ids'] ) && is_array( $previous['failed_test_ids'] ) ? $previous['failed_test_ids'] : array();
		$new_failed = array_diff( $cur_failed, $prev_failed );
		if ( ! empty( $new_failed ) ) {
			$out['new'][] = sprintf(
				/* translators: %d: count */
				_n( '%d new security test failure.', '%d new security test failures.', count( $new_failed ), 'security-ninja' ),
				count( $new_failed )
			);
		}
		$still_failed = array_intersect( $cur_failed, $prev_failed );
		if ( ! empty( $still_failed ) ) {
			$out['needs_attention'][] = sprintf(
				/* translators: %d: count */
				_n( '%d high-priority security test still failing.', '%d high-priority security tests still failing.', count( $still_failed ), 'security-ninja' ),
				count( $still_failed )
			);
		}

		$cur_vuln = (int) ( $current['vulnerability_count'] ?? 0 );
		$prev_vuln = (int) ( $previous['vulnerability_count'] ?? 0 );
		if ( $cur_vuln > $prev_vuln ) {
			$out['new'][] = sprintf(
				/* translators: %d: count */
				_n( '%d new known vulnerability.', '%d new known vulnerabilities.', $cur_vuln - $prev_vuln, 'security-ninja' ),
				$cur_vuln - $prev_vuln
			);
		} elseif ( $prev_vuln > 0 && 0 === $cur_vuln ) {
			$out['improved'][] = __( 'No known vulnerabilities found.', 'security-ninja' );
		}

		$cur_core = (int) ( $current['core_scanner_issues'] ?? 0 );
		$prev_core = (int) ( $previous['core_scanner_issues'] ?? 0 );
		if ( $cur_core > $prev_core ) {
			$out['new'][] = __( 'Core scanner found new file issues.', 'security-ninja' );
		} elseif ( $prev_core > 0 && 0 === $cur_core ) {
			$out['improved'][] = __( 'Core scanner issues were resolved.', 'security-ninja' );
		}

		$cur_mal = (int) ( $current['malware_issues'] ?? 0 );
		$prev_mal = (int) ( $previous['malware_issues'] ?? 0 );
		if ( $cur_mal > $prev_mal ) {
			$out['new'][] = __( 'Malware scanner flagged new suspicious files.', 'security-ninja' );
		} elseif ( $prev_mal > 0 && 0 === $cur_mal ) {
			$out['improved'][] = __( 'Malware scanner no longer reports suspicious files.', 'security-ninja' );
		}

		$resolved_failed = array_diff( $prev_failed, $cur_failed );
		if ( ! empty( $resolved_failed ) ) {
			$out['improved'][] = sprintf(
				/* translators: %d: count */
				_n( '%d security test now passing.', '%d security tests now passing.', count( $resolved_failed ), 'security-ninja' ),
				count( $resolved_failed )
			);
		}

		if ( empty( $current['firewall_enabled'] ) && ! empty( $previous['firewall_enabled'] ) ) {
			$out['needs_attention'][] = __( 'Firewall was disabled.', 'security-ninja' );
		}
		if ( ! empty( $current['firewall_enabled'] ) && empty( $previous['firewall_enabled'] ) ) {
			$out['improved'][] = __( 'Firewall is now enabled.', 'security-ninja' );
		}

		if ( $cur_updates > 0 && $prev_updates === $cur_updates ) {
			$out['needs_attention'][] = sprintf(
				/* translators: %d: update count */
				_n( '%d update still available.', '%d updates still available.', $cur_updates, 'security-ninja' ),
				$cur_updates
			);
		}

		/**
		 * Filter diff output before display.
		 *
		 * @param array $out      Diff buckets.
		 * @param array $current  Current snapshot.
		 * @param array $previous Previous snapshot.
		 */
		return (array) apply_filters( 'wf_sn_security_snapshot_diff', $out, $current, $previous );
	}

	/**
	 * Build diff for Overview: current cached snapshot vs latest AI report snapshot.
	 *
	 * @return array{new: string[], improved: string[], needs_attention: string[], has_comparison: bool, empty_reason: string}
	 */
	public static function get_overview_diff() {
		$current = Wf_Sn_Security_Snapshot::get_current();

		$previous = null;
		if ( class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reports' ) ) {
			$reports = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Reports::get_reports( 1, 0, 'full_report' );
			if ( ! empty( $reports[0]['snapshot'] ) ) {
				$previous = Wf_Sn_Security_Snapshot::decode( $reports[0]['snapshot'] );
			}
		}

		$diff = self::compare( $current, $previous );
		if ( ! $diff['has_comparison'] ) {
			$diff['empty_reason'] = 'no_report';
		} else {
			$diff['empty_reason'] = '';
		}
		return $diff;
	}

	/**
	 * Build diff between two most recent AI report snapshots.
	 *
	 * @return array{new: string[], improved: string[], needs_attention: string[], has_comparison: bool, empty_reason: string}
	 */
	public static function get_report_diff() {
		if ( ! class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reports' ) ) {
			return array(
				'new'             => array(),
				'improved'        => array(),
				'needs_attention' => array(),
				'has_comparison'  => false,
				'empty_reason'    => 'no_module',
			);
		}

		$reports = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Reports::get_latest_two_full_reports();
		if ( count( $reports ) < 2 ) {
			return array(
				'new'             => array(),
				'improved'        => array(),
				'needs_attention' => array(),
				'has_comparison'  => false,
				'empty_reason'    => count( $reports ) < 1 ? 'no_report' : 'one_report',
			);
		}

		$current  = Wf_Sn_Security_Snapshot::decode( isset( $reports[0]['snapshot'] ) ? $reports[0]['snapshot'] : '' );
		$previous = Wf_Sn_Security_Snapshot::decode( isset( $reports[1]['snapshot'] ) ? $reports[1]['snapshot'] : '' );

		$diff = self::compare( $current, $previous );
		$diff['empty_reason'] = $diff['has_comparison'] ? '' : 'no_snapshot';
		return $diff;
	}
}
