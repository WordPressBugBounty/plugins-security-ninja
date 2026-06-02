<?php
/**
 * AI Security Advisor – shared attack activity totals and trend.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Attack_Activity
 */
class Wf_Sn_Ai_Advisor_Attack_Activity {

	/**
	 * Sum event counts for the current 7-day window.
	 *
	 * @param array $counts Row from Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d().
	 * @return int
	 */
	public static function current_total_from_counts( array $counts ) {
		return (int) ( isset( $counts['blocked_logins_7d'] ) ? $counts['blocked_logins_7d'] : 0 )
			+ (int) ( isset( $counts['xmlrpc_blocks_7d'] ) ? $counts['xmlrpc_blocks_7d'] : 0 )
			+ (int) ( isset( $counts['firewall_events_7d'] ) ? $counts['firewall_events_7d'] : 0 )
			+ (int) ( isset( $counts['failed_logins_7d'] ) ? $counts['failed_logins_7d'] : 0 );
	}

	/**
	 * Sum event counts for the previous 7-day window.
	 *
	 * @param array $prev_counts Row from Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d().
	 * @return int
	 */
	public static function previous_total_from_counts( array $prev_counts ) {
		return (int) ( isset( $prev_counts['blocked_logins_prev_7d'] ) ? $prev_counts['blocked_logins_prev_7d'] : 0 )
			+ (int) ( isset( $prev_counts['xmlrpc_blocks_prev_7d'] ) ? $prev_counts['xmlrpc_blocks_prev_7d'] : 0 )
			+ (int) ( isset( $prev_counts['firewall_events_prev_7d'] ) ? $prev_counts['firewall_events_prev_7d'] : 0 )
			+ (int) ( isset( $prev_counts['failed_logins_prev_7d'] ) ? $prev_counts['failed_logins_prev_7d'] : 0 );
	}

	/**
	 * Build aggregated attack-activity summary (totals, trend, reason).
	 *
	 * @param array $counts      Current 7-day counts.
	 * @param array $prev_counts Previous 7-day counts.
	 * @return array{current_total:int, previous_total:int, trend:string, reason:string}
	 */
	public static function build_summary( array $counts, array $prev_counts ) {
		$current_total  = self::current_total_from_counts( $counts );
		$previous_total = self::previous_total_from_counts( $prev_counts );

		$trend  = 'unknown';
		$reason = '';

		if ( 0 === $current_total && 0 === $previous_total ) {
			$trend  = 'stable';
			$reason = 'No recorded blocked or failed events in the last 14 days.';
		} elseif ( 0 === $previous_total && $current_total > 0 ) {
			$trend  = 'up';
			$reason = sprintf(
				/* translators: %d: number of blocked or failed events in the last 7 days */
				__( 'Detected %d blocked or failed events in the last 7 days, compared to none in the previous 7 days.', 'security-ninja' ),
				$current_total
			);
		} else {
			$delta = $current_total - $previous_total;
			$ratio = $delta / max( 1, $previous_total );
			if ( $ratio > 0.25 ) {
				$trend = 'up';
			} elseif ( $ratio < -0.25 ) {
				$trend = 'down';
			} else {
				$trend = 'stable';
			}
			/* translators: 1: current 7-day event count, 2: previous 7-day event count */
			$reason = sprintf( __( 'Current 7-day total is %1$d events versus %2$d in the previous 7 days.', 'security-ninja' ), $current_total, $previous_total );
		}

		return array(
			'current_total'  => $current_total,
			'previous_total' => $previous_total,
			'trend'          => $trend,
			'reason'         => $reason,
		);
	}
}
