<?php
/**
 * AI Security Advisor – improvement risk normalization and sorting (server-only).
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Improvements
 */
class Wf_Sn_Ai_Advisor_Improvements {

	/**
	 * Risk sort weights: high (0), medium (1), low (2).
	 *
	 * @var array<string, int>
	 */
	const RISK_ORDER = array(
		'high'   => 0,
		'medium' => 1,
		'low'    => 2,
	);

	/**
	 * Normalize risk for one improvement row.
	 *
	 * @param array $imp Improvement row from AI JSON.
	 * @return string One of high, medium, low.
	 */
	public static function normalize_risk( array $imp ) {
		$risk = isset( $imp['risk'] ) ? strtolower( (string) $imp['risk'] ) : 'low';
		if ( isset( $imp['id'] ) && 'mysql_permissions' === $imp['id'] ) {
			$risk = 'low';
		}
		if ( ! in_array( $risk, array( 'high', 'medium', 'low' ), true ) ) {
			$risk = 'low';
		}
		return $risk;
	}

	/**
	 * Sort improvements by risk (high first).
	 *
	 * @param array<int, array<string, mixed>> $improvements List of improvement rows.
	 * @return array<int, array<string, mixed>>
	 */
	public static function sort_by_risk( array $improvements ) {
		if ( empty( $improvements ) ) {
			return array();
		}
		usort(
			$improvements,
			function ( $a, $b ) {
				$ia = is_array( $a ) ? $a : array();
				$ib = is_array( $b ) ? $b : array();
				$ra = self::RISK_ORDER[ self::normalize_risk( $ia ) ];
				$rb = self::RISK_ORDER[ self::normalize_risk( $ib ) ];
				return $ra <=> $rb;
			}
		);
		return $improvements;
	}

	/**
	 * Normalize risk on each improvement and sort top_improvements in a full report.
	 *
	 * @param array<string, mixed> $report Decoded full report (modified in place).
	 * @return void
	 */
	public static function prepare_report_improvements( array &$report ) {
		if ( ! isset( $report['top_improvements'] ) || ! is_array( $report['top_improvements'] ) ) {
			return;
		}
		foreach ( $report['top_improvements'] as $idx => $imp ) {
			if ( ! is_array( $imp ) ) {
				continue;
			}
			$report['top_improvements'][ $idx ]['risk'] = self::normalize_risk( $imp );
		}
		$report['top_improvements'] = self::sort_by_risk( $report['top_improvements'] );
	}
}
