<?php
/**
 * AI Security Advisor – shared Security Ninja test score counts.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Test_Scores
 */
class Wf_Sn_Ai_Advisor_Test_Scores {

	/**
	 * Default counts when scores are unavailable.
	 *
	 * @return array{good: int, bad: int, warning: int}
	 */
	public static function empty_counts() {
		return array(
			'good'    => 0,
			'bad'     => 0,
			'warning' => 0,
		);
	}

	/**
	 * Passed, failed, and warning counts from the latest Security Tests run.
	 *
	 * @return array{good: int, bad: int, warning: int}
	 */
	public static function get_counts() {
		if ( ! class_exists( '\WPSecurityNinja\Plugin\Wf_Sn' ) ) {
			return self::empty_counts();
		}
		$response = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
		if ( ! is_array( $response ) ) {
			return self::empty_counts();
		}
		return array(
			'good'    => isset( $response['good'] ) ? (int) $response['good'] : 0,
			'bad'     => isset( $response['bad'] ) ? (int) $response['bad'] : 0,
			'warning' => isset( $response['warning'] ) ? (int) $response['warning'] : 0,
		);
	}
}
