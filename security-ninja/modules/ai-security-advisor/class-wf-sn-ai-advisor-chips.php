<?php
/**
 * Security Advisor — canonical prompt chip registry (single source of truth).
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Chips
 */
class Wf_Sn_Ai_Advisor_Chips {

	const REQUEST_TYPE = 'prompt_chip';

	/**
	 * All valid prompt_id values (fixed set for this release).
	 */
	const PROMPT_IDS = array(
		'delta_since_last',
		'what_next',
		'most_urgent',
		'what_improved',
		'what_can_wait',
	);

	/**
	 * Chip definitions: id => label callback uses __() in caller for i18n.
	 *
	 * @return array<string, array{label: string}>
	 */
	public static function definitions() {
		return array(
			'delta_since_last' => array(
				'label' => __( 'What changed since last report?', 'security-ninja' ),
			),
			'what_next'        => array(
				'label' => __( 'What should I do next?', 'security-ninja' ),
			),
			'most_urgent'      => array(
				'label' => __( 'Which issue is most urgent?', 'security-ninja' ),
			),
			'what_improved'    => array(
				'label' => __( 'What improved since last time?', 'security-ninja' ),
			),
			'what_can_wait'    => array(
				'label' => __( 'Which items can wait?', 'security-ninja' ),
			),
		);
	}

	/**
	 * Whether a prompt_id is known.
	 *
	 * @param string $prompt_id Raw id.
	 * @return bool
	 */
	public static function is_valid_prompt_id( $prompt_id ) {
		$id = sanitize_key( (string) $prompt_id );
		return in_array( $id, self::PROMPT_IDS, true );
	}

	/**
	 * Count stored full_report rows.
	 *
	 * @return int
	 */
	public static function count_full_reports() {
		return Wf_Sn_Ai_Advisor_Reports::count_by_request_type( 'full_report' );
	}

	/**
	 * Whether a chip should be offered in the UI for the current site state.
	 *
	 * @param string $prompt_id Prompt id.
	 * @return bool
	 */
	public static function is_visible( $prompt_id ) {
		if ( ! self::is_valid_prompt_id( $prompt_id ) ) {
			return false;
		}
		$n_full = self::count_full_reports();
		$scores = self::get_test_score_counts();

		switch ( $prompt_id ) {
			case 'delta_since_last':
			case 'what_improved':
				return $n_full >= 2;
			case 'what_next':
			case 'what_can_wait':
				return $n_full >= 1;
			case 'most_urgent':
				return $n_full >= 1 || ( (int) $scores['bad'] + (int) $scores['warning'] ) > 0;
			default:
				return false;
		}
	}

	/**
	 * Chips for localize_script: id, label, enabled.
	 *
	 * @return array<int, array{id: string, label: string, enabled: bool}>
	 */
	public static function get_chips_for_ui() {
		$defs = self::definitions();
		$out  = array();
		foreach ( self::PROMPT_IDS as $pid ) {
			$out[] = array(
				'id'      => $pid,
				'label'   => isset( $defs[ $pid ]['label'] ) ? $defs[ $pid ]['label'] : $pid,
				'enabled' => self::is_visible( $pid ),
			);
		}
		return $out;
	}

	/**
	 * @return array{bad: int, warning: int, good: int}
	 */
	private static function get_test_score_counts() {
		if ( ! class_exists( '\WPSecurityNinja\Plugin\Wf_Sn' ) ) {
			return array(
				'bad'     => 0,
				'warning' => 0,
				'good'    => 0,
			);
		}
		$r = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
		if ( ! is_array( $r ) ) {
			return array(
				'bad'     => 0,
				'warning' => 0,
				'good'    => 0,
			);
		}
		return array(
			'bad'     => isset( $r['bad'] ) ? (int) $r['bad'] : 0,
			'warning' => isset( $r['warning'] ) ? (int) $r['warning'] : 0,
			'good'    => isset( $r['good'] ) ? (int) $r['good'] : 0,
		);
	}
}
