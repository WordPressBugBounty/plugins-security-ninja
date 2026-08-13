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
		'explain_for_client',
		'action_plan_30m',
		'monitor_this_week',
	);

	/**
	 * Chip definitions: id => label callback uses __() in caller for i18n.
	 *
	 * @return array<string, array{label: string}>
	 */
	public static function definitions() {
		return array(
			'delta_since_last'    => array(
				'label' => __( 'What changed since last report?', 'security-ninja' ),
			),
			'what_next'           => array(
				'label' => __( 'What should I fix first?', 'security-ninja' ),
			),
			'most_urgent'         => array(
				'label' => __( 'Which issue is most urgent?', 'security-ninja' ),
			),
			'what_improved'       => array(
				'label' => __( 'What improved since last time?', 'security-ninja' ),
			),
			'what_can_wait'       => array(
				'label' => __( 'Which items can wait?', 'security-ninja' ),
			),
			'explain_for_client'  => array(
				'label' => __( 'Explain this for a client', 'security-ninja' ),
			),
			'action_plan_30m'     => array(
				'label' => __( 'Give me a 30-minute action plan', 'security-ninja' ),
			),
			'monitor_this_week'   => array(
				'label' => __( 'What should I monitor this week?', 'security-ninja' ),
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
		$scores = Wf_Sn_Ai_Advisor_Test_Scores::get_counts();

		switch ( $prompt_id ) {
			case 'delta_since_last':
			case 'what_improved':
				return $n_full >= 2;
			case 'what_next':
			case 'what_can_wait':
			case 'explain_for_client':
			case 'action_plan_30m':
			case 'monitor_this_week':
				return $n_full >= 1;
			case 'most_urgent':
				return $n_full >= 1 || ( (int) $scores['bad'] + (int) $scores['warning'] ) > 0;
			default:
				return false;
		}
	}

	/**
	 * Human-readable reason when a chip is disabled.
	 *
	 * @param string $prompt_id Prompt id.
	 * @return string Empty when enabled or unknown.
	 */
	public static function get_disabled_reason( $prompt_id ) {
		if ( self::is_visible( $prompt_id ) ) {
			return '';
		}
		if ( ! self::is_valid_prompt_id( $prompt_id ) ) {
			return '';
		}

		$n_full = self::count_full_reports();

		switch ( $prompt_id ) {
			case 'delta_since_last':
				return __( 'Unavailable until there are at least two AI reports.', 'security-ninja' );
			case 'what_improved':
				return __( 'Unavailable until there is a previous report to compare.', 'security-ninja' );
			case 'what_next':
			case 'most_urgent':
			case 'what_can_wait':
			case 'explain_for_client':
			case 'action_plan_30m':
			case 'monitor_this_week':
				return __( 'Generate a report first. Then you can ask guided follow-up questions.', 'security-ninja' );
			default:
				return __( 'This prompt is not available for your current reports.', 'security-ninja' );
		}
	}

	/**
	 * Chip ids that compare two saved full reports.
	 *
	 * @return array<int, string>
	 */
	public static function comparison_prompt_ids() {
		return array(
			'delta_since_last',
			'what_improved',
		);
	}

	/**
	 * Chips currently enabled for the follow-up toolbar.
	 *
	 * @return array<int, array{id: string, label: string, enabled: bool, reason: string}>
	 */
	public static function get_enabled_chips_for_ui() {
		return array_values(
			array_filter(
				self::get_chips_for_ui(),
				static function ( $chip ) {
					return ! empty( $chip['enabled'] );
				}
			)
		);
	}

	/**
	 * Whether the follow-up toolbar should be active (at least one enabled chip).
	 *
	 * @return bool
	 */
	public static function is_followup_toolbar_active() {
		return ! empty( self::get_enabled_chips_for_ui() );
	}

	/**
	 * Comparison chips that are visible in definitions but not yet enabled.
	 *
	 * @return array<int, array{id: string, label: string, enabled: bool, reason: string}>
	 */
	public static function get_locked_comparison_chips_for_ui() {
		$comparison = self::comparison_prompt_ids();
		return array_values(
			array_filter(
				self::get_chips_for_ui(),
				static function ( $chip ) use ( $comparison ) {
					return in_array( $chip['id'], $comparison, true ) && empty( $chip['enabled'] );
				}
			)
		);
	}

	/**
	 * Chips for localize_script: id, label, enabled, reason.
	 *
	 * @return array<int, array{id: string, label: string, enabled: bool, reason: string}>
	 */
	public static function get_chips_for_ui() {
		$defs = self::definitions();
		$out  = array();
		foreach ( self::PROMPT_IDS as $pid ) {
			$enabled = self::is_visible( $pid );
			$out[]   = array(
				'id'      => $pid,
				'label'   => isset( $defs[ $pid ]['label'] ) ? $defs[ $pid ]['label'] : $pid,
				'enabled' => $enabled,
				'reason'  => $enabled ? '' : self::get_disabled_reason( $pid ),
			);
		}
		return $out;
	}
}
