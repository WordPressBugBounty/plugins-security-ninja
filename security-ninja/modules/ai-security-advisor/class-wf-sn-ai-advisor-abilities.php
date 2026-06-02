<?php
/**
 * AI Security Advisor – WordPress Abilities registration.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Abilities
 */
class Wf_Sn_Ai_Advisor_Abilities {

	const CATEGORY = 'security-ninja';

	/**
	 * Option key in wf_sn_ai_advisor for global abilities exposure toggle.
	 */
	const OPTION_ABILITIES_EXPOSED = 'abilities_exposed';

	/**
	 * Bootstrap abilities hooks.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! function_exists( 'wp_register_ability' ) || ! function_exists( 'wp_register_ability_category' ) ) {
			return;
		}
		if ( did_action( 'wp_abilities_api_categories_init' ) ) {
			self::register_category();
		} else {
			add_action( 'wp_abilities_api_categories_init', array( __CLASS__, 'register_category' ) );
		}
		if ( did_action( 'wp_abilities_api_init' ) ) {
			self::register_abilities();
		} else {
			add_action( 'wp_abilities_api_init', array( __CLASS__, 'register_abilities' ) );
		}
	}

	/**
	 * Whether WordPress AI abilities from Security Ninja are exposed.
	 *
	 * Does not affect Security Advisor report generation or follow-up chips.
	 *
	 * @return bool
	 */
	public static function is_exposed_enabled() {
		$opts = Wf_Sn_Ai_Advisor_Page::get_options();
		if ( ! array_key_exists( self::OPTION_ABILITIES_EXPOSED, $opts ) ) {
			return true;
		}
		return (int) $opts[ self::OPTION_ABILITIES_EXPOSED ] === 1;
	}

	/**
	 * Saved value for toggle switch (0 or 1).
	 *
	 * @return int
	 */
	public static function get_exposed_saved_value() {
		return self::is_exposed_enabled() ? 1 : 0;
	}

	/**
	 * Canonical ability definitions (registration + settings UI).
	 *
	 * @return array<string, array{slug: string, label: string, summary: string, description: string, callback: callable, output_schema: array}>
	 */
	public static function definitions() {
		return array(
			'get-test-summary' => array(
				'slug'           => 'get-test-summary',
				'label'          => __( 'Get Test Summary', 'security-ninja' ),
				'summary'        => __( 'Passed, warning, and failed counts from your latest Security Tests.', 'security-ninja' ),
				'description'    => __( 'Returns Security Ninja test summary counts: passed, warning, failed.', 'security-ninja' ),
				'callback'       => array( __CLASS__, 'execute_get_test_summary' ),
				'output_schema'  => array(
					'type'                 => 'object',
					'additionalProperties' => false,
					'required'             => array( 'passed', 'warning', 'failed' ),
					'properties'           => array(
						'passed'  => array( 'type' => 'integer' ),
						'warning' => array( 'type' => 'integer' ),
						'failed'  => array( 'type' => 'integer' ),
					),
				),
			),
			'get-attack-activity' => array(
				'slug'           => 'get-attack-activity',
				'label'          => __( 'Get Attack Activity', 'security-ninja' ),
				'summary'        => __( 'Seven-day attack totals compared to the previous week.', 'security-ninja' ),
				'description'    => __( 'Returns 7-day and previous 7-day attack activity summary from Security Ninja.', 'security-ninja' ),
				'callback'       => array( __CLASS__, 'execute_get_attack_activity' ),
				'output_schema'  => array(
					'type'                 => 'object',
					'additionalProperties' => false,
					'required'             => array( 'current_total', 'previous_total', 'trend', 'reason' ),
					'properties'           => array(
						'current_total'  => array( 'type' => 'integer' ),
						'previous_total' => array( 'type' => 'integer' ),
						'trend'          => array( 'type' => 'string' ),
						'reason'         => array( 'type' => 'string' ),
					),
				),
			),
			'get-latest-report' => array(
				'slug'           => 'get-latest-report',
				'label'          => __( 'Get Latest AI Security Report', 'security-ninja' ),
				'summary'        => __( 'The most recent full Security Advisor audit stored on this site.', 'security-ninja' ),
				'description'    => __( 'Returns latest stored Security Advisor full report.', 'security-ninja' ),
				'callback'       => array( __CLASS__, 'execute_get_latest_report' ),
				'output_schema'  => array(
					'type'                 => 'object',
					'additionalProperties' => false,
					'required'             => array( 'generated_at', 'report' ),
					'properties'           => array(
						'generated_at' => array( 'type' => 'string' ),
						'report'       => array(
							'type' => array( 'object', 'null' ),
						),
					),
				),
			),
		);
	}

	/**
	 * Definitions formatted for the settings page list.
	 *
	 * @return array<int, array{slug: string, label: string, summary: string}>
	 */
	public static function get_definitions_for_ui() {
		$out = array();
		foreach ( self::definitions() as $def ) {
			$out[] = array(
				'slug'    => $def['slug'],
				'label'   => $def['label'],
				'summary' => $def['summary'],
			);
		}
		return $out;
	}

	/**
	 * Register ability category.
	 *
	 * @return void
	 */
	public static function register_category() {
		if ( ! self::is_exposed_enabled() ) {
			return;
		}
		wp_register_ability_category(
			self::CATEGORY,
			array(
				'label'       => __( 'Security Ninja', 'security-ninja' ),
				'description' => __( 'Read-only security summary abilities from Security Ninja.', 'security-ninja' ),
			)
		);
	}

	/**
	 * Register Security Advisor abilities.
	 *
	 * @return void
	 */
	public static function register_abilities() {
		if ( ! self::is_exposed_enabled() ) {
			return;
		}
		foreach ( self::definitions() as $def ) {
			wp_register_ability(
				self::CATEGORY . '/' . $def['slug'],
				self::base_args(
					$def['label'],
					$def['description'],
					$def['callback'],
					$def['output_schema']
				)
			);
		}
	}

	/**
	 * Shared ability args.
	 *
	 * @param string   $label            Label.
	 * @param string   $description      Description.
	 * @param callable $execute_callback Callback.
	 * @param array    $output_schema    Schema.
	 * @return array<string,mixed>
	 */
	private static function base_args( $label, $description, $execute_callback, array $output_schema ) {
		return array(
			'label'               => $label,
			'description'         => $description,
			'category'            => self::CATEGORY,
			'input_schema'        => array(
				'type'                 => 'object',
				'default'              => array(),
				'additionalProperties' => false,
			),
			'output_schema'       => $output_schema,
			'execute_callback'    => $execute_callback,
			'permission_callback' => static function () {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations'  => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
				'show_in_rest' => true,
			),
		);
	}

	/**
	 * Execute test summary ability.
	 *
	 * @return array<string,int>
	 */
	public static function execute_get_test_summary() {
		$score = Wf_Sn_Ai_Advisor_Test_Scores::get_counts();
		return array(
			'passed'  => $score['good'],
			'warning' => $score['warning'],
			'failed'  => $score['bad'],
		);
	}

	/**
	 * Execute attack activity ability.
	 *
	 * @return array<string,mixed>
	 */
	public static function execute_get_attack_activity() {
		$counts      = Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d();
		$prev_counts = Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d();

		return Wf_Sn_Ai_Advisor_Attack_Activity::build_summary( $counts, $prev_counts );
	}

	/**
	 * Execute latest report ability.
	 *
	 * @return array<string,mixed>
	 */
	public static function execute_get_latest_report() {
		Wf_Sn_Ai_Advisor_Reports::ensure_table();
		$rows = Wf_Sn_Ai_Advisor_Reports::get_reports( 1, 0, 'full_report' );
		if ( empty( $rows ) || ! is_array( $rows[0] ) ) {
			return array(
				'generated_at' => '',
				'report'       => null,
			);
		}
		$row    = $rows[0];
		$report = null;
		if ( ! empty( $row['report_text'] ) && is_string( $row['report_text'] ) ) {
			$decoded = json_decode( $row['report_text'], true );
			if ( is_array( $decoded ) ) {
				$report = $decoded;
			}
		}
		return array(
			'generated_at' => isset( $row['created'] ) ? (string) $row['created'] : '',
			'report'       => $report,
		);
	}
}
