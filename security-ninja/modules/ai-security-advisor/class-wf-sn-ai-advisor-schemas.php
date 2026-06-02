<?php
/**
 * AI Security Advisor – JSON output schemas for wp_ai_client as_json_response().
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Schemas
 */
class Wf_Sn_Ai_Advisor_Schemas {

	/**
	 * JSON schema for a full Security Advisor report.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_full_report_schema() {
		return array(
			'type'                 => 'object',
			'required'             => array( 'executive_summary', 'overview', 'top_improvements', 'activity' ),
			'additionalProperties' => false,
			'properties'           => array(
				'executive_summary' => array(
					'type' => 'string',
				),
				'overview'          => array(
					'type' => 'string',
				),
				'top_improvements'  => array(
					'type'  => 'array',
					'items' => array(
						'type'                 => 'object',
						'required'             => array( 'id', 'title', 'short_label', 'details', 'risk' ),
						'additionalProperties' => false,
						'properties'           => array(
							'id'          => array( 'type' => 'string' ),
							'title'       => array( 'type' => 'string' ),
							'short_label' => array( 'type' => 'string' ),
							'details'     => array( 'type' => 'string' ),
							'risk'        => array(
								'type' => 'string',
								'enum' => array( 'low', 'medium', 'high' ),
							),
						),
					),
				),
				'activity'          => array(
					'type'                 => 'object',
					'required'             => array( 'summary', 'attack_volume_trend', 'attack_volume_reason' ),
					'additionalProperties' => false,
					'properties'           => array(
						'summary'               => array( 'type' => 'string' ),
						'attack_volume_trend'   => array(
							'type' => 'string',
							'enum' => array( 'up', 'down', 'stable', 'unknown' ),
						),
						'attack_volume_reason'  => array( 'type' => 'string' ),
					),
				),
				'meta'              => array(
					'type'                 => 'object',
					'required'             => array( 'language', 'model', 'generated_at' ),
					'additionalProperties' => false,
					'properties'           => array(
						'language'     => array( 'type' => 'string' ),
						'model'        => array(
							'type' => array( 'string', 'null' ),
						),
						'generated_at' => array( 'type' => 'string' ),
					),
				),
			),
		);
	}

	/**
	 * JSON schema for a prompt chip response.
	 *
	 * @param string $prompt_id Chip id.
	 * @return array<string, mixed>|null Null when unknown.
	 */
	public static function get_chip_schema( $prompt_id ) {
		$prompt_id = sanitize_key( (string) $prompt_id );

		if ( 'delta_since_last' === $prompt_id ) {
			return array(
				'type'                 => 'object',
				'required'             => array( 'delta_summary' ),
				'additionalProperties' => false,
				'properties'           => array(
					'delta_summary'    => array( 'type' => 'string' ),
					'new_items'        => array(
						'type'  => 'array',
						'items' => array( 'type' => 'string' ),
					),
					'resolved_items'   => array(
						'type'  => 'array',
						'items' => array( 'type' => 'string' ),
					),
					'priority_shifts'  => array( 'type' => 'string' ),
					'notes'            => array( 'type' => 'string' ),
				),
			);
		}

		if ( in_array( $prompt_id, array( 'what_next', 'most_urgent', 'what_can_wait', 'what_improved' ), true ) ) {
			return array(
				'type'                 => 'object',
				'required'             => array( 'answer' ),
				'additionalProperties' => false,
				'properties'           => array(
					'answer'   => array( 'type' => 'string' ),
					'bullets'  => array(
						'type'  => 'array',
						'items' => array( 'type' => 'string' ),
					),
				),
			);
		}

		return null;
	}

	/**
	 * Resolve schema for an AJAX request type.
	 *
	 * @param string $request_type full_report or prompt_chip.
	 * @param string $prompt_id    Chip id when prompt_chip.
	 * @return array<string, mixed>|null
	 */
	public static function get_for_request( $request_type, $prompt_id = '' ) {
		if ( 'full_report' === $request_type ) {
			return self::get_full_report_schema();
		}
		if ( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type ) {
			return self::get_chip_schema( $prompt_id );
		}
		return null;
	}

	/**
	 * Validate a decoded chip response against the canonical chip schema.
	 *
	 * @param string $prompt_id Chip id.
	 * @param array  $data      Decoded JSON object.
	 * @return bool
	 */
	public static function validate_chip_response( $prompt_id, array $data ) {
		$schema = self::get_chip_schema( $prompt_id );
		if ( null === $schema ) {
			return false;
		}
		return self::validate_against_schema( $data, $schema );
	}

	/**
	 * Normalize a decoded full report before schema validation (fill server-owned fields, fix common model gaps).
	 *
	 * @param array       $report   Decoded report (modified in place).
	 * @param string|null $model    Model id when known.
	 * @param string      $language UI locale / language code.
	 * @return void
	 */
	public static function normalize_full_report_response( array &$report, $model, $language = '' ) {
		$allowed_top = array( 'executive_summary', 'overview', 'top_improvements', 'activity', 'meta' );
		foreach ( array_keys( $report ) as $key ) {
			if ( ! in_array( $key, $allowed_top, true ) ) {
				unset( $report[ $key ] );
			}
		}

		foreach ( array( 'executive_summary', 'overview' ) as $text_key ) {
			if ( ! isset( $report[ $text_key ] ) || ! is_string( $report[ $text_key ] ) ) {
				$report[ $text_key ] = isset( $report[ $text_key ] ) ? (string) $report[ $text_key ] : '';
			}
			$report[ $text_key ] = trim( $report[ $text_key ] );
			if ( '' === $report[ $text_key ] ) {
				$report[ $text_key ] = __( 'Security assessment based on the latest test results.', 'security-ninja' );
			}
		}

		if ( ! isset( $report['top_improvements'] ) || ! is_array( $report['top_improvements'] ) ) {
			$report['top_improvements'] = array();
		}
		$normalized_improvements = array();
		foreach ( $report['top_improvements'] as $imp ) {
			if ( ! is_array( $imp ) ) {
				continue;
			}
			$title = isset( $imp['title'] ) && is_string( $imp['title'] ) ? trim( $imp['title'] ) : '';
			$id    = isset( $imp['id'] ) && is_string( $imp['id'] ) ? sanitize_key( $imp['id'] ) : '';
			if ( '' === $id && '' !== $title ) {
				$id = sanitize_key( $title );
			}
			if ( '' === $id ) {
				$id = 'improvement_' . ( count( $normalized_improvements ) + 1 );
			}
			$short_label = isset( $imp['short_label'] ) && is_string( $imp['short_label'] ) ? trim( $imp['short_label'] ) : '';
			if ( '' === $short_label ) {
				$short_label = $title;
			}
			if ( function_exists( 'mb_substr' ) && mb_strlen( $short_label, 'UTF-8' ) > 80 ) {
				$short_label = mb_substr( $short_label, 0, 77, 'UTF-8' ) . '…';
			} elseif ( strlen( $short_label ) > 80 ) {
				$short_label = substr( $short_label, 0, 77 ) . '…';
			}
			$details = isset( $imp['details'] ) && is_string( $imp['details'] ) ? trim( $imp['details'] ) : '';
			if ( '' === $details ) {
				$details = $title;
			}
			$risk = 'low';
			if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Improvements' ) ) {
				$risk = Wf_Sn_Ai_Advisor_Improvements::normalize_risk( $imp );
			} elseif ( isset( $imp['risk'] ) && is_string( $imp['risk'] ) ) {
				$candidate = strtolower( trim( $imp['risk'] ) );
				if ( in_array( $candidate, array( 'high', 'medium', 'low' ), true ) ) {
					$risk = $candidate;
				}
			}
			if ( '' === $title && '' === $details ) {
				continue;
			}
			$normalized_improvements[] = array(
				'id'          => $id,
				'title'       => $title,
				'short_label' => $short_label,
				'details'     => $details,
				'risk'        => $risk,
			);
		}
		$report['top_improvements'] = $normalized_improvements;

		if ( ! isset( $report['activity'] ) || ! is_array( $report['activity'] ) ) {
			$report['activity'] = array();
		}
		$activity = &$report['activity'];
		foreach ( array( 'summary', 'attack_volume_reason' ) as $act_key ) {
			if ( ! isset( $activity[ $act_key ] ) || ! is_string( $activity[ $act_key ] ) ) {
				$activity[ $act_key ] = isset( $activity[ $act_key ] ) ? (string) $activity[ $act_key ] : '';
			}
			$activity[ $act_key ] = trim( $activity[ $act_key ] );
		}
		$trend = isset( $activity['attack_volume_trend'] ) ? strtolower( trim( (string) $activity['attack_volume_trend'] ) ) : '';
		$trend_map = array(
			'up'        => 'up',
			'increase'  => 'up',
			'increasing' => 'up',
			'rising'    => 'up',
			'down'      => 'down',
			'decrease'  => 'down',
			'decreasing' => 'down',
			'falling'   => 'down',
			'stable'    => 'stable',
			'flat'      => 'stable',
			'unchanged' => 'stable',
			'same'      => 'stable',
			'unknown'   => 'unknown',
			'none'      => 'unknown',
		);
		$activity['attack_volume_trend'] = isset( $trend_map[ $trend ] ) ? $trend_map[ $trend ] : 'unknown';
		foreach ( array_keys( $activity ) as $act_key ) {
			if ( ! in_array( $act_key, array( 'summary', 'attack_volume_trend', 'attack_volume_reason' ), true ) ) {
				unset( $activity[ $act_key ] );
			}
		}
		if ( '' === $activity['summary'] ) {
			$activity['summary'] = __( 'Review the latest security test results and activity counts.', 'security-ninja' );
		}
		if ( '' === $activity['attack_volume_reason'] ) {
			$activity['attack_volume_reason'] = __( 'Based on the 7-day activity totals in the provided context.', 'security-ninja' );
		}

		$lang = is_string( $language ) && '' !== trim( $language ) ? trim( $language ) : 'en';
		$report['meta'] = array(
			'language'     => $lang,
			'model'        => is_string( $model ) && '' !== $model ? $model : null,
			'generated_at' => gmdate( 'c' ),
		);
	}

	/**
	 * Validate a decoded full report against the canonical full-report schema.
	 *
	 * @param array $data Decoded JSON object.
	 * @return bool
	 */
	public static function validate_full_report_response( array $data ) {
		return self::validate_against_schema( $data, self::get_full_report_schema() );
	}

	/**
	 * Validate a value against a JSON-schema-like array (subset used by advisor schemas).
	 *
	 * @param mixed $value    Value to validate.
	 * @param array $schema   Schema fragment.
	 * @param bool  $required Whether the value is required (non-empty strings).
	 * @return bool
	 */
	private static function validate_against_schema( $value, array $schema, $required = false ) {
		if ( isset( $schema['enum'] ) && is_array( $schema['enum'] ) ) {
			if ( ! in_array( $value, $schema['enum'], true ) ) {
				return false;
			}
		}

		$type = isset( $schema['type'] ) ? $schema['type'] : null;

		if ( is_array( $type ) ) {
			return self::value_matches_type_union( $value, $type, $required );
		}

		if ( 'object' === $type ) {
			if ( ! is_array( $value ) ) {
				return false;
			}
			$properties = isset( $schema['properties'] ) && is_array( $schema['properties'] ) ? $schema['properties'] : array();
			if ( isset( $schema['additionalProperties'] ) && false === $schema['additionalProperties'] ) {
				foreach ( array_keys( $value ) as $key ) {
					if ( ! array_key_exists( $key, $properties ) ) {
						return false;
					}
				}
			}
			$required_keys = isset( $schema['required'] ) && is_array( $schema['required'] ) ? $schema['required'] : array();
			foreach ( $required_keys as $req_key ) {
				if ( ! array_key_exists( $req_key, $value ) ) {
					return false;
				}
				$prop_schema = isset( $properties[ $req_key ] ) ? $properties[ $req_key ] : array();
				if ( ! self::validate_against_schema( $value[ $req_key ], $prop_schema, true ) ) {
					return false;
				}
			}
			foreach ( $value as $prop_key => $prop_value ) {
				if ( in_array( $prop_key, $required_keys, true ) ) {
					continue;
				}
				if ( ! array_key_exists( $prop_key, $properties ) ) {
					continue;
				}
				if ( ! self::validate_against_schema( $prop_value, $properties[ $prop_key ], false ) ) {
					return false;
				}
			}
			return true;
		}

		if ( 'string' === $type ) {
			if ( ! is_string( $value ) ) {
				return false;
			}
			if ( $required && '' === $value ) {
				return false;
			}
			return true;
		}

		if ( 'array' === $type ) {
			if ( ! is_array( $value ) ) {
				return false;
			}
			$item_schema = isset( $schema['items'] ) && is_array( $schema['items'] ) ? $schema['items'] : array();
			foreach ( $value as $item ) {
				if ( ! self::validate_against_schema( $item, $item_schema, false ) ) {
					return false;
				}
			}
			return true;
		}

		return true;
	}

	/**
	 * Whether a value matches a JSON Schema type union (e.g. string|null).
	 *
	 * @param mixed $value    Value to check.
	 * @param array $types    List of type strings.
	 * @param bool  $required Whether a non-empty string is required when type includes string.
	 * @return bool
	 */
	private static function value_matches_type_union( $value, array $types, $required ) {
		foreach ( $types as $type_name ) {
			if ( 'null' === $type_name && null === $value ) {
				return true;
			}
			if ( 'string' === $type_name && is_string( $value ) ) {
				if ( $required && '' === $value ) {
					continue;
				}
				return true;
			}
		}
		return false;
	}
}
