<?php
/**
 * AI Security Advisor – WordPress 7 AI Connectors provider.
 *
 * Uses wp_ai_client_prompt() when WP 7 and connector are available. No Freemius dependency.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Provider_Wp_Connectors
 */
class Wf_Sn_Ai_Advisor_Provider_Wp_Connectors {

	const PROVIDER_IDS = array( 'openai', 'google', 'anthropic' );

	/**
	 * Check if WP 7 AI is available.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return function_exists( 'wp_ai_client_prompt' ) && class_exists( '\WordPress\AiClient\AiClient' );
	}

	/**
	 * Get list of configured provider IDs (openai, google, anthropic).
	 *
	 * @return array List of provider_id strings that are configured.
	 */
	public static function get_configured_providers() {
		if ( ! self::is_available() ) {
			return array();
		}
		$registry = \WordPress\AiClient\AiClient::defaultRegistry();
		if ( ! method_exists( $registry, 'isProviderConfigured' ) ) {
			return array();
		}
		$out = array();
		foreach ( self::PROVIDER_IDS as $id ) {
			if ( $registry->isProviderConfigured( $id ) ) {
				$out[] = $id;
			}
		}
		return $out;
	}

	/**
	 * Generate text via the selected WordPress AI connector.
	 *
	 * @param string $provider_id       One of openai, google, anthropic (must be configured).
	 * @param string $system_instruction System instruction for the model.
	 * @param string $prompt_text       User/message text (privacy-safe context).
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string}
	 */
	public static function generate_text( $provider_id, $system_instruction, $prompt_text ) {
		if ( ! self::is_available() ) {
			return array(
				'ok'    => false,
				'error' => __( 'WordPress AI Connectors are not available.', 'security-ninja' ),
			);
		}
		$configured = self::get_configured_providers();
		if ( ! in_array( $provider_id, $configured, true ) ) {
			return array(
				'ok'    => false,
				'error' => __( 'Selected connector is not configured.', 'security-ninja' ),
			);
		}

		try {
			$result = wp_ai_client_prompt( $prompt_text )
				->using_system_instruction( $system_instruction )
				->using_provider( $provider_id )
				->generate_text();
		} catch ( \Exception $e ) {
			return array(
				'ok'    => false,
				'error' => $e->getMessage(),
			);
		}

		if ( is_wp_error( $result ) ) {
			return array(
				'ok'    => false,
				'error' => $result->get_error_message(),
			);
		}

		$text  = is_string( $result ) ? $result : '';
		$usage = null;
		$model = null;

		if ( is_object( $result ) ) {
			if ( isset( $result->text ) && is_string( $result->text ) ) {
				$text = $result->text;
			}
			if ( isset( $result->usage ) && is_array( $result->usage ) ) {
				$usage = $result->usage;
			}
			if ( isset( $result->model ) && is_string( $result->model ) ) {
				$model = $result->model;
			}
		}
		if ( is_array( $result ) ) {
			if ( isset( $result['text'] ) && is_string( $result['text'] ) ) {
				$text = $result['text'];
			}
			if ( isset( $result['usage'] ) && is_array( $result['usage'] ) ) {
				$usage = $result['usage'];
			}
			if ( isset( $result['model'] ) && is_string( $result['model'] ) ) {
				$model = $result['model'];
			}
		}

		$out = array(
			'ok'   => true,
			'text' => $text,
		);
		if ( null !== $usage ) {
			$out['usage'] = $usage;
		}
		// Use model from response when available; otherwise store connector id so DB model column is not empty.
		$out['model'] = null !== $model ? $model : $provider_id;
		return $out;
	}
}
