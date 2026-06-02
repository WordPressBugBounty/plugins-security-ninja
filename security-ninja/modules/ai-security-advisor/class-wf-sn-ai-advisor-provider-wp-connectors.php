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
		foreach ( self::get_registered_provider_ids( $registry ) as $id ) {
			if ( $registry->isProviderConfigured( $id ) ) {
				$out[] = $id;
			}
		}
		return $out;
	}

	/**
	 * Get provider IDs from AI registry, with safe fallback.
	 *
	 * @param object $registry Registry instance.
	 * @return array<int,string>
	 */
	private static function get_registered_provider_ids( $registry ) {
		if ( is_object( $registry ) && method_exists( $registry, 'getRegisteredProviderIds' ) ) {
			$ids = $registry->getRegisteredProviderIds();
			if ( is_array( $ids ) ) {
				$ids = array_values( array_filter( array_map( 'strval', $ids ) ) );
				if ( ! empty( $ids ) ) {
					return $ids;
				}
			}
		}
		return self::PROVIDER_IDS;
	}

	/**
	 * Generate text via the selected WordPress AI connector.
	 *
	 * @param string $provider_id       One of openai, google, anthropic (must be configured).
	 * @param string $system_instruction System instruction for the model.
	 * @param string $prompt_text       User/message text (privacy-safe context).
	 * @param array  $options           Optional: json_schema, max_tokens, temperature, request_type.
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string}
	 */
	public static function generate_text( $provider_id, $system_instruction, $prompt_text, $options = array() ) {
		if ( ! self::is_available() ) {
			return array(
				'ok'    => false,
				'error' => __( 'WordPress AI Connectors are not available.', 'security-ninja' ),
			);
		}

		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			return array(
				'ok'    => false,
				'error' => __( 'AI features are disabled on this site.', 'security-ninja' ),
			);
		}

		$configured = self::get_configured_providers();
		if ( ! in_array( $provider_id, $configured, true ) ) {
			return array(
				'ok'    => false,
				'error' => __( 'Selected connector is not configured.', 'security-ninja' ),
			);
		}

		$request_type = isset( $options['request_type'] ) ? sanitize_key( (string) $options['request_type'] ) : 'full_report';
		$max_tokens   = self::resolve_max_tokens( $request_type, $options );
		$temperature  = self::resolve_temperature( $options );
		$json_schema  = isset( $options['json_schema'] ) && is_array( $options['json_schema'] ) ? $options['json_schema'] : null;

		$result = null;

		// WordPress 7: prefer as_json_response() when the connector supports it; otherwise plain text_generation.
		if ( null !== $json_schema && self::is_prompt_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, true, true ) ) {
			$result = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, true, true );
			if ( ! empty( $result['ok'] ) ) {
				return $result;
			}
			if ( self::is_unsupported_temperature_error( $result ) ) {
				$retry_no_temp = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, false, true );
				if ( ! empty( $retry_no_temp['ok'] ) ) {
					return $retry_no_temp;
				}
				$result = $retry_no_temp;
			}
		}

		if ( null === $result || empty( $result['ok'] ) ) {
			if ( ! self::is_prompt_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, null, true, true ) ) {
				if ( self::is_no_models_error( $result ) || null === $result ) {
					$any_provider = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, null, false, false );
					if ( ! empty( $any_provider['ok'] ) ) {
						return $any_provider;
					}
					if ( null !== $json_schema && self::is_prompt_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, false, false ) ) {
						$schema_any = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, false, false );
						if ( ! empty( $schema_any['ok'] ) ) {
							return $schema_any;
						}
						$result = $schema_any;
					} else {
						$result = $any_provider;
					}
				}
				if ( null === $result || empty( $result['error'] ) ) {
					return array(
						'ok'    => false,
						'error' => sprintf(
							/* translators: %s: connector provider id */
							__( 'No AI model is available for provider "%s" with this prompt. Try another connector under Settings → Connectors, or check Security Advisor settings.', 'security-ninja' ),
							$provider_id
						),
					);
				}
				return $result;
			}

			$result = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, null, true, true );
			if ( ! empty( $result['ok'] ) ) {
				return $result;
			}
			if ( self::is_unsupported_temperature_error( $result ) ) {
				$retry_no_temp = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, null, false, true );
				if ( ! empty( $retry_no_temp['ok'] ) ) {
					return $retry_no_temp;
				}
				$result = $retry_no_temp;
			}
		}

		if ( self::is_no_models_error( $result ) ) {
			$any_provider = self::execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, null, false, false );
			if ( ! empty( $any_provider['ok'] ) ) {
				return $any_provider;
			}
			$result = $any_provider;
		}

		return $result;
	}

	/**
	 * Whether a configured prompt is supported for text generation (WP 7 feature detection).
	 *
	 * Uses WP_AI_Client_Prompt_Builder::is_supported_for_text_generation() — no API call.
	 *
	 * @param string                   $provider_id        Provider id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param int                      $max_tokens         Max output tokens.
	 * @param float                    $temperature        Temperature.
	 * @param array<string,mixed>|null $json_schema        Optional JSON schema.
	 * @param bool                     $use_temperature    Whether to include temperature.
	 * @param bool                     $force_provider     Whether to force selected provider.
	 * @return bool
	 */
	public static function is_prompt_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, $use_temperature = true, $force_provider = true ) {
		if ( ! self::is_available() ) {
			return false;
		}
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			return false;
		}
		$builder = self::configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, $use_temperature, $force_provider );
		if ( ! is_object( $builder ) || ! method_exists( $builder, 'is_supported_for_text_generation' ) ) {
			return false;
		}
		$supported = $builder->is_supported_for_text_generation();
		return true === $supported;
	}

	/**
	 * Build a WP AI Client prompt builder with advisor defaults.
	 *
	 * @param string                   $provider_id        Provider id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param int                      $max_tokens         Max output tokens.
	 * @param float                    $temperature        Temperature.
	 * @param array<string,mixed>|null $json_schema        Optional JSON schema.
	 * @param bool                     $use_temperature    Whether to include temperature.
	 * @param bool                     $force_provider     Whether to force selected provider.
	 * @return WP_AI_Client_Prompt_Builder|null
	 */
	private static function configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, $use_temperature = true, $force_provider = true ) {
		if ( ! function_exists( 'wp_ai_client_prompt' ) ) {
			return null;
		}
		$builder = wp_ai_client_prompt( $prompt_text )
			->using_system_instruction( $system_instruction )
			->using_max_tokens( $max_tokens );
		if ( $force_provider && '' !== (string) $provider_id ) {
			$builder = $builder->using_provider( $provider_id );
			$prefs = self::get_model_preferences_for_provider( $provider_id );
			if ( ! empty( $prefs ) && method_exists( $builder, 'using_model_preference' ) ) {
				$builder = $builder->using_model_preference( ...$prefs );
			}
		}
		if ( $use_temperature ) {
			$builder = $builder->using_temperature( $temperature );
		}
		if ( null !== $json_schema ) {
			$builder = $builder->as_json_response( $json_schema );
		}
		return $builder;
	}

	/**
	 * Build and run a single prompt request.
	 *
	 * @param string              $provider_id       Provider id.
	 * @param string              $system_instruction System instruction.
	 * @param string              $prompt_text       Prompt text.
	 * @param int                 $max_tokens        Max output tokens.
	 * @param float               $temperature       Temperature.
	 * @param array<string,mixed>|null $json_schema  Optional JSON schema.
	 * @param bool                      $use_temperature Whether to include temperature.
	 * @param bool                      $force_provider  Whether to force selected provider.
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string}
	 */
	private static function execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, $use_temperature = true, $force_provider = true ) {
		$timeout_cb = static function ( $default_timeout ) {
			/**
			 * Filters AI request timeout for Security Advisor calls.
			 *
			 * @param float $timeout Timeout in seconds.
			 */
			$requested_timeout = (float) apply_filters( 'wf_sn_ai_advisor_request_timeout', 60.0 );
			if ( $requested_timeout < 30.0 ) {
				$requested_timeout = 30.0;
			}
			return max( (float) $default_timeout, $requested_timeout );
		};
		add_filter( 'wp_ai_client_default_request_timeout', $timeout_cb, 20 );
		try {
			try {
				$builder = self::configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $temperature, $json_schema, $use_temperature, $force_provider );
				if ( ! is_object( $builder ) ) {
					return array(
						'ok'    => false,
						'error' => __( 'WordPress AI Connectors are not available.', 'security-ninja' ),
					);
				}
				$result = $builder->generate_text_result();
			} catch ( \Exception $e ) {
				return array(
					'ok'    => false,
					'error' => $e->getMessage(),
				);
			}
		} finally {
			remove_filter( 'wp_ai_client_default_request_timeout', $timeout_cb, 20 );
		}

		if ( is_wp_error( $result ) ) {
			return array(
				'ok'    => false,
				'error' => $result->get_error_message(),
			);
		}

		return self::normalize_generative_result( $result, $provider_id );
	}

	/**
	 * Detect connector errors indicating unsupported temperature argument.
	 *
	 * @param array<string,mixed> $result Provider result payload.
	 * @return bool
	 */
	private static function is_unsupported_temperature_error( array $result ) {
		if ( empty( $result['error'] ) || ! is_string( $result['error'] ) ) {
			return false;
		}
		$err = strtolower( $result['error'] );
		return strpos( $err, 'unsupported parameter' ) !== false && strpos( $err, 'temperature' ) !== false;
	}

	/**
	 * Detect connector errors indicating no matching models for selected provider.
	 *
	 * @param array<string,mixed> $result Provider result payload.
	 * @return bool
	 */
	private static function is_no_models_error( $result ) {
		if ( ! is_array( $result ) || empty( $result['error'] ) || ! is_string( $result['error'] ) ) {
			return false;
		}
		$err = strtolower( $result['error'] );
		return strpos( $err, 'no models found for provider' ) !== false || strpos( $err, 'no models found' ) !== false;
	}

	/**
	 * Preferred model IDs per provider (first match wins).
	 *
	 * @param string $provider_id Provider id.
	 * @return array<int, string>
	 */
	private static function get_model_preferences_for_provider( $provider_id ) {
		$provider_id = sanitize_key( (string) $provider_id );
		$defaults    = array();
		if ( 'deepseek' === $provider_id ) {
			// Chat model first — reasoning variants can consume the full output budget without JSON content.
			$defaults = array( 'deepseek-chat', 'deepseek-v4-flash', 'deepseek-v4-pro' );
		}
		/**
		 * Filters preferred model IDs for a connector (evaluated in order).
		 *
		 * @param array<int, string> $defaults    Default preference list.
		 * @param string             $provider_id Provider id.
		 */
		$prefs = apply_filters( 'wf_sn_ai_advisor_model_preferences', $defaults, $provider_id );
		if ( ! is_array( $prefs ) ) {
			return array();
		}
		$out = array();
		foreach ( $prefs as $pref ) {
			$pref = sanitize_key( (string) $pref );
			if ( '' !== $pref ) {
				$out[] = $pref;
			}
		}
		return $out;
	}

	/**
	 * Extract user-visible text from a GenerativeAiResult (content channel first).
	 *
	 * @param object $result GenerativeAiResult instance.
	 * @return string
	 */
	private static function extract_text_from_generative_result( $result ) {
		if ( ! is_object( $result ) ) {
			return '';
		}

		$content_text = '';

		if ( method_exists( $result, 'getCandidates' ) ) {
			$candidates = $result->getCandidates();
			if ( is_array( $candidates ) ) {
				foreach ( $candidates as $candidate ) {
					if ( ! is_object( $candidate ) || ! method_exists( $candidate, 'getMessage' ) ) {
						continue;
					}
					$message = $candidate->getMessage();
					if ( ! is_object( $message ) || ! method_exists( $message, 'getParts' ) ) {
						continue;
					}
					foreach ( $message->getParts() as $part ) {
						if ( ! is_object( $part ) || ! method_exists( $part, 'getText' ) ) {
							continue;
						}
						$part_text = $part->getText();
						if ( ! is_string( $part_text ) || '' === $part_text ) {
							continue;
						}
						$channel = method_exists( $part, 'getChannel' ) ? $part->getChannel() : null;
						if ( is_object( $channel ) && method_exists( $channel, 'isContent' ) && $channel->isContent() ) {
							$content_text .= $part_text;
						}
					}
				}
			}
		}

		if ( '' !== $content_text ) {
			return $content_text;
		}

		if ( method_exists( $result, 'toText' ) ) {
			try {
				$via_api = $result->toText();
				if ( is_string( $via_api ) && '' !== $via_api ) {
					return $via_api;
				}
			} catch ( \Exception $e ) {
				// Fall through.
			}
		}

		return '';
	}

	/**
	 * Read finish_reason from the first candidate when available.
	 *
	 * @param object $result GenerativeAiResult instance.
	 * @return string stop|length|content_filter|tool_calls|error|''
	 */
	private static function get_generative_finish_reason( $result ) {
		if ( ! is_object( $result ) || ! method_exists( $result, 'getCandidates' ) ) {
			return '';
		}
		$candidates = $result->getCandidates();
		if ( ! is_array( $candidates ) || empty( $candidates[0] ) ) {
			return '';
		}
		$candidate = $candidates[0];
		if ( ! is_object( $candidate ) || ! method_exists( $candidate, 'getFinishReason' ) ) {
			return '';
		}
		$finish = $candidate->getFinishReason();
		if ( is_object( $finish ) && method_exists( $finish, '__toString' ) ) {
			return (string) $finish;
		}
		return '';
	}

	/**
	 * Map GenerativeAiResult (or legacy shapes) to the advisor response array.
	 *
	 * @param mixed  $result      AI result object.
	 * @param string $provider_id Fallback model id.
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string, finish_reason?: string}
	 */
	private static function normalize_generative_result( $result, $provider_id ) {
		$text          = '';
		$usage         = array();
		$model         = $provider_id;
		$finish_reason = '';

		if ( is_object( $result ) && method_exists( $result, 'getCandidates' ) ) {
			$text          = self::extract_text_from_generative_result( $result );
			$finish_reason = self::get_generative_finish_reason( $result );

			if ( method_exists( $result, 'getTokenUsage' ) ) {
				$token_usage = $result->getTokenUsage();
				if ( is_object( $token_usage ) && method_exists( $token_usage, 'getPromptTokens' ) ) {
					$usage = array(
						'input_tokens'  => (int) $token_usage->getPromptTokens(),
						'output_tokens' => (int) $token_usage->getCompletionTokens(),
					);
				}
			}

			if ( method_exists( $result, 'getModelMetadata' ) ) {
				$metadata = $result->getModelMetadata();
				if ( is_object( $metadata ) && method_exists( $metadata, 'getId' ) ) {
					$id = (string) $metadata->getId();
					if ( '' !== $id ) {
						$model = $id;
					}
				}
			}
		} elseif ( is_string( $result ) ) {
			$text = $result;
		} elseif ( is_object( $result ) ) {
			if ( isset( $result->text ) && is_string( $result->text ) ) {
				$text = $result->text;
			}
			if ( isset( $result->usage ) && is_array( $result->usage ) ) {
				$usage = $result->usage;
			}
			if ( isset( $result->model ) && is_string( $result->model ) ) {
				$model = $result->model;
			}
		} elseif ( is_array( $result ) ) {
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
			'ok'    => true,
			'text'  => $text,
			'model' => $model,
		);
		if ( ! empty( $usage ) ) {
			$out['usage'] = $usage;
		}
		if ( '' !== $finish_reason ) {
			$out['finish_reason'] = $finish_reason;
		}
		if ( '' === $text && '' !== $finish_reason ) {
			$out['ok'] = false;
			if ( 'length' === $finish_reason ) {
				$out['error'] = __( 'The AI response hit the output token limit before the report was finished. Try again or switch to another connector (e.g. OpenAI or DeepSeek Chat).', 'security-ninja' );
			} else {
				$out['error'] = __( 'The AI provider returned no usable report text.', 'security-ninja' );
			}
		}
		return $out;
	}

	/**
	 * @param string $request_type Request type slug.
	 * @param array  $options      Caller options.
	 * @return int
	 */
	private static function resolve_max_tokens( $request_type, array $options ) {
		if ( isset( $options['max_tokens'] ) && is_numeric( $options['max_tokens'] ) ) {
			return max( 256, (int) $options['max_tokens'] );
		}
		$default = ( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type ) ? 1536 : 8192;
		/**
		 * Filters max output tokens for Security Advisor AI requests.
		 *
		 * @param int    $default      Default token limit.
		 * @param string $request_type full_report or prompt_chip.
		 */
		return max( 256, (int) apply_filters( 'wf_sn_ai_advisor_max_tokens', $default, $request_type ) );
	}

	/**
	 * @param array $options Caller options.
	 * @return float
	 */
	private static function resolve_temperature( array $options ) {
		if ( isset( $options['temperature'] ) && is_numeric( $options['temperature'] ) ) {
			return (float) $options['temperature'];
		}
		/**
		 * Filters temperature for Security Advisor AI requests.
		 *
		 * @param float $temperature Default 0.3 for factual security guidance.
		 */
		return (float) apply_filters( 'wf_sn_ai_advisor_temperature', 0.3 );
	}
}
