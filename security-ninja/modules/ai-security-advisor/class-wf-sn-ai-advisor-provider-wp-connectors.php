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
	 * Register default provider profile filter callbacks.
	 *
	 * @return void
	 */
	public static function register_default_profiles() {
		add_filter( 'wf_sn_ai_advisor_provider_profile', array( __CLASS__, 'filter_default_provider_profile' ), 10, 2 );
	}

	/**
	 * Shipped defaults for known connectors; unknown connectors use the generic ladder.
	 *
	 * @param array  $profile     Profile from prior filters.
	 * @param string $provider_id Registry connector id.
	 * @return array{modes: string[], model_prefs: string[], max_tokens: int|null}
	 */
	public static function filter_default_provider_profile( $profile, $provider_id ) {
		if ( ! is_array( $profile ) ) {
			$profile = array();
		}
		$provider_id = sanitize_key( (string) $provider_id );
		$defaults    = array(
			'modes'       => array( 'schema', 'mime', 'plain' ),
			'model_prefs' => array(),
			'max_tokens'  => 8192,
		);
		if ( in_array( $provider_id, array( 'openai', 'google' ), true ) ) {
			$defaults['max_tokens'] = 8192;
		} elseif ( 'anthropic' === $provider_id ) {
			$defaults['modes']       = array( 'mime', 'plain' );
			$defaults['max_tokens']  = 8192;
		} elseif ( 'deepseek' === $provider_id ) {
			$defaults['modes']       = array( 'mime', 'plain' );
			$defaults['model_prefs'] = array( 'deepseek-chat' );
			$defaults['max_tokens']  = 8192;
		}
		return wp_parse_args(
			$profile,
			array(
				'modes'       => $defaults['modes'],
				'model_prefs' => $defaults['model_prefs'],
				'max_tokens'  => $defaults['max_tokens'],
			)
		);
	}

	/**
	 * Resolved provider profile (modes, model prefs, token cap).
	 *
	 * @param string $provider_id Connector id.
	 * @return array{modes: string[], model_prefs: string[], max_tokens: int|null}
	 */
	private static function get_provider_profile( $provider_id ) {
		$provider_id = sanitize_key( (string) $provider_id );
		/**
		 * Filters generation profile for a WordPress AI connector.
		 *
		 * @param array  $profile {
		 *     @type string[] $modes       Ordered modes: schema, mime, plain.
		 *     @type string[] $model_prefs Optional model preference IDs.
		 *     @type int|null $max_tokens  Optional cap for this provider.
		 * }
		 * @param string $provider_id Registry connector id.
		 */
		$profile = apply_filters( 'wf_sn_ai_advisor_provider_profile', array(), $provider_id );
		if ( ! is_array( $profile ) ) {
			$profile = array();
		}
		$modes = isset( $profile['modes'] ) && is_array( $profile['modes'] ) ? $profile['modes'] : array( 'schema', 'mime', 'plain' );
		$modes = array_values(
			array_filter(
				array_map(
					static function ( $mode ) {
						return sanitize_key( (string) $mode );
					},
					$modes
				),
				static function ( $mode ) {
					return in_array( $mode, array( 'schema', 'mime', 'plain' ), true );
				}
			)
		);
		if ( empty( $modes ) ) {
			$modes = array( 'schema', 'mime', 'plain' );
		}
		$model_prefs = isset( $profile['model_prefs'] ) && is_array( $profile['model_prefs'] ) ? $profile['model_prefs'] : array();
		$max_tokens  = null;
		if ( isset( $profile['max_tokens'] ) && is_numeric( $profile['max_tokens'] ) ) {
			$max_tokens = max( 256, (int) $profile['max_tokens'] );
		}
		return array(
			'modes'       => $modes,
			'model_prefs' => $model_prefs,
			'max_tokens'  => $max_tokens,
		);
	}

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
		try {
			$registry = \WordPress\AiClient\AiClient::defaultRegistry();
		} catch ( \Throwable $e ) {
			return array();
		}
		if ( ! method_exists( $registry, 'isProviderConfigured' ) ) {
			return array();
		}
		$out = array();
		foreach ( self::get_registered_provider_ids( $registry ) as $id ) {
			try {
				if ( $registry->isProviderConfigured( $id ) ) {
					$out[] = $id;
				}
			} catch ( \Throwable $e ) {
				// AI Client may throw TypeError (e.g. cache returns bool instead of array).
				continue;
			}
		}
		return $out;
	}

	/**
	 * Admin URL for WordPress Settings → Connectors.
	 *
	 * @return string
	 */
	public static function get_connectors_admin_url() {
		if ( function_exists( 'wp_ai_connectors_admin_url' ) ) {
			return (string) \wp_ai_connectors_admin_url();
		}
		return admin_url( 'options-connectors.php' );
	}

	/**
	 * Metadata for one connector id (label, logo, configured state).
	 *
	 * @param string $id Connector / provider id.
	 * @return array{id: string, label: string, description: string, logo_url: string, is_configured: bool}
	 */
	public static function get_connector_metadata( $id ) {
		$id = sanitize_key( (string) $id );
		$label       = ucfirst( $id );
		$description = '';
		$logo_url    = '';

		if ( '' !== $id && function_exists( 'wp_get_connector' ) ) {
			$connector = wp_get_connector( $id );
			if ( is_array( $connector ) ) {
				if ( ! empty( $connector['name'] ) && is_string( $connector['name'] ) ) {
					$label = $connector['name'];
				}
				if ( ! empty( $connector['description'] ) && is_string( $connector['description'] ) ) {
					$description = $connector['description'];
				}
				if ( ! empty( $connector['logo_url'] ) && is_string( $connector['logo_url'] ) ) {
					$logo_url = $connector['logo_url'];
				}
			}
		}

		$is_configured = false;
		if ( '' !== $id && self::is_available() ) {
			try {
				$registry = \WordPress\AiClient\AiClient::defaultRegistry();
				if ( method_exists( $registry, 'isProviderConfigured' ) && $registry->hasProvider( $id ) ) {
					$is_configured = (bool) $registry->isProviderConfigured( $id );
				}
			} catch ( \Throwable $e ) {
				$is_configured = false;
			}
		}

		return array(
			'id'              => $id,
			'label'           => $label,
			'description'     => $description,
			'logo_url'        => $logo_url,
			'is_configured'   => $is_configured,
		);
	}

	/**
	 * Configured connectors with UI metadata for dropdowns and badges.
	 *
	 * @return array<int, array{id: string, label: string, description: string, logo_url: string, is_configured: bool}>
	 */
	public static function get_connectors_for_ui() {
		$out = array();
		foreach ( self::get_configured_providers() as $id ) {
			$out[] = self::get_connector_metadata( $id );
		}
		return $out;
	}

	/**
	 * Metadata for the stored or default connector selection.
	 *
	 * @return array{id: string, label: string, description: string, logo_url: string, is_configured: bool}|null
	 */
	public static function get_selected_connector_metadata() {
		$configured = self::get_configured_providers();
		if ( empty( $configured ) ) {
			return null;
		}
		$options = Wf_Sn_Ai_Advisor_Page::get_options();
		$stored  = isset( $options['last_connector_provider'] ) ? sanitize_key( (string) $options['last_connector_provider'] ) : '';
		if ( '' !== $stored && in_array( $stored, $configured, true ) ) {
			return self::get_connector_metadata( $stored );
		}
		return self::get_connector_metadata( $configured[0] );
	}

	/**
	 * Verify that a connector is configured and reachable.
	 *
	 * @param string $id Connector id.
	 * @return array{ok: bool, message: string}
	 */
	public static function test_connector( $id ) {
		$id = sanitize_key( (string) $id );
		if ( '' === $id ) {
			return array(
				'ok'      => false,
				'message' => __( 'No connector selected.', 'security-ninja' ),
			);
		}
		if ( ! self::is_available() ) {
			return array(
				'ok'      => false,
				'message' => __( 'WordPress AI Connectors are not available.', 'security-ninja' ),
			);
		}
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			return array(
				'ok'      => false,
				'message' => __( 'AI features are disabled on this site.', 'security-ninja' ),
			);
		}
		$configured = self::get_configured_providers();
		if ( ! in_array( $id, $configured, true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'This connector is not configured. Add your API key under Settings → Connectors.', 'security-ninja' ),
			);
		}
		$meta = self::get_connector_metadata( $id );
		if ( ! empty( $meta['is_configured'] ) ) {
			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: %s: connector display name */
					__( '%s is ready to use.', 'security-ninja' ),
					$meta['label']
				),
			);
		}
		return array(
			'ok'      => false,
			'message' => sprintf(
				/* translators: %s: connector display name */
				__( '%s could not be verified. Check your API key under Settings → Connectors.', 'security-ninja' ),
				$meta['label']
			),
		);
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
	 * @param array  $options           Optional: json_schema, max_tokens, request_type.
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
		$json_schema  = isset( $options['json_schema'] ) && is_array( $options['json_schema'] ) ? $options['json_schema'] : null;

		$profile = self::get_provider_profile( $provider_id );
		if ( null !== $profile['max_tokens'] && $max_tokens > (int) $profile['max_tokens'] ) {
			$max_tokens = (int) $profile['max_tokens'];
		}

		$result = self::run_generation_ladder(
			$provider_id,
			$system_instruction,
			$prompt_text,
			$max_tokens,
			$json_schema,
			$profile
		);

		if ( is_array( $result ) ) {
			$result['max_tokens_requested'] = $max_tokens;
		}

		if ( is_array( $result ) && empty( $result['ok'] ) && self::should_report_no_models_error( $result ) ) {
			return array(
				'ok'            => false,
				'error'         => sprintf(
					/* translators: %s: connector provider id */
					__( 'No AI model is available for provider "%s" with this prompt. Try another connector under Settings → Connectors, or check Security Advisor settings.', 'security-ninja' ),
					$provider_id
				),
				'attempt_count' => isset( $result['attempt_count'] ) ? (int) $result['attempt_count'] : 0,
			);
		}

		return is_array( $result ) ? $result : array(
			'ok'    => false,
			'error' => __( 'Request failed.', 'security-ninja' ),
		);
	}

	/**
	 * Whether the connector will use strict JSON schema output for this prompt.
	 *
	 * @param string                   $provider_id        Connector id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param array<string,mixed>|null $json_schema        JSON schema.
	 * @return bool
	 */
	public static function uses_schema_output( $provider_id, $system_instruction, $prompt_text, $json_schema ) {
		if ( null === $json_schema || ! is_array( $json_schema ) ) {
			return false;
		}
		$profile = self::get_provider_profile( $provider_id );
		$modes   = isset( $profile['modes'] ) && is_array( $profile['modes'] ) ? $profile['modes'] : array();
		if ( ! in_array( 'schema', $modes, true ) ) {
			return false;
		}
		$max_tokens = self::resolve_max_tokens( 'full_report', array() );
		if ( null !== $profile['max_tokens'] && $max_tokens > (int) $profile['max_tokens'] ) {
			$max_tokens = (int) $profile['max_tokens'];
		}
		return self::is_prompt_supported(
			$provider_id,
			$system_instruction,
			$prompt_text,
			$max_tokens,
			$json_schema,
			true,
			'schema',
			$profile
		);
	}

	/**
	 * Walk profile modes (schema → mime → plain) until one succeeds.
	 *
	 * @param string                   $provider_id        Provider id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param int                      $max_tokens         Max output tokens.
	 * @param array<string,mixed>|null $json_schema        JSON schema when structured output requested.
	 * @param array                    $profile            Provider profile from get_provider_profile().
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string, attempt_count?: int, generation_mode?: string}
	 */
	private static function run_generation_ladder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, array $profile ) {
		$result        = null;
		$attempt_count = 0;
		$modes         = isset( $profile['modes'] ) && is_array( $profile['modes'] ) ? $profile['modes'] : array( 'schema', 'mime', 'plain' );

		foreach ( $modes as $mode ) {
			if ( 'plain' !== $mode && null === $json_schema ) {
				continue;
			}
			if ( 'schema' === $mode && null === $json_schema ) {
				continue;
			}
			if ( ! self::is_mode_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $mode, $profile ) ) {
				continue;
			}
			$schema_for_mode = ( 'plain' === $mode ) ? null : $json_schema;
			$attempt         = self::execute_prompt(
				$provider_id,
				$system_instruction,
				$prompt_text,
				$max_tokens,
				$schema_for_mode,
				true,
				$mode,
				$profile
			);
			++$attempt_count;
			if ( ! empty( $attempt['ok'] ) ) {
				$attempt['attempt_count']   = $attempt_count;
				$attempt['generation_mode'] = $mode;
				return $attempt;
			}
			$result = $attempt;
		}

		if ( ! is_array( $result ) ) {
			$result = array(
				'ok'    => false,
				'error' => '',
			);
		}
		$result['attempt_count'] = $attempt_count;
		return $result;
	}

	/**
	 * Whether a generation mode passes WP feature detection.
	 *
	 * @param string                   $provider_id        Provider id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param int                      $max_tokens         Max output tokens.
	 * @param array<string,mixed>|null $json_schema        JSON schema.
	 * @param string                   $mode               schema, mime, or plain.
	 * @param array                    $profile            Provider profile.
	 * @return bool
	 */
	private static function is_mode_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $mode, array $profile ) {
		if ( 'plain' === $mode ) {
			return true;
		}
		return self::is_prompt_supported(
			$provider_id,
			$system_instruction,
			$prompt_text,
			$max_tokens,
			$json_schema,
			true,
			$mode,
			$profile
		);
	}

	/**
	 * Whether to replace a provider error with the friendly no-models message.
	 *
	 * @param array<string,mixed> $result Provider result payload.
	 * @return bool
	 */
	private static function should_report_no_models_error( array $result ) {
		return self::is_no_models_error( $result );
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
	 * @param array<string,mixed>|null $json_schema        Optional JSON schema.
	 * @param bool                     $force_provider     Whether to force selected provider.
	 * @param string                   $json_response_mode One of none, schema, mime.
	 * @return bool
	 */
	public static function is_prompt_supported( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $force_provider = true, $json_response_mode = 'none', $profile = null ) {
		if ( ! self::is_available() ) {
			return false;
		}
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			return false;
		}
		try {
			$builder = self::configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $force_provider, $json_response_mode, $profile );
			if ( ! is_object( $builder ) || ! method_exists( $builder, 'is_supported_for_text_generation' ) ) {
				return false;
			}
			$supported = $builder->is_supported_for_text_generation();
			return true === $supported;
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Build a WP AI Client prompt builder with advisor defaults.
	 *
	 * Temperature is omitted so providers use their defaults (compatible with
	 * Claude models that reject non-default sampling parameters).
	 *
	 * @param string                   $provider_id        Provider id.
	 * @param string                   $system_instruction System instruction.
	 * @param string                   $prompt_text        Prompt text.
	 * @param int                      $max_tokens         Max output tokens.
	 * @param array<string,mixed>|null $json_schema        Optional JSON schema.
	 * @param bool                     $force_provider     Whether to force selected provider.
	 * @param string                   $json_response_mode One of none, schema, mime.
	 * @return WP_AI_Client_Prompt_Builder|null
	 */
	private static function configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $force_provider = true, $json_response_mode = 'none', $profile = null ) {
		if ( ! function_exists( 'wp_ai_client_prompt' ) ) {
			return null;
		}
		$builder = wp_ai_client_prompt( $prompt_text )
			->using_system_instruction( $system_instruction )
			->using_max_tokens( $max_tokens );
		if ( $force_provider && '' !== (string) $provider_id ) {
			$builder = $builder->using_provider( $provider_id );
			$prefs   = self::get_model_preferences_for_provider( $provider_id, $profile );
			if ( ! empty( $prefs ) && method_exists( $builder, 'using_model_preference' ) ) {
				$builder = $builder->using_model_preference( ...$prefs );
			}
		}
		if ( 'schema' === $json_response_mode && null !== $json_schema ) {
			$builder = $builder->as_json_response( $json_schema );
		} elseif ( 'mime' === $json_response_mode && method_exists( $builder, 'as_output_mime_type' ) ) {
			$builder = $builder->as_output_mime_type( 'application/json' );
		}
		return $builder;
	}

	/**
	 * Build and run a single prompt request.
	 *
	 * @param string                   $provider_id         Provider id.
	 * @param string                   $system_instruction  System instruction.
	 * @param string                   $prompt_text         Prompt text.
	 * @param int                      $max_tokens          Max output tokens.
	 * @param array<string,mixed>|null $json_schema         Optional JSON schema.
	 * @param bool                     $force_provider      Whether to force selected provider.
	 * @param string                   $json_response_mode  One of none, schema, mime.
	 * @return array{ok: bool, text?: string, usage?: array, model?: string, error?: string}
	 */
	private static function execute_prompt( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $force_provider = true, $json_response_mode = 'none', $profile = null ) {
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
				$builder = self::configure_builder( $provider_id, $system_instruction, $prompt_text, $max_tokens, $json_schema, $force_provider, $json_response_mode, $profile );
				if ( ! is_object( $builder ) ) {
					return array(
						'ok'    => false,
						'error' => __( 'WordPress AI Connectors are not available.', 'security-ninja' ),
					);
				}
				$result = $builder->generate_text_result();
			} catch ( \Throwable $e ) {
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
	 * Optional model preferences from the wf_sn_ai_advisor_model_preferences filter.
	 *
	 * Security Ninja does not ship provider-specific defaults; model selection is delegated
	 * to WordPress AI Connectors when no filter overrides are present.
	 *
	 * @param string $provider_id Provider id.
	 * @return array<int, string>
	 */
	private static function get_model_preferences_for_provider( $provider_id, $profile = null ) {
		$provider_id = sanitize_key( (string) $provider_id );
		$defaults    = array();
		if ( is_array( $profile ) && ! empty( $profile['model_prefs'] ) && is_array( $profile['model_prefs'] ) ) {
			$defaults = $profile['model_prefs'];
		}
		/**
		 * Filters preferred model IDs for a connector (evaluated in order).
		 *
		 * @param array<int, string> $defaults    Default preference list from provider profile.
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
			} catch ( \Throwable $e ) {
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
}
