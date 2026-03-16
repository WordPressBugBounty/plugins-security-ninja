<?php
/**
 * AI Security Advisor – WPSN API client: register, credits, complete.
 *
 * Uses Wf_Sn_Ai_Advisor_Api_Auth for both Pro and free. Available to all users.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Provider_Wpsn
 */
class Wf_Sn_Ai_Advisor_Provider_Wpsn {

	/**
	 * POST /register. Called only when user clicks "Register this site".
	 *
	 * @param string $email Optional. User email for register (Pro may send).
	 * @return array{ok: bool, error?: string, credits_remaining?: int, credits_total?: int}
	 */
	public static function register( $email = '' ) {
		$base = self::get_base_url();
		$auth = Wf_Sn_Ai_Advisor_Api_Auth::build_auth();
		$body = $auth['body_auth'];
		if ( $auth['is_pro'] && $email !== '' ) {
			$body['email'] = sanitize_email( $email );
		}
		if ( ! $auth['is_pro'] ) {
			$stored = get_option( Wf_Sn_Ai_Advisor_Api_Auth::OPTION_SITE_AUTH, array() );
			if ( ! empty( $stored['site_secret'] ) ) {
				$body['site_secret'] = $stored['site_secret'];
			}
		}

		$response = wp_remote_post(
			$base . 'register',
			array(
				'timeout'  => 15,
				'headers'  => array_merge(
					array( 'Content-Type' => 'application/json' ),
					$auth['headers']
				),
				'body'     => wp_json_encode( $body ),
				'blocking' => true,
			)
		);

		return self::parse_register_response( $response );
	}

	/**
	 * GET /credits.
	 *
	 * @return array{ok: bool, credits_remaining?: int, credits_total?: int, error?: string}
	 */
	public static function get_credits() {
		$base  = self::get_base_url();
		$auth  = Wf_Sn_Ai_Advisor_Api_Auth::build_auth();
		$url   = add_query_arg( $auth['body_auth'], $base . 'credits' );

		$response = wp_remote_get(
			$url,
			array(
				'timeout'  => 10,
				'headers'  => $auth['headers'],
				'blocking' => true,
			)
		);

		return self::parse_credits_response( $response );
	}

	/**
	 * POST /complete – send prompt and get AI text.
	 *
	 * @param string $system_instruction System instruction for the model.
	 * @param string $prompt             User/message text.
	 * @param array  $context            Privacy-safe context for request body.
	 * @param string $request_type       full_report (only supported type).
	 * @return array{ok: bool, report?: array, text?: string, credits_used?: int, credits_remaining?: int, usage?: array, model?: string, error?: string}
	 */
	public static function complete( $system_instruction, $prompt, array $context, $request_type = 'full_report' ) {
		$base = self::get_base_url();
		$auth = Wf_Sn_Ai_Advisor_Api_Auth::build_auth();

		$body = array_merge(
			$auth['body_auth'],
			array(
				'system_instruction' => $system_instruction,
				'prompt'             => $prompt,
				'context'            => $context,
				'request_type'       => $request_type,
			)
		);

		$response = wp_remote_post(
			$base . 'complete',
			array(
				'timeout'  => 60,
				'headers'  => array_merge(
					array( 'Content-Type' => 'application/json' ),
					$auth['headers']
				),
				'body'     => wp_json_encode( $body ),
				'blocking' => true,
			)
		);

		return self::parse_complete_response( $response );
	}

	private static function get_base_url() {
		$url = apply_filters( 'wf_sn_ai_api_base_url', 'https://api.wpsecurityninja.com/ai/v1' );
		$url = rtrim( $url, '/' );
		return $url . '/';
	}

	private static function parse_register_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code === 200 && is_array( $body ) ) {
			$out = array( 'ok' => true );
			if ( isset( $body['credits_remaining'] ) ) {
				$out['credits_remaining'] = (int) $body['credits_remaining'];
			}
			if ( isset( $body['credits_total'] ) ) {
				$out['credits_total'] = (int) $body['credits_total'];
			}
			return $out;
		}
		$error = isset( $body['error'] ) ? $body['error'] : __( 'Registration failed.', 'security-ninja' );
		return array( 'ok' => false, 'error' => $error );
	}

	private static function parse_credits_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code === 200 && is_array( $body ) ) {
			return array(
				'ok'                => true,
				'credits_remaining' => isset( $body['credits_remaining'] ) ? (int) $body['credits_remaining'] : 0,
				'credits_total'     => isset( $body['credits_total'] ) ? (int) $body['credits_total'] : 0,
			);
		}
		$error = isset( $body['error'] ) ? $body['error'] : __( 'Unable to load credit balance.', 'security-ninja' );
		return array( 'ok' => false, 'error' => $error );
	}

	private static function parse_complete_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code === 200 && is_array( $body ) ) {
			$out = array( 'ok' => true );
			if ( isset( $body['report'] ) && is_array( $body['report'] ) ) {
				$out['report'] = $body['report'];
			}
			if ( isset( $body['text'] ) && is_string( $body['text'] ) ) {
				$out['text'] = $body['text'];
			}
			if ( isset( $body['credits_used'] ) ) {
				$out['credits_used'] = (int) $body['credits_used'];
			}
			if ( isset( $body['credits_remaining'] ) ) {
				$out['credits_remaining'] = (int) $body['credits_remaining'];
			}
			if ( isset( $body['usage'] ) && is_array( $body['usage'] ) ) {
				$out['usage'] = $body['usage'];
			}
			if ( isset( $body['model'] ) && is_string( $body['model'] ) ) {
				$out['model'] = $body['model'];
			}
			return $out;
		}
		if ( $code === 402 ) {
			return array(
				'ok'                => false,
				'error'             => isset( $body['error'] ) ? $body['error'] : __( 'Insufficient credits.', 'security-ninja' ),
				'credits_remaining' => isset( $body['credits_remaining'] ) ? (int) $body['credits_remaining'] : 0,
			);
		}
		$error = isset( $body['error'] ) ? $body['error'] : __( 'Request failed.', 'security-ninja' );
		return array( 'ok' => false, 'error' => $error );
	}
}
