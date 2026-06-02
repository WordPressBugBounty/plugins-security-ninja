<?php
/**
 * AI Security Advisor – structured system instructions and prompt text (full report only).
 *
 * Anti-hallucination: strict, short system instructions and consistent formats.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Prompts
 */
class Wf_Sn_Ai_Advisor_Prompts {

	/**
	 * Get system instruction and user prompt text.
	 *
	 * @param string $request_type full_report or prompt_chip.
	 * @param array  $context      Privacy-safe context; for prompt_chip include prompt_id, report_a, report_b, parent_report_id.
	 * @return array{system_instruction: string, prompt: string}
	 */
	public static function get( $request_type, array $context ) {
		$tier_block = Wf_Sn_Ai_Advisor_Feature_Tiers::get_feature_tier_instructions();
		if ( 'prompt_chip' === $request_type ) {
			$prompt_id = isset( $context['prompt_id'] ) ? sanitize_key( (string) $context['prompt_id'] ) : '';
			return array(
				'system_instruction' => self::get_system_prompt_chip( $prompt_id ) . "\n\n" . $tier_block,
				'prompt'             => self::format_context_for_prompt(
					$context,
					array(
						'skip_keys' => array( 'prompt_id', 'parent_report_id', 'report_a', 'report_b', 'report_a_id', 'report_b_id' ),
					)
				),
			);
		}
		$context_text = self::format_context_for_prompt( $context );
		$system       = self::get_system_full_report() . "\n\n" . $tier_block;
		return array(
			'system_instruction' => $system,
			'prompt'             => $context_text,
		);
	}

	/**
	 * Format context array as readable text for the model (no PII).
	 *
	 * @param array $context From Payload::build().
	 * @param array $options Optional: skip_keys, defer_keys.
	 * @return string
	 */
	public static function format_context_for_prompt( array $context, array $options = array() ) {
		$defaults = array(
			'skip_keys'   => array(),
			'defer_keys'  => array( 'tests_with_guidance' ),
			'append_lines' => array(),
		);
		$options  = array_merge( $defaults, $options );

		if ( empty( $options['append_lines'] ) ) {
			$append = array();
			if ( ! empty( $context['report_a'] ) && is_string( $context['report_a'] ) ) {
				$append[] = 'latest_stored_full_report_json: ' . $context['report_a'];
			}
			if ( ! empty( $context['report_b'] ) && is_string( $context['report_b'] ) ) {
				$append[] = 'previous_stored_full_report_json: ' . $context['report_b'];
			}
			if ( ! empty( $append ) ) {
				$options['append_lines'] = $append;
			}
		}

		return self::format_context_lines( $context, $options );
	}

	/**
	 * Build key: value lines for prompt context.
	 *
	 * @param array $context Context array.
	 * @param array $options skip_keys, defer_keys, append_lines (list of raw lines).
	 * @return string
	 */
	private static function format_context_lines( array $context, array $options ) {
		$skip_keys    = isset( $options['skip_keys'] ) && is_array( $options['skip_keys'] ) ? $options['skip_keys'] : array();
		$defer_keys   = isset( $options['defer_keys'] ) && is_array( $options['defer_keys'] ) ? $options['defer_keys'] : array();
		$append_lines = isset( $options['append_lines'] ) && is_array( $options['append_lines'] ) ? $options['append_lines'] : array();

		$lines = array();
		foreach ( $context as $key => $value ) {
			if ( in_array( $key, $skip_keys, true ) || in_array( $key, $defer_keys, true ) ) {
				continue;
			}
			$lines[] = $key . ': ' . self::format_context_value( $value );
		}

		foreach ( $defer_keys as $defer_key ) {
			if ( empty( $context[ $defer_key ] ) || ! is_array( $context[ $defer_key ] ) ) {
				continue;
			}
			$lines[] = $defer_key . ': ' . wp_json_encode( $context[ $defer_key ] );
		}

		foreach ( $append_lines as $line ) {
			if ( is_string( $line ) && '' !== $line ) {
				$lines[] = $line;
			}
		}

		return implode( "\n", $lines );
	}

	/**
	 * Serialize one context value for a prompt line.
	 *
	 * @param mixed $value Context value.
	 * @return string
	 */
	private static function format_context_value( $value ) {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}
		if ( is_array( $value ) ) {
			return wp_json_encode( $value );
		}
		return (string) $value;
	}

	/**
	 * System block for a prompt chip (JSON-only answer).
	 *
	 * @param string $prompt_id Chip id.
	 * @return string
	 */
	private static function get_system_prompt_chip( $prompt_id ) {
		$base = 'You are a security advisor for WordPress (Security Ninja plugin). Answer using ONLY the context provided (current site data and any stored report JSON). Do not invent findings. Stay calm and practical: no hype, no fear-mongering, no marketing tone. Be brief.

Return ONE JSON object only. No markdown fences. No text before or after the JSON.

Language: Match ui_locale from context when set; otherwise English.

';

		switch ( $prompt_id ) {
			case 'delta_since_last':
				return $base . 'Task: Compare the latest vs previous stored full-report JSON with the CURRENT site context. Call out if stored reports may be stale vs current tests. Output JSON keys exactly:
{"delta_summary":"string (2-4 short sentences)","new_items":["string"],"resolved_items":["string"],"priority_shifts":"string (1-2 sentences)","notes":"string (optional, short)"}
Arrays may be empty. Be specific using text from the reports/tests; do not add issues not evidenced.';

			case 'what_improved':
				return $base . 'Task: Focus on what improved between the previous and latest stored full-report JSON and current context. Output JSON keys exactly:
{"answer":"string (2-4 sentences)","bullets":["string"]}
bullets optional (max 5 short items). Positive, factual tone.';

			case 'what_next':
			case 'most_urgent':
			case 'what_can_wait':
				return $base . 'Task: Prioritize next actions for this site using current context and the latest stored full-report JSON when present. For what_can_wait, name lower-priority items without sounding dismissive. Output JSON keys exactly:
{"answer":"string (2-4 sentences)","bullets":["string"]}
bullets optional (max 5).';

			default:
				return $base . 'Output JSON: {"answer":"string","bullets":[]}';
		}
	}

	/**
	 * Full report: executive summary (with attack volume), overview, improvements, activity.
	 *
	 * The model MUST return a single JSON object only, matching this schema:
	 * {
	 *   "executive_summary": string,
	 *   "overview": string,
	 *   "top_improvements": [
	 *     {
	 *       "id": string,
	 *       "title": string,
	 *       "short_label": string,
	 *       "details": string,
	 *       "risk": "low"|"medium"|"high"
	 *     }
	 *   ],
	 *   "activity": {
	 *     "summary": string,
	 *     "attack_volume_trend": "up"|"down"|"stable"|"unknown",
	 *     "attack_volume_reason": string
	 *   },
	 *   "meta": {
	 *     "language": string,
	 *     "model": string|null,
	 *     "generated_at": string
	 *   }
	 * }
	 *
	 * @return string
	 */
	private static function get_system_full_report() {
		return 'You are a security advisor for WordPress. Produce a single combined report as ONE JSON object only. Do not add any text before or after the JSON. Do not wrap JSON in markdown code fences. Use ONLY the structured context provided.

Assessment: Base your assessment solely on the test results and other context provided. Use tests_passed, tests_warning, and tests_failed for overall counts. tests_with_guidance lists each non-passing test with testid, status, title when available, the live finding, optional details, and a short product-approved guidance summary—use guidance as the authoritative explanation base; summarize and adapt, do not replace with generic advice. Evaluate severity from actual findings. You MUST use exact finding text from tests_with_guidance when describing issues. Also use feature flags, activity counts, plan_tier, attack_activity, and ui_locale. Do NOT say firewall, login protection, or 2FA are disabled if the context shows them enabled. Do not mention upgrading, licenses, or premium. Do not output a single numeric overall score or overall risk label.

Additional context fields may include: vulnerabilities (total and item list), core_scanner (counts and sample files), malware_scanner (Pro, when present), and recent_events. Use these fields when present. Mention specific plugin/theme names and CVE IDs only when they exist in the provided context. Never invent CVE IDs, plugin names, or file findings.

Product context: The user sees this report inside the WordPress plugin Security Ninja. The firewall, login protection, and 2FA flags refer to this plugin\'s Cloud Firewall, Login Protection, and 2FA features. When writing improvement details, refer to Security Ninja by name and to specific areas (e.g. Cloud Firewall, Login Protection) where it helps. Do NOT give generic numbered steps like "1. Open the security plugin dashboard" or "2. Locate the cloud firewall settings"—they sound vague and apply to any product. Either give one or two short, specific sentences (e.g. "In Security Ninja, enable the Cloud Firewall from the Cloud Firewall menu so traffic is inspected and blocked where needed.") or a brief explanation of why it matters.

Language: If the context contains non-empty ui_locale and ui_language_name, respond entirely in that language. Otherwise respond in English. Do not mix languages.

Structure (map your reasoning into the JSON fields):
Formatting: Use newline characters between sentences or paragraphs in executive_summary, overview, and in long improvement details so the report displays with clear line breaks.

1) EXECUTIVE SUMMARY (executive_summary): 2–3 short sentences. One sentence on attack volume (up/down/stable/unknown from counts and attack_activity). One or two sentences on posture and the single most important takeaway from real findings—not failure count alone. No score or risk label.

2) OVERVIEW (overview): 2–4 short sentences. Passing/warning/failing counts, key feature flags, one pattern from activity if relevant. Do not repeat the executive summary verbatim.

3) TOP IMPROVEMENTS (top_improvements): A prioritized array of the most impactful improvements (ONLY those available for the user\'s plan_tier). Base each improvement ONLY on failing or warning tests that appear in tests_with_guidance; do NOT invent or infer issues (e.g. do not mention "incompatible plugins" or "outdated plugins" or "dangerous files" unless tests_with_guidance contains that test with a finding). When the context provides finding or details for a test (e.g. plugin names, file names, specific messages), you MUST cite that exact information in the improvement title or details—e.g. "Update or replace the following plugins: [names from context]" or "Remove these files: [from context]". For each improvement you MUST:
- Set a stable id (for example, "enable_firewall", "add_security_headers", "incompatible_plugins", "old_plugins", "dangerous_files").
- Provide a short, clear title and a very short_label suitable for compact UI; include specific names from the test summary/details when present.
- In details: explain why this improvement matters and what to do in one or two short, product-specific sentences. Refer to Security Ninja and its areas (e.g. Cloud Firewall, Login Protection) where relevant. Do NOT output generic numbered steps (e.g. "1. Open the dashboard 2. Locate settings"); if you cannot give specific steps, give a brief actionable summary.
- Set risk to "low", "medium", or "high" based on how likely it is to break existing behavior. For improvements about MySQL/database permissions (e.g. restricting DB user permissions, id mysql_permissions), always set risk to "low" only—never medium or high.
- If risk is medium or high, explain in details that the change should be tested on staging first. For anything related to CSP, Permissions/Feature Policy, or HTTP security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, etc.), explicitly mention that these changes can break embeds (YouTube, Vimeo), analytics, CDN resources, or third-party widgets unless carefully configured.

4) ACTIVITY (activity): Interpret the aggregated counts and any attack_activity summary and what they suggest (for example, credential stuffing if failed_logins_7d is high, XML-RPC abuse if xmlrpc_blocks_7d is high). Set attack_volume_trend to "up", "down", "stable", or "unknown" and explain why in attack_volume_reason. The attack-volume takeaway must already appear in the executive summary; here you may add detail and one clear recommendation for what to do next.

Output rules:
- Return ONE JSON object only, matching the described schema. Do not include reasoning, chain-of-thought, or any text outside the JSON object.
- Limit top_improvements to at most 12 items (highest priority first).
- Do NOT wrap the JSON in markdown fences.
- Do NOT include comments or trailing commas.
- Do NOT add additional top-level keys beyond executive_summary, overview, top_improvements, and activity. Do not include meta; the plugin adds metadata server-side.';
	}
}
