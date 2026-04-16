<?php
/**
 * Reusable “re-evaluate with AI” notice markup for Security Advisor.
 *
 * Use one helper so copy and structure stay consistent (settings saved, scans done, etc.).
 * Other flows can later call do_action( 'wf_sn_ai_advisor_should_reevaluate', $context ) from the main plugin.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Reevaluate_Notice
 */
class Wf_Sn_Ai_Advisor_Reevaluate_Notice {

	/**
	 * Default CSS class on the wrapper (BEM-friendly).
	 */
	const WRAPPER_CLASS = 'wf-sn-ai-reevaluate-notice';

	/**
	 * Render the notice block.
	 *
	 * @param array $args {
	 *     @type string $message   Main text (required).
	 *     @type string $cta_label Button/link label (optional).
	 *     @type string $cta_href  URL or href; use #anchor for in-page (optional).
	 *     @type string $context   Slug for analytics/future hooks (optional).
	 * }
	 * @return void Echoes HTML.
	 */
	public static function render( array $args ) {
		$message = isset( $args['message'] ) ? (string) $args['message'] : '';
		if ( '' === $message ) {
			return;
		}
		$cta_label = isset( $args['cta_label'] ) ? (string) $args['cta_label'] : '';
		$cta_href  = isset( $args['cta_href'] ) ? (string) $args['cta_href'] : '';
		$context   = isset( $args['context'] ) ? sanitize_key( (string) $args['context'] ) : '';

		$wrapper_class = 'notice notice-info ' . self::WRAPPER_CLASS;
		if ( '' !== $context ) {
			$wrapper_class .= ' ' . self::WRAPPER_CLASS . '--' . $context;
		}

		echo '<div class="' . esc_attr( $wrapper_class ) . '" role="status"';
		if ( '' !== $context ) {
			echo ' data-context="' . esc_attr( $context ) . '"';
		}
		echo '>';
		echo '<div class="' . esc_attr( self::WRAPPER_CLASS . '__inner' ) . '">';
		echo '<span class="dashicons dashicons-yes-alt ' . esc_attr( self::WRAPPER_CLASS . '__icon' ) . '" aria-hidden="true"></span>';
		echo '<p class="' . esc_attr( self::WRAPPER_CLASS . '__message' ) . '">' . esc_html( $message ) . '</p>';
		if ( '' !== $cta_label && '' !== $cta_href ) {
			$href = $cta_href;
			if ( preg_match( '/^#[\w-]+$/', $href ) ) {
				$href = esc_attr( $href );
			} else {
				$href = esc_url( $href );
			}
			echo '<a class="button button-primary ' . esc_attr( self::WRAPPER_CLASS . '__cta' ) . '" href="' . $href . '">' . esc_html( $cta_label ) . '</a>';
		}
		echo '</div></div>';
	}

	/**
	 * Admin notice after advisor settings save (redirect with settings-updated=1).
	 */
	public static function admin_notice_settings_saved() {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( Wf_Sn_Ai_Advisor::SLUG !== $page ) {
			return;
		}
		if ( empty( $_GET['settings-updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		self::render(
			array(
				'message'   => __( 'Settings saved. Run Security Tests if needed, then generate a fresh Security Audit so advice matches your site.', 'security-ninja' ),
				'cta_label' => __( 'Re-evaluate with AI', 'security-ninja' ),
				'cta_href'  => self::default_generate_section_id(),
				'context'   => 'settings_saved',
			)
		);
	}

	/**
	 * HTML id of the generate block (single source for anchors).
	 *
	 * @return string Hash fragment including #.
	 */
	public static function default_generate_section_id() {
		return '#wf_sn_ai_section_full_report';
	}
}
