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
	const OPTION_KEY    = 'wf_sn_ai_reevaluate_pending';

	/**
	 * Render the notice block.
	 *
	 * @param array $args {
	 *     @type string $message   Main text (required).
	 *     @type string $cta_label Button/link label (optional).
	 *     @type string $cta_href  URL or href; use #anchor for in-page (optional).
	 *     @type string $context   Slug for analytics/future hooks (optional).
	 * }
	 * @param bool  $dismissable Whether to show dismiss button.
	 * @return void Echoes HTML.
	 */
	public static function render( array $args, $dismissable = false ) {
		$message = isset( $args['message'] ) ? (string) $args['message'] : '';
		if ( '' === $message ) {
			return;
		}
		$cta_label = isset( $args['cta_label'] ) ? (string) $args['cta_label'] : '';
		$cta_href  = isset( $args['cta_href'] ) ? (string) $args['cta_href'] : '';
		$context   = isset( $args['context'] ) ? sanitize_key( (string) $args['context'] ) : '';

		$wrapper_class = 'notice notice-info ' . self::WRAPPER_CLASS;
		if ( $dismissable ) {
			$wrapper_class .= ' is-dismissible';
		}
		if ( '' !== $context ) {
			$wrapper_class .= ' ' . self::WRAPPER_CLASS . '--' . $context;
		}

		echo '<div class="' . esc_attr( $wrapper_class ) . '" role="status"';
		if ( '' !== $context ) {
			echo ' data-context="' . esc_attr( $context ) . '"';
		}
		echo ' data-dismiss-nonce="' . esc_attr( wp_create_nonce( 'wf_sn_ai_advisor_dismiss_reevaluate' ) ) . '"';
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
		self::set_pending( 'settings_saved' );
	}

	/**
	 * Set pending reevaluate notice context.
	 *
	 * @param string $context Context slug.
	 * @return void
	 */
	public static function set_pending( $context ) {
		$context = sanitize_key( (string) $context );
		if ( '' === $context ) {
			return;
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Reports' ) || Wf_Sn_Ai_Advisor_Reports::count_by_request_type( 'full_report' ) < 1 ) {
			return;
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ) {
			return;
		}
		if ( ! Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available() ) {
			return;
		}
		if ( empty( Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers() ) ) {
			return;
		}
		update_option( self::OPTION_KEY, $context, false );
	}

	/**
	 * Clear pending reevaluate state.
	 *
	 * @return void
	 */
	public static function clear_pending() {
		delete_option( self::OPTION_KEY );
	}

	/**
	 * Render pending notice on Security Ninja pages.
	 *
	 * @return void
	 */
	public static function admin_notice_pending() {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) || ! self::is_security_ninja_page() ) {
			return;
		}
		$context = get_option( self::OPTION_KEY, '' );
		if ( ! is_string( $context ) || '' === $context ) {
			return;
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ) {
			return;
		}
		if ( ! Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available() ) {
			return;
		}
		if ( empty( Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers() ) ) {
			return;
		}

		self::render(
			array(
				'message'   => self::message_for_context( $context ),
				'cta_label' => __( 'Re-evaluate with AI', 'security-ninja' ),
				'cta_href'  => admin_url( 'admin.php?page=' . Wf_Sn_Ai_Advisor::SLUG ) . self::default_generate_section_id(),
				'context'   => $context,
			),
			true
		);
	}

	/**
	 * Handle AJAX dismiss.
	 *
	 * @return void
	 */
	public static function ajax_dismiss() {
		check_ajax_referer( 'wf_sn_ai_advisor_dismiss_reevaluate', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Forbidden.', 'security-ninja' ) ) );
		}
		self::clear_pending();
		wp_send_json_success();
	}

	/**
	 * Print JS for dismissing pending notice.
	 *
	 * @return void
	 */
	public static function print_dismiss_script() {
		if ( ! is_admin() || ! self::is_security_ninja_page() ) {
			return;
		}
		?>
		<script>
		(function($){
			'use strict';
			$(document).on('click', '.<?php echo esc_js( self::WRAPPER_CLASS ); ?> .notice-dismiss', function () {
				var $notice = $(this).closest('.<?php echo esc_js( self::WRAPPER_CLASS ); ?>');
				var nonce = $notice.data('dismiss-nonce');
				if (!nonce) {
					return;
				}
				$.post(ajaxurl, { action: 'wf_sn_ai_advisor_dismiss_reevaluate', nonce: nonce });
			});
		})(jQuery);
		</script>
		<?php
	}

	/**
	 * @param string $context Context slug.
	 * @return string
	 */
	private static function message_for_context( $context ) {
		$messages = array(
			'settings_saved'          => __( 'Settings saved. Run Security Tests if needed, then generate a fresh Security Audit so advice matches your site.', 'security-ninja' ),
			'tests_completed'         => __( 'Security Tests finished. Generate a fresh Security Audit so the AI advice reflects your latest results.', 'security-ninja' ),
			'core_scan_completed'     => __( 'Core Scanner just finished. Re-evaluate with AI to include the latest file integrity findings.', 'security-ninja' ),
			'vuln_scan_completed'     => __( 'Vulnerability scan just finished. Re-evaluate with AI to prioritize newly detected vulnerabilities.', 'security-ninja' ),
			'malware_scan_completed'  => __( 'Malware scan results changed. Re-evaluate with AI for updated guidance.', 'security-ninja' ),
			'firewall_settings_saved' => __( 'Firewall settings changed. Re-evaluate with AI to get recommendations based on current protection settings.', 'security-ninja' ),
		);
		return isset( $messages[ $context ] ) ? $messages[ $context ] : __( 'Security settings changed. Re-evaluate with AI for updated guidance.', 'security-ninja' );
	}

	/**
	 * Whether current admin screen is Security Ninja page.
	 *
	 * @return bool
	 */
	private static function is_security_ninja_page() {
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return is_string( $page ) && strpos( $page, 'wf-sn' ) === 0;
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
