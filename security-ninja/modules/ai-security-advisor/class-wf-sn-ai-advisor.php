<?php

/**
 * AI Security Advisor – main bootstrap: menu, scripts, AJAX handlers.
 *
 * Loaded only when apply_filters( 'wf_sn_ai_advisor_enabled', true ). Capability: manage_options.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Ai_Advisor
 */
class Wf_Sn_Ai_Advisor {
    const SLUG = 'wf-sn-advisor';

    const AJAX_ACTION_PREFIX = 'wf_sn_ai_advisor_';

    /**
     * Bootstrap: load files and hook menu + AJAX.
     */
    public static function init() {
        $dir = __DIR__;
        require_once $dir . '/class-wf-sn-ai-advisor-aggregation.php';
        require_once $dir . '/class-wf-sn-ai-advisor-payload.php';
        require_once $dir . '/class-wf-sn-ai-advisor-feature-tiers.php';
        require_once $dir . '/class-wf-sn-ai-advisor-prompts.php';
        require_once $dir . '/class-wf-sn-ai-advisor-provider-wp-connectors.php';
        require_once $dir . '/class-wf-sn-ai-advisor-reports.php';
        require_once $dir . '/class-wf-sn-ai-advisor-page.php';
        add_action( 'admin_enqueue_scripts', array(__CLASS__, 'enqueue_scripts') );
        add_action( 'admin_post_wf_sn_ai_advisor_save_settings', array(__CLASS__, 'handle_save_settings') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'request', array(__CLASS__, 'ajax_request') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'preview_data', array(__CLASS__, 'ajax_preview_data') );
        add_action( 'admin_notices', array(__CLASS__, 'connectors_page_notice') );
    }

    /**
     * Callback for the Security Advisor submenu page.
     */
    public static function render_page() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        Wf_Sn_Ai_Advisor_Page::render();
    }

    /**
     * Enqueue script and style on our admin page only.
     *
     * @param string $hook_suffix Admin page hook.
     */
    public static function enqueue_scripts( $hook_suffix ) {
        if ( strpos( $hook_suffix, self::SLUG ) === false ) {
            return;
        }
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $ui_locale = ( isset( $options['ui_locale'] ) && '' !== $options['ui_locale'] ? $options['ui_locale'] : (( function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale() )) );
        $admin_url_parsed = wp_parse_url( admin_url( 'admin.php?page=wf-sn' ) );
        $base_url_path = (( isset( $admin_url_parsed['path'] ) ? $admin_url_parsed['path'] : '/wp-admin/admin.php' )) . (( isset( $admin_url_parsed['query'] ) ? '?' . $admin_url_parsed['query'] : '?page=wf-sn' ));
        $advisor_css = __DIR__ . '/css/ai-advisor.css';
        if ( file_exists( $advisor_css ) ) {
            wp_enqueue_style(
                'wf-sn-ai-advisor',
                plugins_url( 'css/ai-advisor.css', __FILE__ ),
                array('sn-css'),
                filemtime( $advisor_css )
            );
        }
        $deps = array('jquery');
        $ai_advisor_js = __DIR__ . '/js/ai-advisor.js';
        wp_enqueue_script(
            'wf-sn-ai-advisor',
            plugins_url( 'js/ai-advisor.js', __FILE__ ),
            $deps,
            ( file_exists( $ai_advisor_js ) ? filemtime( $ai_advisor_js ) : '1.0' ),
            true
        );
        wp_localize_script( 'wf-sn-ai-advisor', 'wfSnAiAdvisor', array(
            'ajaxurl'          => admin_url( 'admin-ajax.php' ),
            'ajaxUrl'          => admin_url( 'admin-ajax.php' ),
            'nonce'            => wp_create_nonce( 'wf_sn_ai_advisor' ),
            'connectors'       => $configured,
            'uiLocale'         => $ui_locale,
            'improvementLinks' => self::get_improvement_links(),
            'baseUrlPath'      => $base_url_path,
            'strings'          => array(
                'requestFailed'     => __( 'Request failed.', 'security-ninja' ),
                'riskLabel'         => __( 'Risk: %s', 'security-ninja' ),
                'executiveSummary'  => __( 'Executive summary', 'security-ninja' ),
                'overview'          => __( 'Overview', 'security-ninja' ),
                'topImprovements'   => __( 'Top improvements', 'security-ninja' ),
                'activityLast7Days' => __( 'Activity (last 7 days)', 'security-ninja' ),
                'trendLabel'        => __( 'Trend: %s', 'security-ninja' ),
                'stagePreparing'    => __( 'Preparing security data', 'security-ninja' ),
                'stageSending'      => __( 'Sending to AI', 'security-ninja' ),
                'stageWaiting'      => __( 'Waiting for response', 'security-ninja' ),
                'stageReceived'     => __( 'Response received.', 'security-ninja' ),
                'waitingTips'       => array(
                    __( 'Run Security Tests regularly so your report stays up to date.', 'security-ninja' ),
                    __( 'Strong passwords and two-factor authentication reduce brute-force risk.', 'security-ninja' ),
                    __( 'Keeping WordPress, themes, and plugins updated closes known vulnerabilities.', 'security-ninja' ),
                    __( 'Limit login attempts and disable XML-RPC if you do not need them.', 'security-ninja' ),
                    __( 'Review failed and blocked login activity in Security Ninja to spot attacks.', 'security-ninja' ),
                    __( 'Back up your site before making security changes suggested in the report.', 'security-ninja' )
                ),
                'generating'        => __( 'Generating…', 'security-ninja' ),
                'saving'            => __( 'Saving', 'security-ninja' ),
                'settingsSaved'     => __( 'Settings saved.', 'security-ninja' ),
                'settingsSaveError' => __( 'Unable to save settings.', 'security-ninja' ),
                'previous7Days'     => __( 'Previous 7 days', 'security-ninja' ),
                'last7Days'         => __( 'Last 7 days', 'security-ninja' ),
                'exportReport'      => __( 'Print / Copy report', 'security-ninja' ),
                'openInSn'          => __( 'Open in Security Ninja', 'security-ninja' ),
                'copied'            => __( 'Copied', 'security-ninja' ),
                'connectionError'   => __( 'The request failed. Check your connection and try again.', 'security-ninja' ),
                'previewDataLink'   => __( 'Preview data sent to AI', 'security-ninja' ),
                'previewModalTitle' => __( 'Preview of data sent to AI', 'security-ninja' ),
                'previewLoading'    => __( 'Loading…', 'security-ninja' ),
                'previewError'      => __( 'Could not load preview.', 'security-ninja' ),
                'closeModal'        => __( 'Close', 'security-ninja' ),
            ),
        ) );
    }

    /**
     * Improvement ID to hash fragment for the current plan (free vs Pro). JS builds full URL from location.origin + baseUrlPath + hash.
     *
     * @return array<string, string> Map of improvement id => hash (e.g. '#sn_tests').
     */
    public static function get_improvement_links() {
        $links = self::get_improvement_links_free();
        return $links;
    }

    /**
     * Improvement links for free plan (sn_tests, sn_overview, sn_vuln). Hash only; JS prepends origin + baseUrlPath.
     *
     * @return array<string, string>
     */
    private static function get_improvement_links_free() {
        return array(
            'run_tests'            => '#sn_tests',
            'sn_tests'             => '#sn_tests',
            'overview'             => '#sn_overview',
            'sn_overview'          => '#sn_overview',
            'sn_vuln'              => '#sn_vuln',
            'vulnerability'        => '#sn_vuln',
            'old_plugins'          => '#sn_vuln',
            'incompatible_plugins' => '#sn_vuln',
            'dangerous_files'      => '#sn_vuln',
            'add_security_headers' => '#sn_overview',
        );
    }

    public static function handle_save_settings() {
        if ( !isset( $_POST['wf_sn_ai_advisor_nonce'] ) ) {
            wp_die( 'Missing nonce.' );
        }
        check_admin_referer( 'wf_sn_ai_advisor_save_settings', 'wf_sn_ai_advisor_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $provider = ( !empty( $configured ) ? 'wordpress_connectors' : '' );
        Wf_Sn_Ai_Advisor_Page::set_option( 'provider', $provider );
        if ( isset( $_POST['wf_sn_ai_advisor_connector'] ) ) {
            $connector = sanitize_text_field( wp_unslash( $_POST['wf_sn_ai_advisor_connector'] ) );
            if ( in_array( $connector, $configured, true ) ) {
                Wf_Sn_Ai_Advisor_Page::set_option( 'last_connector_provider', $connector );
            }
        }
        $redirect = add_query_arg( array(
            'page'             => self::SLUG,
            'settings-updated' => 1,
        ), admin_url( 'admin.php' ) );
        wp_safe_redirect( $redirect );
        exit;
    }

    public static function ajax_request() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        $request_type = ( isset( $_POST['request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['request_type'] ) ) : '' );
        $allowed = array('full_report');
        if ( !in_array( $request_type, $allowed, true ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request type.', 'security-ninja' ),
            ) );
        }
        $ui_locale = '';
        if ( isset( $_POST['ui_locale'] ) ) {
            $ui_locale = sanitize_text_field( wp_unslash( $_POST['ui_locale'] ) );
        }
        self::ensure_tables();
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $connector_id = ( isset( $options['last_connector_provider'] ) ? $options['last_connector_provider'] : '' );
        if ( empty( $connector_id ) && !empty( $configured ) ) {
            $connector_id = $configured[0];
        }
        if ( '' !== $connector_id ) {
            Wf_Sn_Ai_Advisor_Page::set_option( 'last_connector_provider', $connector_id );
        }
        $context = Wf_Sn_Ai_Advisor_Payload::build( $request_type, $ui_locale );
        $prompts = Wf_Sn_Ai_Advisor_Prompts::get( $request_type, $context );
        $prompt_text = $prompts['prompt'];
        $token_input = Wf_Sn_Ai_Advisor_Reports::estimate_input_tokens( $prompts['system_instruction'], $prompt_text );
        $text = '';
        $report = null;
        $error = '';
        $result = array();
        if ( '' !== $connector_id ) {
            $result = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::generate_text( $connector_id, $prompts['system_instruction'], $prompt_text );
            if ( !empty( $result['ok'] ) ) {
                if ( isset( $result['text'] ) && is_string( $result['text'] ) ) {
                    $text = $result['text'];
                }
            } else {
                $error = ( isset( $result['error'] ) ? $result['error'] : __( 'Request failed.', 'security-ninja' ) );
                $error = self::normalize_connector_error( $error );
            }
        } else {
            $error = __( 'No AI connector is configured. Add one under Settings → Connectors, then choose it on the Security Advisor page.', 'security-ninja' );
        }
        $model_used = null;
        if ( !empty( $result['model'] ) && is_string( $result['model'] ) ) {
            $model_used = $result['model'];
        }
        if ( '' === $error && '' !== $text && null === $report ) {
            $report = self::decode_report_json_string( $text );
            if ( !is_array( $report ) ) {
                $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                $report = null;
            }
        }
        if ( '' === $error && is_array( $report ) ) {
            $token_output = ( isset( $result['usage']['output_tokens'] ) ? (int) $result['usage']['output_tokens'] : Wf_Sn_Ai_Advisor_Reports::estimate_output_tokens( wp_json_encode( $report ) ) );
            $stored_text = wp_json_encode( $report );
            Wf_Sn_Ai_Advisor_Reports::insert_report(
                $stored_text,
                'wordpress_connectors',
                $model_used,
                $token_input,
                $token_output,
                $request_type
            );
            delete_transient( 'secnin_dashboard_ai_advisor' );
        }
        if ( class_exists( '\\WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
            \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                'ai_advisor',
                'ai_advisor_request',
                __( 'AI Security Advisor request executed.', 'security-ninja' ),
                array(
                    'request_type' => $request_type,
                    'provider'     => 'wordpress_connectors',
                )
            );
        }
        if ( '' !== $error ) {
            wp_send_json_error( array(
                'message' => $error,
            ) );
        }
        wp_send_json_success( array(
            'report'   => $report,
            'raw_text' => $text,
        ) );
    }

    /**
     * AJAX handler: return the context (payload) sent to the AI for preview. No prompt or system instruction.
     */
    public static function ajax_preview_data() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        $request_type = ( isset( $_POST['request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['request_type'] ) ) : 'full_report' );
        $ui_locale = ( isset( $_POST['ui_locale'] ) ? sanitize_text_field( wp_unslash( $_POST['ui_locale'] ) ) : '' );
        self::ensure_tables();
        $context = Wf_Sn_Ai_Advisor_Payload::build( $request_type, $ui_locale );
        wp_send_json_success( array(
            'data' => $context,
        ) );
    }

    /**
     * Normalize common connector error strings to a user-friendly message.
     *
     * @param string $error Raw error from provider.
     * @return string
     */
    private static function normalize_connector_error( $error ) {
        $lower = ( is_string( $error ) ? strtolower( $error ) : '' );
        if ( strpos( $lower, 'rate limit' ) !== false || strpos( $lower, 'quota' ) !== false ) {
            return __( 'The AI service is temporarily unavailable. Try again in a few minutes.', 'security-ninja' );
        }
        if ( strpos( $lower, 'not configured' ) !== false || strpos( $lower, 'configuration' ) !== false ) {
            return __( 'The selected connector is not configured. Check Settings → Connectors.', 'security-ninja' );
        }
        return $error;
    }

    /**
     * Attempt to decode a JSON report object from a raw text response.
     *
     * @param string $text Raw model output.
     * @return array|null
     */
    private static function decode_report_json_string( $text ) {
        if ( !is_string( $text ) || '' === $text ) {
            return null;
        }
        $trimmed = trim( $text );
        // First try full string.
        $data = json_decode( $trimmed, true );
        if ( is_array( $data ) ) {
            return $data;
        }
        // If wrapped in fences or extra text, try to extract the first JSON object.
        $start = strpos( $trimmed, '{' );
        $end = strrpos( $trimmed, '}' );
        if ( false === $start || false === $end || $end <= $start ) {
            return null;
        }
        $json = substr( $trimmed, $start, $end - $start + 1 );
        $data = json_decode( $json, true );
        return ( is_array( $data ) ? $data : null );
    }

    /**
     * Ensure plugin tables exist before using aggregation/payload (e.g. wf_sn_el, wf_sn_ai_reports).
     */
    private static function ensure_tables() {
        global $wpdb;
        $table = $wpdb->prefix . 'wf_sn_el';
        if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
            if ( !function_exists( 'dbDelta' ) ) {
                require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            }
            if ( class_exists( '\\WPSecurityNinja\\Plugin\\Utils' ) && method_exists( '\\WPSecurityNinja\\Plugin\\Utils', 'create_tables_for_site' ) ) {
                \WPSecurityNinja\Plugin\Utils::create_tables_for_site( $wpdb->get_charset_collate() );
            }
        }
        Wf_Sn_Ai_Advisor_Reports::ensure_table();
    }

    /**
     * Show a notice on the Settings → Connectors page (WP 7) when Security Ninja is active.
     */
    public static function connectors_page_notice() {
        $screen = ( function_exists( 'get_current_screen' ) ? get_current_screen() : null );
        if ( !$screen || !isset( $screen->id ) ) {
            return;
        }
        // WordPress 7+ Settings → Connectors: wp-admin/options-connectors.php → screen id options-connectors.
        if ( 'options-connectors' !== $screen->id ) {
            return;
        }
        echo '<div class="notice notice-info"><p>' . esc_html__( 'Security Ninja uses the AI connectors configured on this page to generate Security Advisor reports. You can choose which connector to use on the Security Advisor page in the Security Ninja menu.', 'security-ninja' ) . '</p></div>';
    }

}
