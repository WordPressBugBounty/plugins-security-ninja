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
        require_once $dir . '/class-wf-sn-ai-advisor-chips.php';
        require_once $dir . '/class-wf-sn-ai-advisor-page.php';
        require_once $dir . '/class-wf-sn-ai-advisor-reevaluate-notice.php';
        add_action( 'admin_enqueue_scripts', array(__CLASS__, 'enqueue_scripts') );
        add_action( 'admin_post_wf_sn_ai_advisor_save_settings', array(__CLASS__, 'handle_save_settings') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'request', array(__CLASS__, 'ajax_request') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'preview_data', array(__CLASS__, 'ajax_preview_data') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'delete_report', array(__CLASS__, 'ajax_delete_report') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'chip_history_page', array(__CLASS__, 'ajax_chip_history_page') );
        add_action( 'admin_notices', array(__CLASS__, 'connectors_page_notice') );
        add_action( 'admin_notices', array(__CLASS__, 'advisor_settings_saved_notice'), 5 );
    }

    /**
     * Re-evaluate notice after saving Security Advisor settings.
     */
    public static function advisor_settings_saved_notice() {
        Wf_Sn_Ai_Advisor_Reevaluate_Notice::admin_notice_settings_saved();
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
        $chip_history_page_size = (int) apply_filters( 'wf_sn_ai_advisor_chip_history_page_size', 15 );
        $chip_history_page_size = max( 5, min( 25, $chip_history_page_size ) );
        wp_localize_script( 'wf-sn-ai-advisor', 'wfSnAiAdvisor', array(
            'ajaxurl'             => admin_url( 'admin-ajax.php' ),
            'nonce'               => wp_create_nonce( 'wf_sn_ai_advisor' ),
            'connectors'          => $configured,
            'uiLocale'            => $ui_locale,
            'improvementLinks'    => self::get_improvement_links(),
            'baseUrlPath'         => $base_url_path,
            'chips'               => Wf_Sn_Ai_Advisor_Chips::get_chips_for_ui(),
            'chipHistoryPageSize' => $chip_history_page_size,
            'strings'             => array(
                'requestFailed'            => __( 'Request failed.', 'security-ninja' ),
                'riskLabel'                => __( 'Risk: %s', 'security-ninja' ),
                'executiveSummary'         => __( 'Executive summary', 'security-ninja' ),
                'overview'                 => __( 'Overview', 'security-ninja' ),
                'topImprovements'          => __( 'Top improvements', 'security-ninja' ),
                'activityLast7Days'        => __( 'Activity (last 7 days)', 'security-ninja' ),
                'trendLabel'               => __( 'Trend: %s', 'security-ninja' ),
                'stagePreparing'           => __( 'Preparing security data', 'security-ninja' ),
                'stageSending'             => __( 'Sending to AI', 'security-ninja' ),
                'stageWaiting'             => __( 'Waiting for response', 'security-ninja' ),
                'stageReceived'            => __( 'Response received.', 'security-ninja' ),
                'waitingTips'              => array(
                    __( 'Run Security Tests regularly so your report stays up to date.', 'security-ninja' ),
                    __( 'Strong passwords and two-factor authentication reduce brute-force risk.', 'security-ninja' ),
                    __( 'Keeping WordPress, themes, and plugins updated closes known vulnerabilities.', 'security-ninja' ),
                    __( 'Limit login attempts and disable XML-RPC if you do not need them.', 'security-ninja' ),
                    __( 'Review failed and blocked login activity in Security Ninja to spot attacks.', 'security-ninja' ),
                    __( 'Back up your site before making security changes suggested in the report.', 'security-ninja' )
                ),
                'generating'               => __( 'Generating…', 'security-ninja' ),
                'saving'                   => __( 'Saving', 'security-ninja' ),
                'settingsSaved'            => __( 'Settings saved.', 'security-ninja' ),
                'settingsSaveError'        => __( 'Unable to save settings.', 'security-ninja' ),
                'previous7Days'            => __( 'Previous 7 days', 'security-ninja' ),
                'last7Days'                => __( 'Last 7 days', 'security-ninja' ),
                'openInSn'                 => __( 'Open in Security Ninja', 'security-ninja' ),
                'connectionError'          => __( 'The request failed. Check your connection and try again.', 'security-ninja' ),
                'assistantTitle'           => __( 'Assistant', 'security-ninja' ),
                'assistantHint'            => __( 'Choose a suggested prompt at the bottom. Follow-ups use your latest saved audit.', 'security-ninja' ),
                'loadOlderMessages'        => __( 'Load older messages', 'security-ninja' ),
                'assistantArchiveTitle'    => __( 'All saved answers (table view)', 'security-ninja' ),
                'assistantArchiveSummary'  => __( 'Same entries as the conversation above, in a compact table.', 'security-ninja' ),
                'chipRunning'              => __( 'Working…', 'security-ninja' ),
                'deleteReport'             => __( 'Delete', 'security-ninja' ),
                'deleteConfirm'            => __( 'Delete this entry permanently?', 'security-ninja' ),
                'showMoreIssues'           => __( 'Show more issues', 'security-ninja' ),
                'showFewerIssues'          => __( 'Show fewer', 'security-ninja' ),
                'quickInfo'                => __( 'Quick info', 'security-ninja' ),
                'deltaAnalysis'            => __( 'Delta analysis', 'security-ninja' ),
                'issuesTitle'              => __( 'Issues needing attention', 'security-ninja' ),
                'recentAssistant'          => __( 'Recent assistant answers', 'security-ninja' ),
                'modelTokens'              => __( 'Model / tokens', 'security-ninja' ),
                'usageLine'                => __( 'Model: %1$s · In: %2$s · Out: %3$s', 'security-ninja' ),
                'deltaPlaceholder'         => __( 'Run “What changed since last report?” under Follow-ups when you have two saved audits.', 'security-ninja' ),
                'latestSecurityReport'     => __( 'Latest Security Report', 'security-ninja' ),
                'justNow'                  => __( 'Just now', 'security-ninja' ),
                'viewFullReport'           => __( 'View Full Report', 'security-ninja' ),
                'attackActivityChartTitle' => __( 'Attack Activity (last 7 days)', 'security-ninja' ),
                'attackActivityChartAria'  => __( 'Attack activity comparison: previous 7 days vs last 7 days', 'security-ninja' ),
                'previewDataLink'          => __( 'Preview data sent to AI', 'security-ninja' ),
                'previewModalTitle'        => __( 'Preview of data sent to AI', 'security-ninja' ),
                'previewLoading'           => __( 'Loading…', 'security-ninja' ),
                'previewError'             => __( 'Could not load preview.', 'security-ninja' ),
                'closeModal'               => __( 'Close', 'security-ninja' ),
                'chipNewItems'             => __( 'New items (%d)', 'security-ninja' ),
                'chipResolvedItems'        => __( 'Resolved (%d)', 'security-ninja' ),
                'chipNotes'                => __( 'Notes', 'security-ninja' ),
                'chipMoreDetail'           => __( 'More detail', 'security-ninja' ),
                'chipShowFullAnswer'       => __( 'Show full answer', 'security-ninja' ),
                'promptEchoPrefix'         => '%s',
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
        $allowed = array('full_report', Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE);
        if ( !in_array( $request_type, $allowed, true ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request type.', 'security-ninja' ),
            ) );
        }
        if ( !self::passes_rate_limit() ) {
            wp_send_json_error( array(
                'message' => __( 'Too many AI requests in the last hour. Please wait and try again.', 'security-ninja' ),
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
        $prompt_id = '';
        if ( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type ) {
            $prompt_id = ( isset( $_POST['prompt_id'] ) ? sanitize_key( wp_unslash( $_POST['prompt_id'] ) ) : '' );
            if ( !Wf_Sn_Ai_Advisor_Chips::is_valid_prompt_id( $prompt_id ) ) {
                wp_send_json_error( array(
                    'message' => __( 'Invalid request.', 'security-ninja' ),
                ) );
            }
            if ( !Wf_Sn_Ai_Advisor_Chips::is_visible( $prompt_id ) ) {
                wp_send_json_error( array(
                    'message' => __( 'This prompt is not available for your current reports.', 'security-ninja' ),
                ) );
            }
        }
        $context = Wf_Sn_Ai_Advisor_Payload::build( 'full_report', $ui_locale );
        if ( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type ) {
            $context['prompt_id'] = $prompt_id;
            $two = Wf_Sn_Ai_Advisor_Reports::get_latest_two_full_reports();
            $parent_id = 0;
            if ( !empty( $two[0]['report_text'] ) && is_string( $two[0]['report_text'] ) ) {
                $context['report_a'] = $two[0]['report_text'];
                $context['report_a_id'] = ( isset( $two[0]['id'] ) ? (int) $two[0]['id'] : 0 );
                $parent_id = $context['report_a_id'];
            } else {
                $context['report_a'] = '';
                $context['report_a_id'] = 0;
            }
            if ( !empty( $two[1]['report_text'] ) && is_string( $two[1]['report_text'] ) ) {
                $context['report_b'] = $two[1]['report_text'];
                $context['report_b_id'] = ( isset( $two[1]['id'] ) ? (int) $two[1]['id'] : 0 );
            } else {
                $context['report_b'] = '';
                $context['report_b_id'] = 0;
            }
            $context['parent_report_id'] = $parent_id;
        }
        $prompts = Wf_Sn_Ai_Advisor_Prompts::get( $request_type, $context );
        $prompt_text = $prompts['prompt'];
        $token_in_est = Wf_Sn_Ai_Advisor_Reports::estimate_input_tokens( $prompts['system_instruction'], $prompt_text );
        $text = '';
        $report = null;
        $chip_parsed = null;
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
        $usage = ( !empty( $result['usage'] ) && is_array( $result['usage'] ) ? $result['usage'] : array() );
        $token_input = self::resolve_input_tokens_from_usage( $usage, $token_in_est );
        $token_output = null;
        if ( '' === $error && '' !== $text ) {
            if ( 'full_report' === $request_type ) {
                $report = self::decode_report_json_string( $text );
                if ( !is_array( $report ) ) {
                    $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                    $report = null;
                }
            } else {
                $chip_parsed = self::decode_report_json_string( $text );
                if ( !is_array( $chip_parsed ) || !self::validate_chip_response( $prompt_id, $chip_parsed ) ) {
                    $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                    $chip_parsed = null;
                }
            }
        }
        if ( '' === $error && 'full_report' === $request_type && is_array( $report ) ) {
            $token_output = self::resolve_output_tokens_from_usage( $usage, wp_json_encode( $report ) );
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
        $chip_report_id = 0;
        if ( '' === $error && Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type && is_array( $chip_parsed ) ) {
            $token_output = self::resolve_output_tokens_from_usage( $usage, wp_json_encode( $chip_parsed ) );
            $store = array(
                'prompt_id'        => $prompt_id,
                'response'         => $chip_parsed,
                'generated_at'     => gmdate( 'c' ),
                'parent_report_id' => ( isset( $context['parent_report_id'] ) ? (int) $context['parent_report_id'] : 0 ),
            );
            $inserted = Wf_Sn_Ai_Advisor_Reports::insert_report(
                wp_json_encode( $store ),
                'wordpress_connectors',
                $model_used,
                $token_input,
                $token_output,
                Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE
            );
            if ( false !== $inserted ) {
                $chip_report_id = (int) $inserted;
            }
        }
        if ( class_exists( '\\WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
            \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                'ai_advisor',
                'ai_advisor_request',
                __( 'AI Security Advisor request executed.', 'security-ninja' ),
                array(
                    'request_type' => $request_type,
                    'prompt_id'    => $prompt_id,
                    'provider'     => 'wordpress_connectors',
                )
            );
        }
        if ( '' !== $error ) {
            wp_send_json_error( array(
                'message' => $error,
            ) );
        }
        $usage_out = array(
            'token_input'  => (int) $token_input,
            'token_output' => ( null !== $token_output ? (int) $token_output : 0 ),
            'model'        => $model_used,
        );
        if ( 'full_report' === $request_type ) {
            wp_send_json_success( array(
                'report'   => $report,
                'raw_text' => $text,
                'usage'    => $usage_out,
            ) );
        }
        $chip_success = array(
            'prompt_id' => $prompt_id,
            'response'  => $chip_parsed,
            'raw_text'  => $text,
            'usage'     => $usage_out,
            'report_id' => $chip_report_id,
        );
        if ( $chip_report_id > 0 ) {
            $saved_row = Wf_Sn_Ai_Advisor_Reports::get_row_by_id( $chip_report_id );
            if ( is_array( $saved_row ) && !empty( $saved_row['created'] ) ) {
                $chip_success = array_merge( $chip_success, self::chip_created_client_fields( (string) $saved_row['created'] ) );
            }
        }
        wp_send_json_success( $chip_success );
    }

    /**
     * AJAX: paginated chip (assistant) history for the convo thread.
     */
    public static function ajax_chip_history_page() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        self::ensure_tables();
        $offset = ( isset( $_POST['offset'] ) ? (int) $_POST['offset'] : 0 );
        $limit = ( isset( $_POST['limit'] ) ? (int) $_POST['limit'] : 15 );
        $limit = max( 5, min( 25, $limit ) );
        $offset = max( 0, $offset );
        $rows = Wf_Sn_Ai_Advisor_Reports::get_reports( $limit, $offset, Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE );
        $items = array();
        foreach ( $rows as $row ) {
            if ( !is_array( $row ) ) {
                continue;
            }
            $formatted = self::format_chip_row_for_client( $row );
            if ( null !== $formatted ) {
                $items[] = $formatted;
            }
        }
        $total = Wf_Sn_Ai_Advisor_Reports::count_by_request_type( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE );
        $next_off = $offset + count( $rows );
        $has_more = $next_off < $total;
        wp_send_json_success( array(
            'items'       => $items,
            'has_more'    => $has_more,
            'next_offset' => $next_off,
        ) );
    }

    /**
     * MySQL `created` value formatted for the convo UI (ISO + localized display).
     *
     * @param string $mysql_created Datetime string from DB.
     * @return array{created: string, created_iso: string, created_display: string}
     */
    private static function chip_created_client_fields( $mysql_created ) {
        if ( !is_string( $mysql_created ) || '' === $mysql_created ) {
            return array(
                'created'         => '',
                'created_iso'     => '',
                'created_display' => '',
            );
        }
        $ts = strtotime( $mysql_created );
        if ( false === $ts ) {
            return array(
                'created'         => $mysql_created,
                'created_iso'     => '',
                'created_display' => '',
            );
        }
        $fmt = sprintf( '%s %s', get_option( 'date_format' ), get_option( 'time_format' ) );
        return array(
            'created'         => $mysql_created,
            'created_iso'     => wp_date( 'c', $ts ),
            'created_display' => wp_date( $fmt, $ts ),
        );
    }

    /**
     * Decode one DB row into a client payload for the convo thread (full response + usage).
     *
     * @param array $row DB row.
     * @return array<string, mixed>|null
     */
    private static function format_chip_row_for_client( array $row ) {
        $id = ( isset( $row['id'] ) ? (int) $row['id'] : 0 );
        $text = ( isset( $row['report_text'] ) ? $row['report_text'] : '' );
        if ( $id <= 0 || !is_string( $text ) || '' === $text ) {
            return null;
        }
        $dec = json_decode( $text, true );
        if ( !is_array( $dec ) || empty( $dec['prompt_id'] ) || empty( $dec['response'] ) || !is_array( $dec['response'] ) ) {
            return null;
        }
        $defs = Wf_Sn_Ai_Advisor_Chips::definitions();
        $pid = sanitize_key( (string) $dec['prompt_id'] );
        $label = ( isset( $defs[$pid]['label'] ) ? $defs[$pid]['label'] : $pid );
        $cf = self::chip_created_client_fields( ( isset( $row['created'] ) ? (string) $row['created'] : '' ) );
        return array_merge( $cf, array(
            'id'           => $id,
            'prompt_id'    => $pid,
            'prompt_label' => $label,
            'response'     => $dec['response'],
            'usage'        => array(
                'model'        => ( isset( $row['model'] ) ? (string) $row['model'] : '' ),
                'token_input'  => ( isset( $row['token_input'] ) ? (int) $row['token_input'] : 0 ),
                'token_output' => ( isset( $row['token_output'] ) && null !== $row['token_output'] ? (int) $row['token_output'] : 0 ),
            ),
        ) );
    }

    /**
     * AJAX: delete one advisor DB row.
     */
    public static function ajax_delete_report() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        $id = ( isset( $_POST['id'] ) ? (int) $_POST['id'] : 0 );
        if ( $id <= 0 ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request.', 'security-ninja' ),
            ) );
        }
        self::ensure_tables();
        $row = Wf_Sn_Ai_Advisor_Reports::get_row_by_id( $id );
        if ( null === $row ) {
            wp_send_json_error( array(
                'message' => __( 'Not found.', 'security-ninja' ),
            ) );
        }
        $rt = ( isset( $row['request_type'] ) ? sanitize_key( (string) $row['request_type'] ) : '' );
        if ( 'full_report' !== $rt && Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE !== $rt ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request.', 'security-ninja' ),
            ) );
        }
        $ok = Wf_Sn_Ai_Advisor_Reports::delete_report( $id );
        if ( !$ok ) {
            wp_send_json_error( array(
                'message' => __( 'Could not delete.', 'security-ninja' ),
            ) );
        }
        delete_transient( 'secnin_dashboard_ai_advisor' );
        wp_send_json_success( array(
            'id' => $id,
        ) );
    }

    /**
     * Per-user rolling window rate limit for AI calls.
     *
     * @return bool
     */
    private static function passes_rate_limit() {
        $max = (int) apply_filters( 'wf_sn_ai_advisor_rate_limit', 20 );
        if ( $max <= 0 ) {
            return true;
        }
        $uid = get_current_user_id();
        if ( $uid <= 0 ) {
            return false;
        }
        $key = 'wf_sn_ai_advisor_rl_' . $uid;
        $data = get_transient( $key );
        if ( !is_array( $data ) || !isset( $data['c'], $data['started'] ) ) {
            set_transient( $key, array(
                'c'       => 1,
                'started' => time(),
            ), HOUR_IN_SECONDS );
            return true;
        }
        if ( time() - (int) $data['started'] > HOUR_IN_SECONDS ) {
            set_transient( $key, array(
                'c'       => 1,
                'started' => time(),
            ), HOUR_IN_SECONDS );
            return true;
        }
        if ( (int) $data['c'] >= $max ) {
            return false;
        }
        $data['c'] = (int) $data['c'] + 1;
        set_transient( $key, $data, HOUR_IN_SECONDS );
        return true;
    }

    /**
     * @param array $usage Usage from connector.
     * @param int   $fallback Estimated input tokens.
     * @return int
     */
    private static function resolve_input_tokens_from_usage( array $usage, $fallback ) {
        foreach ( array('input_tokens', 'prompt_tokens', 'prompt_token_count') as $k ) {
            if ( isset( $usage[$k] ) && is_numeric( $usage[$k] ) ) {
                return max( 0, (int) $usage[$k] );
            }
        }
        return max( 0, (int) $fallback );
    }

    /**
     * @param array  $usage Usage from connector.
     * @param string $text  Response body for estimation.
     * @return int
     */
    private static function resolve_output_tokens_from_usage( array $usage, $text ) {
        foreach ( array('output_tokens', 'completion_tokens', 'completion_token_count') as $k ) {
            if ( isset( $usage[$k] ) && is_numeric( $usage[$k] ) ) {
                return max( 0, (int) $usage[$k] );
            }
        }
        return Wf_Sn_Ai_Advisor_Reports::estimate_output_tokens( (string) $text );
    }

    /**
     * Validate decoded JSON for a chip.
     *
     * @param string $prompt_id Chip id.
     * @param array  $data      Decoded JSON.
     * @return bool
     */
    private static function validate_chip_response( $prompt_id, array $data ) {
        if ( in_array( $prompt_id, array('delta_since_last'), true ) ) {
            if ( empty( $data['delta_summary'] ) || !is_string( $data['delta_summary'] ) ) {
                return false;
            }
            foreach ( array('new_items', 'resolved_items') as $arr_key ) {
                if ( isset( $data[$arr_key] ) && !is_array( $data[$arr_key] ) ) {
                    return false;
                }
            }
            if ( isset( $data['priority_shifts'] ) && !is_string( $data['priority_shifts'] ) ) {
                return false;
            }
            if ( isset( $data['notes'] ) && !is_string( $data['notes'] ) ) {
                return false;
            }
            return true;
        }
        if ( !empty( $data['answer'] ) && is_string( $data['answer'] ) ) {
            if ( isset( $data['bullets'] ) && !is_array( $data['bullets'] ) ) {
                return false;
            }
            return true;
        }
        return false;
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
        $allowed = array('full_report', Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE);
        if ( !in_array( $request_type, $allowed, true ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request type.', 'security-ninja' ),
            ) );
        }
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
        if ( is_string( $error ) && '' !== $error && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- debug-only diagnostic.
            error_log( 'Security Ninja AI Advisor connector error: ' . substr( $error, 0, 500 ) );
        }
        return __( 'The AI request could not be completed. Try again or check your connector under Settings → Connectors.', 'security-ninja' );
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
