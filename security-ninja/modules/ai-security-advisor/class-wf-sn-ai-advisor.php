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

    const PENDING_SNAPSHOT_TRANSIENT = 'wf_sn_ai_advisor_pending_snapshot';

    const PENDING_META_TRANSIENT = 'wf_sn_ai_advisor_pending_meta';

    /**
     * Bootstrap: register hooks only. Heavy class files load via load_dependencies() when needed.
     */
    public static function init() {
        // Lightweight notice class: needed in admin/AJAX and on cron (core/malware/vuln scans
        // fire wf_sn_ai_advisor_should_reevaluate → handle_should_reevaluate → set_pending).
        require_once __DIR__ . '/class-wf-sn-ai-advisor-reevaluate-notice.php';
        require_once __DIR__ . '/class-wf-sn-ai-advisor-abilities.php';
        Wf_Sn_Ai_Advisor_Abilities::init();
        add_action( 'admin_enqueue_scripts', array(__CLASS__, 'enqueue_scripts') );
        add_action( 'admin_post_wf_sn_ai_advisor_save_settings', array(__CLASS__, 'handle_save_settings') );
        add_action( 'admin_post_wf_sn_ai_advisor_clear_history', array(__CLASS__, 'handle_clear_history') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'request', array(__CLASS__, 'ajax_request') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'prepare', array(__CLASS__, 'ajax_prepare') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'preview_data', array(__CLASS__, 'ajax_preview_data') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'delete_report', array(__CLASS__, 'ajax_delete_report') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'chip_history_page', array(__CLASS__, 'ajax_chip_history_page') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'test_connector', array(__CLASS__, 'ajax_test_connector') );
        add_action( 'wp_ajax_' . self::AJAX_ACTION_PREFIX . 'dismiss_reevaluate', array('WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reevaluate_Notice', 'ajax_dismiss') );
        add_action( 'admin_notices', array(__CLASS__, 'connectors_page_notice') );
        add_action( 'admin_notices', array(__CLASS__, 'advisor_settings_saved_notice'), 5 );
        add_action( 'admin_notices', array(__CLASS__, 'advisor_history_cleared_notice'), 5 );
        add_action( 'admin_notices', array(__CLASS__, 'advisor_connector_saved_notice'), 4 );
        add_action( 'admin_notices', array('WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reevaluate_Notice', 'admin_notice_pending'), 6 );
        add_action( 'admin_footer', array('WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reevaluate_Notice', 'print_dismiss_script') );
        add_action( 'wf_sn_ai_advisor_should_reevaluate', array(__CLASS__, 'handle_should_reevaluate') );
        add_action( 'security_ninja_done_testing', static function () {
            do_action( 'wf_sn_ai_advisor_should_reevaluate', 'tests_completed' );
        } );
        add_action( 'security_ninja_core_scanner_done_scanning', static function () {
            do_action( 'wf_sn_ai_advisor_should_reevaluate', 'core_scan_completed' );
        } );
        add_action( 'security_ninja_malware_scanner_done_scanning', static function () {
            do_action( 'wf_sn_ai_advisor_should_reevaluate', 'malware_scan_completed' );
        } );
        add_action( 'security_ninja_vulnerability_scan_done', static function () {
            do_action( 'wf_sn_ai_advisor_should_reevaluate', 'vuln_scan_completed' );
        } );
        add_action( 'security_ninja_firewall_settings_saved', static function () {
            do_action( 'wf_sn_ai_advisor_should_reevaluate', 'firewall_settings_saved' );
        } );
    }

    /**
     * Load AI Advisor class files once (not on every front-end / admin init).
     *
     * @return void
     */
    public static function load_dependencies() {
        static $loaded = false;
        if ( $loaded ) {
            return;
        }
        $loaded = true;
        $dir = __DIR__;
        require_once $dir . '/class-wf-sn-ai-advisor-aggregation.php';
        require_once $dir . '/class-wf-sn-ai-advisor-attack-activity.php';
        require_once $dir . '/class-wf-sn-ai-advisor-test-scores.php';
        require_once $dir . '/class-wf-sn-ai-advisor-improvements.php';
        require_once $dir . '/class-wf-sn-ai-advisor-payload.php';
        require_once $dir . '/class-wf-sn-ai-advisor-feature-tiers.php';
        require_once $dir . '/class-wf-sn-ai-advisor-prompts.php';
        require_once $dir . '/class-wf-sn-ai-advisor-schemas.php';
        require_once $dir . '/class-wf-sn-ai-advisor-provider-wp-connectors.php';
        require_once $dir . '/class-wf-sn-ai-advisor-reports.php';
        require_once $dir . '/class-wf-sn-ai-advisor-abilities.php';
        require_once $dir . '/class-wf-sn-ai-advisor-chips.php';
        require_once $dir . '/class-wf-sn-ai-advisor-readiness.php';
        require_once $dir . '/class-wf-sn-ai-advisor-page.php';
        require_once $dir . '/class-wf-sn-ai-advisor-reevaluate-notice.php';
        static $runtime_booted = false;
        if ( !$runtime_booted ) {
            $runtime_booted = true;
            Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::register_default_profiles();
        }
    }

    /**
     * Re-evaluate notice after saving Security Advisor settings.
     */
    public static function advisor_settings_saved_notice() {
        self::load_dependencies();
        Wf_Sn_Ai_Advisor_Reevaluate_Notice::admin_notice_settings_saved();
    }

    /**
     * Notice after AI connector settings are saved (no existing reports).
     */
    public static function advisor_connector_saved_notice() {
        if ( !is_admin() || !current_user_can( 'manage_options' ) ) {
            return;
        }
        $page = ( isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '' );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( self::SLUG !== $page ) {
            return;
        }
        if ( empty( $_GET['settings-updated'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return;
        }
        self::load_dependencies();
        if ( Wf_Sn_Ai_Advisor_Reports::count_by_request_type( 'full_report' ) >= 1 ) {
            return;
        }
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'AI settings saved. Your connector is ready — generate your first Security Advisor review below.', 'security-ninja' ) . '</p></div>';
    }

    /**
     * Notice after AI history was cleared.
     */
    public static function advisor_history_cleared_notice() {
        if ( !is_admin() || !current_user_can( 'manage_options' ) ) {
            return;
        }
        if ( empty( $_GET['ai_history_cleared'] ) || 'success' !== $_GET['ai_history_cleared'] ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return;
        }
        $page = ( isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '' );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( self::SLUG !== $page ) {
            return;
        }
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'AI reports and follow-up history cleared. Scan data and site checks are unchanged — generate a fresh review when ready.', 'security-ninja' ) . '</p></div>';
    }

    /**
     * Schedule re-evaluate notice for plugin flows.
     *
     * @param string $context Context slug.
     * @return void
     */
    public static function handle_should_reevaluate( $context ) {
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Reevaluate_Notice', false ) ) {
            require_once __DIR__ . '/class-wf-sn-ai-advisor-reevaluate-notice.php';
        }
        Wf_Sn_Ai_Advisor_Reevaluate_Notice::set_pending( (string) $context );
    }

    /**
     * Shared AI Advisor card state for Overview, dashboard widget, and Advisor page.
     *
     * @return array{available: bool, state: int, last_reviewed: string, teaser: string, has_connectors: bool, has_reports: bool, advisor_url: string, connector_label: string}
     */
    public static function get_card_state() {
        self::load_dependencies();
        $advisor_url = admin_url( 'admin.php?page=wf-sn-advisor' );
        $state = array(
            'available'       => false,
            'state'           => 1,
            'last_reviewed'   => '',
            'teaser'          => '',
            'has_connectors'  => false,
            'has_reports'     => false,
            'advisor_url'     => $advisor_url,
            'connector_label' => '',
        );
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ) {
            return $state;
        }
        $available = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available();
        $state['available'] = $available;
        if ( !$available ) {
            return $state;
        }
        try {
            $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
            $options = Wf_Sn_Ai_Advisor_Page::get_options();
            $site_registered = !empty( $options['site_registered'] );
            $ready = is_array( $configured ) && count( $configured ) > 0 || $site_registered;
            $state['has_connectors'] = !empty( $configured );
            $selected_meta = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_selected_connector_metadata();
            if ( is_array( $selected_meta ) && !empty( $selected_meta['label'] ) ) {
                $state['connector_label'] = (string) $selected_meta['label'];
            } elseif ( !empty( $options['last_connector_provider'] ) ) {
                $state['connector_label'] = (string) $options['last_connector_provider'];
            } elseif ( !empty( $configured[0] ) ) {
                $state['connector_label'] = ucfirst( (string) $configured[0] );
            }
            $reports = Wf_Sn_Ai_Advisor_Reports::get_reports( 1, 0, 'full_report' );
            $has_reports = is_array( $reports ) && isset( $reports[0] );
            $state['has_reports'] = $has_reports;
            if ( $ready || $has_reports ) {
                $state['state'] = 2;
                if ( $has_reports ) {
                    $report = $reports[0];
                    $created = ( isset( $report['created'] ) ? $report['created'] : '' );
                    if ( $created ) {
                        $state['last_reviewed'] = human_time_diff( strtotime( $created ), time() );
                    }
                    $text = ( isset( $report['report_text'] ) ? $report['report_text'] : '' );
                    if ( is_string( $text ) && '' !== $text ) {
                        $decoded = json_decode( $text, true );
                        if ( is_array( $decoded ) ) {
                            if ( !empty( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ) {
                                $state['teaser'] = wp_trim_words( $decoded['executive_summary'], 20 );
                            } elseif ( !empty( $decoded['overview'] ) && is_string( $decoded['overview'] ) ) {
                                $state['teaser'] = wp_trim_words( $decoded['overview'], 20 );
                            }
                        }
                    }
                }
            } else {
                $state['state'] = 3;
            }
        } catch ( \Throwable $e ) {
            // AI Client TypeError or other failures must not white-screen Overview.
            $state['has_connectors'] = false;
            $state['state'] = 3;
        }
        return $state;
    }

    /**
     * Callback for the Security Advisor submenu page.
     */
    public static function render_page() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        self::load_dependencies();
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
        self::load_dependencies();
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
        $deps = array('jquery', 'sn-dialog');
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
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        wp_localize_script( 'wf-sn-ai-advisor', 'wfSnAiAdvisor', array(
            'ajaxurl'              => admin_url( 'admin-ajax.php' ),
            'nonce'                => wp_create_nonce( 'wf_sn_ai_advisor' ),
            'connectors'           => $configured,
            'connectorsMeta'       => Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_for_ui(),
            'connectorsAdminUrl'   => Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_admin_url(),
            'uiLocale'             => $ui_locale,
            'improvementLinks'     => self::get_improvement_links(),
            'baseUrlPath'          => $base_url_path,
            'chips'                => Wf_Sn_Ai_Advisor_Chips::get_chips_for_ui(),
            'chipHistoryPageSize'  => $chip_history_page_size,
            'latestParentReportId' => Wf_Sn_Ai_Advisor_Reports::get_latest_full_report_id(),
            'followupReady'        => Wf_Sn_Ai_Advisor_Chips::is_followup_toolbar_active(),
            'mainSnUrl'            => admin_url( 'admin.php?page=wf-sn' ),
            'strings'              => array(
                'requestFailed'            => __( 'Request failed.', 'security-ninja' ),
                'riskLabel'                => __( 'Risk: %s', 'security-ninja' ),
                'executiveSummary'         => __( 'Executive summary', 'security-ninja' ),
                'overview'                 => __( 'Overview', 'security-ninja' ),
                'topImprovements'          => __( 'Top improvements', 'security-ninja' ),
                'activityLast7Days'        => __( 'Activity (last 7 days)', 'security-ninja' ),
                'trendLabel'               => __( 'Trend: %s', 'security-ninja' ),
                'stagePreparing'           => __( 'Preparing security data…', 'security-ninja' ),
                'stageSendingTo'           => __( 'Sending to %s…', 'security-ninja' ),
                'stageWaitingFor'          => __( 'Waiting for %s…', 'security-ninja' ),
                'stageSending'             => __( 'Sending to AI', 'security-ninja' ),
                'stageWaiting'             => __( 'Waiting for response', 'security-ninja' ),
                'stageReceived'            => __( 'Response received.', 'security-ninja' ),
                'prepareStatsLine'         => __( 'Context ~%1$s KB · ~%2$s input tokens · %3$s guidance items', 'security-ninja' ),
                'longWaitExpectation'      => __( 'Full reports can take up to a minute depending on your connector and site size.', 'security-ninja' ),
                'waitingTips'              => array(
                    __( 'Run Security Tests regularly so your report stays up to date.', 'security-ninja' ),
                    __( 'Strong passwords and two-factor authentication reduce brute-force risk.', 'security-ninja' ),
                    __( 'Keeping WordPress, themes, and plugins updated closes known vulnerabilities.', 'security-ninja' ),
                    __( 'Limit login attempts and disable XML-RPC if you do not need them.', 'security-ninja' ),
                    sprintf( 
                        /* translators: %s: plugin display name */
                        __( 'Review failed and blocked login activity in %s to spot attacks.', 'security-ninja' ),
                        $plugin_name
                     ),
                    __( 'Back up your site before making security changes suggested in the report.', 'security-ninja' )
                ),
                'generating'               => __( 'Generating…', 'security-ninja' ),
                'saving'                   => __( 'Saving', 'security-ninja' ),
                'settingsSaved'            => __( 'Settings saved.', 'security-ninja' ),
                'settingsSaveError'        => __( 'Unable to save settings.', 'security-ninja' ),
                'previous7Days'            => __( 'Previous 7 days', 'security-ninja' ),
                'last7Days'                => __( 'Last 7 days', 'security-ninja' ),
                'openInSn'                 => sprintf( 
                    /* translators: %s: plugin display name */
                    __( 'Open in %s', 'security-ninja' ),
                    $plugin_name
                 ),
                'connectionError'          => __( 'The request failed. Check your connection and try again.', 'security-ninja' ),
                'assistantTitle'           => __( 'Assistant', 'security-ninja' ),
                'assistantHint'            => __( 'Choose a suggested prompt at the bottom. Follow-ups use your latest saved audit.', 'security-ninja' ),
                'followupEmptyActive'      => __( 'No messages yet. Pick a guided question below.', 'security-ninja' ),
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
                'errorTitle'               => __( 'The AI provider did not respond', 'security-ninja' ),
                'nothingChangedOnSite'     => __( 'Nothing was changed on your site.', 'security-ninja' ),
                'tryAgain'                 => __( 'Try again', 'security-ninja' ),
                'switchConnector'          => __( 'Use another AI connector', 'security-ninja' ),
                'viewResults'              => __( 'View scan results without AI', 'security-ninja' ),
                'technicalDetails'         => __( 'Technical details', 'security-ninja' ),
                'snapshotSaved'            => __( 'We saved the scan snapshot. Retrying will reuse the same scan data unless you choose to refresh it.', 'security-ninja' ),
                'testConnection'           => __( 'Test connection', 'security-ninja' ),
                'testConnectionRunning'    => __( 'Testing connection…', 'security-ninja' ),
                'testConnectionFixLink'    => __( 'Open Settings → Connectors', 'security-ninja' ),
                'testConnectionSelect'     => __( 'Select a connector first.', 'security-ninja' ),
                'scheduleRunNow'           => __( 'Run report now', 'security-ninja' ),
                'scheduleRunNowRunning'    => __( 'Queuing report…', 'security-ninja' ),
            ),
        ) );
    }

    /**
     * Improvement ID to hash fragment for the current plan (free vs Pro). JS builds full URL from location.origin + baseUrlPath + hash.
     *
     * @return array<string, string> Map of improvement id => hash (e.g. '#sn_tests').
     */
    public static function get_improvement_links() {
        self::load_dependencies();
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
            'sn_core'              => '#sn_core',
            'sn_malware'           => '#sn_malware',
            'core_scanner'         => '#sn_core',
            'malware'              => '#sn_malware',
            'update_plugins'       => admin_url( 'update-core.php' ),
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
        self::load_dependencies();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $provider = ( !empty( $configured ) ? 'wordpress_connectors' : '' );
        Wf_Sn_Ai_Advisor_Page::set_option( 'provider', $provider );
        if ( isset( $_POST['wf_sn_ai_advisor_connector'] ) ) {
            $connector = sanitize_text_field( wp_unslash( $_POST['wf_sn_ai_advisor_connector'] ) );
            if ( in_array( $connector, $configured, true ) ) {
                Wf_Sn_Ai_Advisor_Page::set_option( 'last_connector_provider', $connector );
            }
        }
        $abilities_raw = ( isset( $_POST['wf_sn_ai_advisor_abilities_exposed'] ) ? sanitize_text_field( wp_unslash( $_POST['wf_sn_ai_advisor_abilities_exposed'] ) ) : '0' );
        $abilities_exposed = '1' === $abilities_raw;
        Wf_Sn_Ai_Advisor_Page::set_option( Wf_Sn_Ai_Advisor_Abilities::OPTION_ABILITIES_EXPOSED, ( $abilities_exposed ? 1 : 0 ) );
        $redirect = add_query_arg( array(
            'page'             => self::SLUG,
            'settings-updated' => 1,
        ), admin_url( 'admin.php' ) );
        wp_safe_redirect( $redirect );
        exit;
    }

    /**
     * Remove all saved AI reports, follow-ups, and related cached advisor state.
     *
     * @return int Rows deleted from reports table.
     */
    public static function clear_history() {
        self::load_dependencies();
        $deleted = Wf_Sn_Ai_Advisor_Reports::clear_all();
        delete_transient( self::PENDING_SNAPSHOT_TRANSIENT );
        delete_transient( self::PENDING_META_TRANSIENT );
        delete_transient( 'secnin_dashboard_ai_advisor' );
        Wf_Sn_Ai_Advisor_Reevaluate_Notice::clear_pending();
        Wf_Sn_Ai_Advisor_Aggregation::clear_cache();
        self::clear_rate_limit_transients();
        /**
         * Fires after Security Advisor AI history has been cleared.
         */
        do_action( 'wf_sn_ai_advisor_history_cleared' );
        return $deleted;
    }

    /**
     * Delete per-user AI advisor rate-limit transients.
     *
     * @return void
     */
    private static function clear_rate_limit_transients() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_transient_wf_sn_ai_advisor_rl_' ) . '%', $wpdb->esc_like( '_transient_timeout_wf_sn_ai_advisor_rl_' ) . '%' ) );
    }

    /**
     * Handle clear-history form submission (Tools or Advisor settings).
     */
    public static function handle_clear_history() {
        check_admin_referer( 'wf_sn_ai_advisor_clear_history', '_wpnonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions.', 'security-ninja' ) );
        }
        self::clear_history();
        $redirect_page = ( isset( $_POST['redirect_to'] ) ? sanitize_key( wp_unslash( $_POST['redirect_to'] ) ) : self::SLUG );
        if ( !in_array( $redirect_page, array(self::SLUG, 'wf-sn-tools'), true ) ) {
            $redirect_page = self::SLUG;
        }
        $redirect = add_query_arg( array(
            'page'               => $redirect_page,
            'ai_history_cleared' => 'success',
        ), admin_url( 'admin.php' ) );
        wp_safe_redirect( $redirect );
        exit;
    }

    /**
     * AJAX: test selected WordPress AI connector.
     */
    public static function ajax_test_connector() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        self::load_dependencies();
        $connector_id = ( isset( $_POST['connector_id'] ) ? sanitize_key( wp_unslash( $_POST['connector_id'] ) ) : '' );
        $result = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::test_connector( $connector_id );
        if ( !empty( $result['ok'] ) ) {
            wp_send_json_success( array(
                'message' => $result['message'],
            ) );
        }
        wp_send_json_error( array(
            'message'        => $result['message'],
            'connectors_url' => Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_admin_url(),
        ) );
    }

    /**
     * Generate and store a full AI security report.
     *
     * @param array $args {
     *     @type string $connector_id Optional connector override.
     *     @type string $ui_locale    Optional UI locale.
     *     @type string $source       'manual' or 'scheduled'.
     * }
     * @return array{ok:bool,report_id:int,report:array|null,error:string,raw_error:string,connector_id:string,model_used:?string,text:string,usage:array}
     */
    public static function run_full_report( $args = array() ) {
        self::load_dependencies();
        $args = wp_parse_args( ( is_array( $args ) ? $args : array() ), array(
            'connector_id' => '',
            'ui_locale'    => '',
            'source'       => 'manual',
            'prepared'     => false,
            'prepare_ms'   => 0,
        ) );
        self::ensure_tables();
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $stored = ( isset( $options['last_connector_provider'] ) ? (string) $options['last_connector_provider'] : '' );
        $requested = sanitize_key( (string) $args['connector_id'] );
        if ( '' !== $requested && in_array( $requested, $configured, true ) ) {
            $connector_id = $requested;
        } else {
            $connector_id = self::resolve_connector_id( $stored, $configured );
        }
        $ui_locale = sanitize_text_field( (string) $args['ui_locale'] );
        $request_type = 'full_report';
        $prepare_ms = max( 0, (int) $args['prepare_ms'] );
        $use_prepared = !empty( $args['prepared'] );
        $context = null;
        if ( $use_prepared ) {
            $loaded = self::load_prepared_context( $connector_id, $ui_locale );
            if ( is_wp_error( $loaded ) ) {
                return array(
                    'ok'           => false,
                    'report_id'    => 0,
                    'report'       => null,
                    'error'        => $loaded->get_error_message(),
                    'raw_error'    => '',
                    'connector_id' => $connector_id,
                    'model_used'   => null,
                    'text'         => '',
                    'usage'        => array(),
                );
            }
            $context = $loaded;
        } else {
            $context = Wf_Sn_Ai_Advisor_Payload::build( $ui_locale );
            set_transient( self::PENDING_SNAPSHOT_TRANSIENT, wp_json_encode( $context ), HOUR_IN_SECONDS );
        }
        $json_schema = Wf_Sn_Ai_Advisor_Schemas::get_for_request( $request_type, '' );
        $max_out_tokens = max( 256, (int) apply_filters( 'wf_sn_ai_advisor_max_tokens', 8192, $request_type ) );
        $prompt_options = self::get_full_report_prompt_options( $connector_id, $context, $json_schema );
        $prompts = Wf_Sn_Ai_Advisor_Prompts::get( $request_type, $context, $prompt_options );
        $prompt_text = $prompts['prompt'];
        $token_in_est = Wf_Sn_Ai_Advisor_Reports::estimate_input_tokens( $prompts['system_instruction'], $prompt_text );
        $text = '';
        $report = null;
        $error = '';
        $raw_err = '';
        $result = array();
        $attempt_count = 0;
        $parse_failed = false;
        $truncated_accepted = false;
        $ai_start = microtime( true );
        if ( '' !== $connector_id ) {
            $gen_options = array(
                'request_type' => $request_type,
                'json_schema'  => $json_schema,
            );
            $result = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::generate_text(
                $connector_id,
                $prompts['system_instruction'],
                $prompt_text,
                $gen_options
            );
            $text = self::extract_result_text( $result );
            if ( isset( $result['attempt_count'] ) ) {
                $attempt_count = (int) $result['attempt_count'];
            }
            if ( '' === $text && !empty( $result['error'] ) && is_string( $result['error'] ) ) {
                $raw_err = (string) $result['error'];
                $error = self::format_connector_error_for_display( $raw_err );
            }
        } else {
            $error = __( 'No AI connector is configured. Add one under Settings → Connectors, then choose it on the Security Advisor page.', 'security-ninja' );
        }
        $ai_ms = (int) round( (microtime( true ) - $ai_start) * 1000 );
        $model_used = null;
        if ( !empty( $result['model'] ) && is_string( $result['model'] ) ) {
            $model_used = $result['model'];
        }
        $usage = ( !empty( $result['usage'] ) && is_array( $result['usage'] ) ? $result['usage'] : array() );
        $max_tokens_used = ( isset( $result['max_tokens_requested'] ) ? (int) $result['max_tokens_requested'] : $max_out_tokens );
        $finish_reason = ( isset( $result['finish_reason'] ) ? sanitize_key( (string) $result['finish_reason'] ) : '' );
        $token_input = self::resolve_input_tokens_from_usage( $usage, $token_in_est );
        $token_output = null;
        if ( '' !== $text ) {
            $parse_result = self::parse_full_report_text( $text );
            $report = $parse_result['report'];
            if ( is_array( $report ) ) {
                $report_lang = ( isset( $context['ui_locale'] ) && is_string( $context['ui_locale'] ) ? $context['ui_locale'] : '' );
                Wf_Sn_Ai_Advisor_Schemas::normalize_full_report_response( $report, $model_used, $report_lang );
                $strict_ok = Wf_Sn_Ai_Advisor_Schemas::validate_full_report_response( $report );
                $lenient_ok = !$strict_ok && Wf_Sn_Ai_Advisor_Schemas::is_viable_full_report( $report );
                if ( $strict_ok || $lenient_ok ) {
                    Wf_Sn_Ai_Advisor_Improvements::prepare_report_improvements( $report );
                    $error = '';
                    $raw_err = '';
                    if ( 'length' === $finish_reason ) {
                        $truncated_accepted = true;
                    }
                } else {
                    $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                    $raw_err = self::build_parse_failure_detail( $text, array(
                        'reason' => 'validation',
                    ) );
                    $parse_failed = true;
                    $report = null;
                }
            } else {
                $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                $raw_err = self::build_parse_failure_detail( $text, $parse_result );
                $parse_failed = true;
            }
        }
        if ( '' === $error && !is_array( $report ) ) {
            if ( '' === $text ) {
                if ( !empty( $result['error'] ) && is_string( $result['error'] ) ) {
                    $error = (string) $result['error'];
                    $raw_err = $error;
                } elseif ( 'length' === $finish_reason ) {
                    $error = __( 'The AI response hit the output token limit before the report was finished. Try again or switch to another connector (e.g. OpenAI or DeepSeek Chat).', 'security-ninja' );
                    $raw_err = self::build_token_limit_error_detail( $result, $text, $max_tokens_used );
                } elseif ( !empty( $usage['output_tokens'] ) && $max_tokens_used > 0 && (int) $usage['output_tokens'] >= (int) ($max_tokens_used * 0.95) ) {
                    $error = __( 'The AI response hit the output token limit before the report was finished. Try again or switch to another connector (e.g. OpenAI or DeepSeek Chat).', 'security-ninja' );
                    $raw_err = self::build_token_limit_error_detail( $result, $text, $max_tokens_used );
                } else {
                    $error = __( 'The AI provider returned an empty response. Please try again later.', 'security-ninja' );
                }
            } else {
                $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                $raw_err = self::build_parse_failure_detail( $text, array(
                    'reason' => 'validation',
                ) );
                $parse_failed = true;
            }
        }
        $new_full_report_id = 0;
        if ( '' === $error && is_array( $report ) ) {
            $token_output = self::resolve_output_tokens_from_usage( $usage, wp_json_encode( $report ) );
            $stored_text = wp_json_encode( $report );
            $snapshot_json = wp_json_encode( \WPSecurityNinja\Plugin\Wf_Sn_Security_Snapshot::build() );
            $inserted = Wf_Sn_Ai_Advisor_Reports::insert_report(
                $stored_text,
                'wordpress_connectors',
                $model_used,
                $token_input,
                $token_output,
                $request_type,
                null,
                $snapshot_json
            );
            if ( false !== $inserted ) {
                $new_full_report_id = (int) $inserted;
                Wf_Sn_Ai_Advisor_Reports::prune_chip_reports_for_parent( $new_full_report_id );
            }
            \WPSecurityNinja\Plugin\Wf_Sn_Security_Snapshot::refresh_cache();
            delete_transient( self::PENDING_SNAPSHOT_TRANSIENT );
            delete_transient( self::PENDING_META_TRANSIENT );
            delete_transient( 'secnin_dashboard_ai_advisor' );
            Wf_Sn_Ai_Advisor_Reevaluate_Notice::clear_pending();
        }
        if ( '' !== $error ) {
            $diagnostics = self::build_ai_diagnostics_from_result( $result, $text, $max_tokens_used );
            $event_context = self::build_ai_advisor_event_context(
                '',
                $connector_id,
                $model_used,
                $error
            );
            if ( $parse_failed ) {
                $event_context['parse_failure'] = '1';
                $event_context['response_preview'] = $raw_err;
            }
            $event_context['duration_ms'] = (string) $ai_ms;
            $event_context['prepare_ms'] = (string) $prepare_ms;
            $event_context['attempt_count'] = (string) $attempt_count;
            self::log_ai_advisor_request_event( 'error', $request_type, $event_context );
            return array(
                'ok'           => false,
                'report_id'    => 0,
                'report'       => null,
                'error'        => $error,
                'raw_error'    => $raw_err,
                'connector_id' => $connector_id,
                'model_used'   => $model_used,
                'text'         => $text,
                'diagnostics'  => $diagnostics,
                'usage'        => array(
                    'token_input'  => (int) $token_input,
                    'token_output' => ( null !== $token_output ? (int) $token_output : 0 ),
                    'model'        => $model_used,
                ),
            );
        }
        $success_context = self::build_ai_advisor_event_context( '', $connector_id, $model_used );
        $success_context['duration_ms'] = (string) $ai_ms;
        $success_context['prepare_ms'] = (string) $prepare_ms;
        $success_context['attempt_count'] = (string) $attempt_count;
        if ( $truncated_accepted ) {
            $success_context['truncated_response_accepted'] = '1';
        }
        self::log_ai_advisor_request_event( 'success', $request_type, $success_context );
        return array(
            'ok'           => true,
            'report_id'    => $new_full_report_id,
            'report'       => $report,
            'error'        => '',
            'raw_error'    => '',
            'connector_id' => $connector_id,
            'model_used'   => $model_used,
            'text'         => $text,
            'usage'        => array(
                'token_input'  => (int) $token_input,
                'token_output' => ( null !== $token_output ? (int) $token_output : 0 ),
                'model'        => $model_used,
            ),
        );
    }

    /**
     * AJAX: phase 1 — build snapshot and return payload stats.
     *
     * @return void
     */
    public static function ajax_prepare() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        self::load_dependencies();
        if ( !self::passes_rate_limit() ) {
            wp_send_json_error( array(
                'message'    => __( 'Too many AI requests in the last hour. Please wait and try again.', 'security-ninja' ),
                'error_code' => 'rate_limit',
            ) );
        }
        $ui_locale = ( isset( $_POST['ui_locale'] ) ? sanitize_text_field( wp_unslash( $_POST['ui_locale'] ) ) : '' );
        self::ensure_tables();
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $stored = ( isset( $options['last_connector_provider'] ) ? (string) $options['last_connector_provider'] : '' );
        $requested = ( isset( $_POST['connector_id'] ) ? sanitize_key( wp_unslash( $_POST['connector_id'] ) ) : '' );
        if ( '' !== $requested && in_array( $requested, $configured, true ) ) {
            $connector_id = $requested;
        } else {
            $connector_id = self::resolve_connector_id( $stored, $configured );
        }
        if ( '' === $connector_id ) {
            wp_send_json_error( array(
                'message'    => __( 'No AI connector is configured. Add one under Settings → Connectors, then choose it on the Security Advisor page.', 'security-ninja' ),
                'error_code' => 'no_connector',
            ) );
        }
        $prepare_start = microtime( true );
        $prepared = self::prepare_report_snapshot( $connector_id, $ui_locale );
        $prepare_ms = (int) round( (microtime( true ) - $prepare_start) * 1000 );
        if ( is_wp_error( $prepared ) ) {
            wp_send_json_error( array(
                'message' => $prepared->get_error_message(),
            ) );
        }
        $meta = get_transient( self::PENDING_META_TRANSIENT );
        if ( is_array( $meta ) ) {
            $meta['prepare_ms'] = $prepare_ms;
            set_transient( self::PENDING_META_TRANSIENT, $meta, HOUR_IN_SECONDS );
        }
        $connector_meta = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connector_metadata( $connector_id );
        wp_send_json_success( array(
            'prepared'        => true,
            'connector_id'    => $connector_id,
            'connector_label' => ( isset( $connector_meta['label'] ) ? (string) $connector_meta['label'] : $connector_id ),
            'stats'           => ( isset( $prepared['stats'] ) ? $prepared['stats'] : array() ),
            'prepare_ms'      => $prepare_ms,
        ) );
    }

    /**
     * Prompt options for full reports (compact when schema output is unavailable).
     *
     * @param string                   $connector_id Connector id.
     * @param array                    $context      Payload context.
     * @param array<string,mixed>|null $json_schema  JSON schema.
     * @return array{compact_output: bool}
     */
    private static function get_full_report_prompt_options( $connector_id, array $context, $json_schema ) {
        $base_prompts = Wf_Sn_Ai_Advisor_Prompts::get( 'full_report', $context );
        $compact = true;
        if ( '' !== (string) $connector_id ) {
            $compact = !Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::uses_schema_output(
                $connector_id,
                $base_prompts['system_instruction'],
                $base_prompts['prompt'],
                $json_schema
            );
        }
        return array(
            'compact_output' => $compact,
        );
    }

    /**
     * Extract non-empty model text from a provider result payload.
     *
     * @param array<string,mixed> $result Provider result.
     * @return string
     */
    private static function extract_result_text( array $result ) {
        if ( empty( $result['text'] ) || !is_string( $result['text'] ) ) {
            return '';
        }
        $text = trim( $result['text'] );
        return ( '' !== $text ? $result['text'] : '' );
    }

    /**
     * Build diagnostic metadata for error UI and logging.
     *
     * @param array<string,mixed> $result          Provider result.
     * @param string              $text            Raw response text.
     * @param int                 $max_tokens_used Requested max output tokens.
     * @return array<string, string|int>
     */
    private static function build_ai_diagnostics_from_result( array $result, $text, $max_tokens_used ) {
        $usage = ( !empty( $result['usage'] ) && is_array( $result['usage'] ) ? $result['usage'] : array() );
        $out = array(
            'max_tokens'     => (int) $max_tokens_used,
            'response_chars' => ( is_string( $text ) ? strlen( $text ) : 0 ),
        );
        if ( !empty( $result['finish_reason'] ) ) {
            $out['finish_reason'] = sanitize_key( (string) $result['finish_reason'] );
        }
        if ( !empty( $result['generation_mode'] ) ) {
            $out['generation_mode'] = sanitize_key( (string) $result['generation_mode'] );
        }
        if ( !empty( $result['model'] ) && is_string( $result['model'] ) ) {
            $out['model'] = sanitize_text_field( $result['model'] );
        }
        foreach ( array('input_tokens', 'output_tokens') as $usage_key ) {
            if ( isset( $usage[$usage_key] ) && is_numeric( $usage[$usage_key] ) ) {
                $out[$usage_key] = (int) $usage[$usage_key];
            }
        }
        return $out;
    }

    /**
     * Technical detail when output stopped at the token cap.
     *
     * @param array<string,mixed> $result          Provider result.
     * @param string              $text            Raw response text.
     * @param int                 $max_tokens_used Requested max output tokens.
     * @return string
     */
    private static function build_token_limit_error_detail( array $result, $text, $max_tokens_used ) {
        $usage = ( !empty( $result['usage'] ) && is_array( $result['usage'] ) ? $result['usage'] : array() );
        $output_tokens = ( isset( $usage['output_tokens'] ) ? (int) $usage['output_tokens'] : 0 );
        $finish_reason = ( isset( $result['finish_reason'] ) ? sanitize_key( (string) $result['finish_reason'] ) : '' );
        $response_len = ( is_string( $text ) ? strlen( $text ) : 0 );
        return sprintf(
            /* translators: 1: output tokens used, 2: max tokens requested, 3: finish reason, 4: response character count */
            __( 'Output stopped at %1$d/%2$d tokens (finish_reason: %3$s). Response length: %4$d chars.', 'security-ninja' ),
            $output_tokens,
            (int) $max_tokens_used,
            ( '' !== $finish_reason ? $finish_reason : 'unknown' ),
            $response_len
        );
    }

    /**
     * Build and store a pending full-report snapshot for two-phase AJAX.
     *
     * @param string $connector_id Connector id.
     * @param string $ui_locale    UI locale.
     * @return array{stats: array}|WP_Error
     */
    private static function prepare_report_snapshot( $connector_id, $ui_locale = '' ) {
        $context = Wf_Sn_Ai_Advisor_Payload::build( $ui_locale );
        $json_schema = Wf_Sn_Ai_Advisor_Schemas::get_for_request( 'full_report', '' );
        $prompt_opts = self::get_full_report_prompt_options( $connector_id, $context, $json_schema );
        $stats = Wf_Sn_Ai_Advisor_Payload::get_payload_stats(
            $context,
            'full_report',
            $ui_locale,
            $prompt_opts
        );
        set_transient( self::PENDING_SNAPSHOT_TRANSIENT, wp_json_encode( $context ), HOUR_IN_SECONDS );
        set_transient( self::PENDING_META_TRANSIENT, array(
            'connector_id' => sanitize_key( (string) $connector_id ),
            'ui_locale'    => sanitize_text_field( (string) $ui_locale ),
            'prepared_at'  => gmdate( 'c' ),
            'stats'        => $stats,
        ), HOUR_IN_SECONDS );
        return array(
            'stats' => $stats,
        );
    }

    /**
     * Load a prepared snapshot when phase 2 runs.
     *
     * @param string $connector_id Expected connector id.
     * @param string $ui_locale    Expected UI locale.
     * @return array|WP_Error
     */
    private static function load_prepared_context( $connector_id, $ui_locale = '' ) {
        $meta = get_transient( self::PENDING_META_TRANSIENT );
        if ( !is_array( $meta ) || empty( $meta['connector_id'] ) ) {
            return new \WP_Error('wf_sn_ai_advisor_not_prepared', __( 'Security data is not prepared. Please try generating the report again.', 'security-ninja' ));
        }
        $stored_connector = sanitize_key( (string) $meta['connector_id'] );
        if ( '' !== $connector_id && $stored_connector !== sanitize_key( (string) $connector_id ) ) {
            return new \WP_Error('wf_sn_ai_advisor_connector_mismatch', __( 'The selected AI connector changed since preparation. Please try again.', 'security-ninja' ));
        }
        $snapshot_json = get_transient( self::PENDING_SNAPSHOT_TRANSIENT );
        if ( !is_string( $snapshot_json ) || '' === $snapshot_json ) {
            return new \WP_Error('wf_sn_ai_advisor_snapshot_missing', __( 'Prepared security data expired. Please try generating the report again.', 'security-ninja' ));
        }
        $context = json_decode( $snapshot_json, true );
        if ( !is_array( $context ) ) {
            return new \WP_Error('wf_sn_ai_advisor_snapshot_invalid', __( 'Prepared security data is invalid. Please try generating the report again.', 'security-ninja' ));
        }
        return $context;
    }

    /**
     * Technical detail string when AI text cannot be parsed as a report.
     *
     * @param string $text Raw AI response text.
     * @return string
     */
    private static function build_parse_failure_detail( $text, array $parse_result = array() ) {
        $text = ( is_string( $text ) ? trim( $text ) : '' );
        if ( '' === $text ) {
            return __( 'The provider returned empty text.', 'security-ninja' );
        }
        $reason = ( isset( $parse_result['reason'] ) ? (string) $parse_result['reason'] : '' );
        if ( 'validation' === $reason ) {
            return sprintf( 
                /* translators: 1: character count, 2: response preview */
                __( 'JSON decoded but failed validation (%1$d chars): %2$s', 'security-ninja' ),
                strlen( $text ),
                self::redact_response_preview( $text )
             );
        }
        $json_error = ( isset( $parse_result['json_error'] ) ? (string) $parse_result['json_error'] : '' );
        if ( '' !== $json_error ) {
            return sprintf(
                /* translators: 1: json error message, 2: character count, 3: response preview */
                __( 'JSON decode error (%1$s, %2$d chars): %3$s', 'security-ninja' ),
                $json_error,
                strlen( $text ),
                self::redact_response_preview( $text )
            );
        }
        return sprintf( 
            /* translators: 1: character count, 2: response preview */
            __( 'Parse failure (%1$d chars): %2$s', 'security-ninja' ),
            strlen( $text ),
            self::redact_response_preview( $text )
         );
    }

    /**
     * Redact and truncate AI response text for error display.
     *
     * @param string $text Raw response.
     * @return string
     */
    private static function redact_response_preview( $text ) {
        $preview = wp_strip_all_tags( (string) $text );
        $preview = preg_replace( '/\\s+/', ' ', $preview );
        $preview = ( is_string( $preview ) ? trim( $preview ) : '' );
        $preview = preg_replace( '/\\bsk-[A-Za-z0-9_-]{8,}\\b/', '[redacted]', $preview );
        if ( strlen( $preview ) > 300 ) {
            $preview = substr( $preview, 0, 300 ) . '…';
        }
        return $preview;
    }

    /**
     * Decode a full-report JSON object from raw model text.
     *
     * @param string $text Raw model output.
     * @return array{report: array|null, reason: string, json_error: string}
     */
    private static function parse_full_report_text( $text ) {
        $report = self::decode_report_json_string( $text );
        if ( is_array( $report ) ) {
            return array(
                'report'     => $report,
                'reason'     => '',
                'json_error' => '',
            );
        }
        return array(
            'report'     => null,
            'reason'     => 'decode',
            'json_error' => self::get_last_json_decode_error(),
        );
    }

    /**
     * Human-readable message for the last json_decode() failure.
     *
     * @return string
     */
    private static function get_last_json_decode_error() {
        switch ( json_last_error() ) {
            case JSON_ERROR_NONE:
                return '';
            case JSON_ERROR_DEPTH:
                return 'maximum stack depth exceeded';
            case JSON_ERROR_STATE_MISMATCH:
                return 'invalid or malformed JSON';
            case JSON_ERROR_CTRL_CHAR:
                return 'unexpected control character';
            case JSON_ERROR_SYNTAX:
                return 'syntax error';
            case JSON_ERROR_UTF8:
                return 'invalid UTF-8';
            default:
                return 'unknown error';
        }
    }

    public static function ajax_request() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        $request_type = ( isset( $_POST['request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['request_type'] ) ) : '' );
        $prompt_id = '';
        if ( !current_user_can( 'manage_options' ) ) {
            self::ajax_request_fail(
                __( 'Forbidden.', 'security-ninja' ),
                $request_type,
                $prompt_id,
                '',
                'capability'
            );
        }
        self::load_dependencies();
        $allowed = array('full_report', Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE);
        if ( !in_array( $request_type, $allowed, true ) ) {
            self::ajax_request_fail(
                __( 'Invalid request type.', 'security-ninja' ),
                $request_type,
                $prompt_id,
                '',
                'invalid_response'
            );
        }
        if ( !self::passes_rate_limit() ) {
            self::ajax_request_fail(
                __( 'Too many AI requests in the last hour. Please wait and try again.', 'security-ninja' ),
                $request_type,
                $prompt_id,
                '',
                'rate_limit'
            );
        }
        $ui_locale = '';
        if ( isset( $_POST['ui_locale'] ) ) {
            $ui_locale = sanitize_text_field( wp_unslash( $_POST['ui_locale'] ) );
        }
        self::ensure_tables();
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $stored = ( isset( $options['last_connector_provider'] ) ? (string) $options['last_connector_provider'] : '' );
        $requested = ( isset( $_POST['connector_id'] ) ? sanitize_key( wp_unslash( $_POST['connector_id'] ) ) : '' );
        if ( '' !== $requested && in_array( $requested, $configured, true ) ) {
            $connector_id = $requested;
        } else {
            $connector_id = self::resolve_connector_id( $stored, $configured );
        }
        if ( '' !== $connector_id && $connector_id !== $stored ) {
            Wf_Sn_Ai_Advisor_Page::set_option( 'last_connector_provider', $connector_id );
        }
        if ( 'full_report' === $request_type ) {
            $prepared = !empty( $_POST['prepared'] );
            $prepare_ms = 0;
            if ( $prepared ) {
                $meta = get_transient( self::PENDING_META_TRANSIENT );
                if ( is_array( $meta ) && isset( $meta['prepare_ms'] ) ) {
                    $prepare_ms = (int) $meta['prepare_ms'];
                }
            }
            $full_result = self::run_full_report( array(
                'connector_id' => $connector_id,
                'ui_locale'    => $ui_locale,
                'source'       => 'manual',
                'prepared'     => $prepared,
                'prepare_ms'   => $prepare_ms,
            ) );
            if ( empty( $full_result['ok'] ) ) {
                $error = ( isset( $full_result['error'] ) ? (string) $full_result['error'] : __( 'Request failed.', 'security-ninja' ) );
                $raw_err = ( isset( $full_result['raw_error'] ) ? (string) $full_result['raw_error'] : '' );
                $code = 'no_connector';
                if ( '' !== $connector_id ) {
                    $code = self::classify_error_code( ( $raw_err ? $raw_err : $error ) );
                }
                if ( false !== strpos( strtolower( $error ), 'could not be parsed' ) ) {
                    $code = 'parse';
                }
                if ( false !== strpos( strtolower( $error ), 'token limit' ) ) {
                    $code = 'invalid_response';
                }
                wp_send_json_error( self::build_ajax_error_payload(
                    $error,
                    $code,
                    $connector_id,
                    $raw_err,
                    ( isset( $full_result['diagnostics'] ) && is_array( $full_result['diagnostics'] ) ? $full_result['diagnostics'] : array() )
                ) );
            }
            wp_send_json_success( array(
                'report'         => $full_result['report'],
                'raw_text'       => $full_result['text'],
                'usage'          => $full_result['usage'],
                'report_id'      => $full_result['report_id'],
                'chips'          => Wf_Sn_Ai_Advisor_Chips::get_chips_for_ui(),
                'followup_ready' => Wf_Sn_Ai_Advisor_Chips::is_followup_toolbar_active(),
            ) );
        }
        if ( Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE === $request_type ) {
            $prompt_id = ( isset( $_POST['prompt_id'] ) ? sanitize_key( wp_unslash( $_POST['prompt_id'] ) ) : '' );
            if ( !Wf_Sn_Ai_Advisor_Chips::is_valid_prompt_id( $prompt_id ) ) {
                self::ajax_request_fail(
                    __( 'Invalid request.', 'security-ninja' ),
                    $request_type,
                    $prompt_id,
                    $connector_id,
                    'invalid_response'
                );
            }
            if ( !Wf_Sn_Ai_Advisor_Chips::is_visible( $prompt_id ) ) {
                self::ajax_request_fail(
                    __( 'This prompt is not available for your current reports.', 'security-ninja' ),
                    $request_type,
                    $prompt_id,
                    $connector_id,
                    'capability'
                );
            }
        }
        $context = Wf_Sn_Ai_Advisor_Payload::build( $ui_locale );
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
        $prompts = Wf_Sn_Ai_Advisor_Prompts::get( $request_type, $context );
        $prompt_text = $prompts['prompt'];
        $token_in_est = Wf_Sn_Ai_Advisor_Reports::estimate_input_tokens( $prompts['system_instruction'], $prompt_text );
        $text = '';
        $chip_parsed = null;
        $error = '';
        $raw_err = '';
        $result = array();
        $json_schema = Wf_Sn_Ai_Advisor_Schemas::get_for_request( $request_type, $prompt_id );
        $max_out_tokens = max( 256, (int) apply_filters( 'wf_sn_ai_advisor_max_tokens', 1536, $request_type ) );
        if ( '' !== $connector_id ) {
            $gen_options = array(
                'request_type' => $request_type,
                'json_schema'  => $json_schema,
            );
            $result = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::generate_text(
                $connector_id,
                $prompts['system_instruction'],
                $prompt_text,
                $gen_options
            );
            $text = self::extract_result_text( ( is_array( $result ) ? $result : array() ) );
            if ( '' === $text && !empty( $result['error'] ) && is_string( $result['error'] ) ) {
                $raw_err = (string) $result['error'];
                $error = self::format_connector_error_for_display( $raw_err );
            }
        } else {
            $error = __( 'No AI connector is configured. Add one under Settings → Connectors, then choose it on the Security Advisor page.', 'security-ninja' );
        }
        $model_used = null;
        if ( !empty( $result['model'] ) && is_string( $result['model'] ) ) {
            $model_used = $result['model'];
        }
        $usage = ( !empty( $result['usage'] ) && is_array( $result['usage'] ) ? $result['usage'] : array() );
        if ( '' === $error && '' === $text ) {
            if ( !empty( $result['error'] ) && is_string( $result['error'] ) ) {
                $error = $result['error'];
            } elseif ( !empty( $result['finish_reason'] ) && 'length' === $result['finish_reason'] ) {
                $error = __( 'The AI response hit the output token limit before the report was finished. Try again or switch to another connector (e.g. OpenAI or DeepSeek Chat).', 'security-ninja' );
            } elseif ( !empty( $usage['output_tokens'] ) && $max_out_tokens > 0 && (int) $usage['output_tokens'] >= (int) ($max_out_tokens * 0.95) ) {
                $error = __( 'The AI response hit the output token limit before the report was finished. Try again or switch to another connector (e.g. OpenAI or DeepSeek Chat).', 'security-ninja' );
            } else {
                $error = __( 'The AI provider returned an empty response. Please try again later.', 'security-ninja' );
            }
        }
        $token_input = self::resolve_input_tokens_from_usage( $usage, $token_in_est );
        $token_output = null;
        if ( '' === $error && '' !== $text ) {
            $chip_parsed = self::decode_report_json_string( $text );
            if ( !is_array( $chip_parsed ) || !Wf_Sn_Ai_Advisor_Schemas::validate_chip_response( $prompt_id, $chip_parsed ) ) {
                $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
                $chip_parsed = null;
            }
        }
        $chip_report_id = 0;
        if ( '' === $error && is_array( $chip_parsed ) ) {
            $token_output = self::resolve_output_tokens_from_usage( $usage, wp_json_encode( $chip_parsed ) );
            $parent_id = ( isset( $context['parent_report_id'] ) ? (int) $context['parent_report_id'] : 0 );
            $store = array(
                'prompt_id'        => $prompt_id,
                'response'         => $chip_parsed,
                'generated_at'     => gmdate( 'c' ),
                'parent_report_id' => $parent_id,
            );
            $inserted = Wf_Sn_Ai_Advisor_Reports::insert_report(
                wp_json_encode( $store ),
                'wordpress_connectors',
                $model_used,
                $token_input,
                $token_output,
                Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE,
                ( $parent_id > 0 ? $parent_id : null )
            );
            if ( false !== $inserted ) {
                $chip_report_id = (int) $inserted;
                if ( $parent_id > 0 ) {
                    Wf_Sn_Ai_Advisor_Reports::prune_chip_reports_for_parent( $parent_id );
                }
            }
        }
        if ( '' === $error && !is_array( $chip_parsed ) ) {
            $error = __( 'The AI response could not be parsed. Please try again later.', 'security-ninja' );
        }
        if ( '' !== $error ) {
            $code = 'no_connector';
            if ( '' !== $connector_id ) {
                $code = self::classify_error_code( ( $raw_err ? $raw_err : $error ) );
            }
            if ( false !== strpos( strtolower( $error ), 'could not be parsed' ) ) {
                $code = 'parse';
            }
            if ( false !== strpos( strtolower( $error ), 'token limit' ) ) {
                $code = 'invalid_response';
            }
            self::log_ai_advisor_request_event( 'error', $request_type, self::build_ai_advisor_event_context(
                $prompt_id,
                $connector_id,
                $model_used,
                $error
            ) );
            wp_send_json_error( self::build_ajax_error_payload(
                $error,
                $code,
                $connector_id,
                $raw_err
            ) );
        }
        self::log_ai_advisor_request_event( 'success', $request_type, self::build_ai_advisor_event_context( $prompt_id, $connector_id, $model_used ) );
        $usage_out = array(
            'token_input'  => (int) $token_input,
            'token_output' => ( null !== $token_output ? (int) $token_output : 0 ),
            'model'        => $model_used,
        );
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
        self::load_dependencies();
        self::ensure_tables();
        $offset = ( isset( $_POST['offset'] ) ? (int) $_POST['offset'] : 0 );
        $limit = ( isset( $_POST['limit'] ) ? (int) $_POST['limit'] : 15 );
        $limit = max( 5, min( 25, $limit ) );
        $offset = max( 0, $offset );
        $parent_report_id = Wf_Sn_Ai_Advisor_Reports::get_latest_full_report_id();
        if ( $parent_report_id > 0 ) {
            Wf_Sn_Ai_Advisor_Reports::prune_chip_reports_for_parent( $parent_report_id );
        }
        $rows = array();
        $items = array();
        $total = 0;
        if ( $parent_report_id > 0 ) {
            $rows = Wf_Sn_Ai_Advisor_Reports::get_chip_reports_for_parent( $parent_report_id, $limit, $offset );
            $total = Wf_Sn_Ai_Advisor_Reports::count_chip_reports_for_parent( $parent_report_id );
            foreach ( $rows as $row ) {
                if ( !is_array( $row ) ) {
                    continue;
                }
                $formatted = self::format_chip_row_for_client( $row );
                if ( null !== $formatted ) {
                    $items[] = $formatted;
                }
            }
        }
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
        self::load_dependencies();
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
     * AJAX handler: return the context (payload) sent to the AI for preview. No prompt or system instruction.
     */
    public static function ajax_preview_data() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        self::load_dependencies();
        $request_type = ( isset( $_POST['request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['request_type'] ) ) : 'full_report' );
        $allowed = array('full_report', Wf_Sn_Ai_Advisor_Chips::REQUEST_TYPE);
        if ( !in_array( $request_type, $allowed, true ) ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request type.', 'security-ninja' ),
            ) );
        }
        $ui_locale = ( isset( $_POST['ui_locale'] ) ? sanitize_text_field( wp_unslash( $_POST['ui_locale'] ) ) : '' );
        $connector_id = ( isset( $_POST['connector_id'] ) ? sanitize_key( wp_unslash( $_POST['connector_id'] ) ) : '' );
        self::ensure_tables();
        $context = Wf_Sn_Ai_Advisor_Payload::build( $ui_locale );
        $prompt_opts = array();
        if ( 'full_report' === $request_type && '' !== $connector_id ) {
            $json_schema = Wf_Sn_Ai_Advisor_Schemas::get_for_request( 'full_report', '' );
            $prompt_opts = self::get_full_report_prompt_options( $connector_id, $context, $json_schema );
        }
        $stats = Wf_Sn_Ai_Advisor_Payload::get_payload_stats(
            $context,
            $request_type,
            $ui_locale,
            $prompt_opts
        );
        wp_send_json_success( array(
            'data'  => $context,
            'stats' => $stats,
        ) );
    }

    /**
     * Build optional fields for AI advisor Events Logger raw_data.
     *
     * @param string      $prompt_id    Chip prompt id (omit for full reports).
     * @param string      $connector_id WordPress connector id (openai, deepseek, etc.).
     * @param string|null $model        Model id returned by the provider API.
     * @param string      $error_message Error detail when logging failures.
     * @return array<string, string>
     */
    private static function build_ai_advisor_event_context(
        $prompt_id = '',
        $connector_id = '',
        $model = null,
        $error_message = ''
    ) {
        $context = array();
        if ( '' !== $prompt_id ) {
            $context['prompt_id'] = sanitize_key( (string) $prompt_id );
        }
        if ( '' !== $connector_id ) {
            $context['connector'] = sanitize_key( (string) $connector_id );
        }
        if ( is_string( $model ) && '' !== trim( $model ) ) {
            $context['model'] = sanitize_text_field( $model );
        }
        if ( '' !== $error_message ) {
            $context['error_message'] = sanitize_text_field( $error_message );
        }
        return $context;
    }

    /**
     * Log an AI Security Advisor request outcome to the Events Logger.
     *
     * @param string               $status       success|error.
     * @param string               $request_type Request type slug.
     * @param array<string,string> $context      Optional: prompt_id, connector, model, error_message.
     * @return void
     */
    private static function log_ai_advisor_request_event( $status, $request_type, array $context = array() ) {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
            return;
        }
        $raw_data = array(
            'status'       => $status,
            'request_type' => $request_type,
            'provider'     => 'wordpress_connectors',
        );
        if ( !empty( $context['prompt_id'] ) ) {
            $raw_data['prompt_id'] = $context['prompt_id'];
        }
        if ( !empty( $context['connector'] ) ) {
            $raw_data['connector'] = $context['connector'];
        }
        if ( !empty( $context['model'] ) ) {
            $raw_data['model'] = $context['model'];
        }
        if ( 'error' === $status && !empty( $context['error_message'] ) ) {
            $raw_data['error_message'] = $context['error_message'];
        }
        foreach ( array(
            'parse_failure',
            'response_preview',
            'duration_ms',
            'prepare_ms',
            'attempt_count',
            'truncated_response_accepted'
        ) as $extra_key ) {
            if ( !empty( $context[$extra_key] ) ) {
                $raw_data[$extra_key] = sanitize_text_field( (string) $context[$extra_key] );
            }
        }
        $error_message = ( isset( $context['error_message'] ) ? $context['error_message'] : '' );
        if ( 'success' === $status ) {
            $model_label = ( !empty( $context['model'] ) ? $context['model'] : '' );
            if ( 'full_report' === $request_type ) {
                if ( '' !== $model_label ) {
                    $description = sprintf( 
                        /* translators: %s: AI model id (e.g. deepseek-chat, gpt-4o). */
                        __( 'AI Security Advisor report generated successfully (%s).', 'security-ninja' ),
                        $model_label
                     );
                } else {
                    $description = __( 'AI Security Advisor report generated successfully.', 'security-ninja' );
                }
            } elseif ( '' !== $model_label ) {
                $description = sprintf( 
                    /* translators: %s: AI model id. */
                    __( 'AI Security Advisor follow-up request completed successfully (%s).', 'security-ninja' ),
                    $model_label
                 );
            } else {
                $description = __( 'AI Security Advisor follow-up request completed successfully.', 'security-ninja' );
            }
        } else {
            $description = sprintf( 
                /* translators: %s: error message */
                __( 'AI Security Advisor request failed: %s', 'security-ninja' ),
                ( '' !== $error_message ? $error_message : __( 'Unknown error.', 'security-ninja' ) )
             );
        }
        \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
            'ai_advisor',
            'ai_advisor_request',
            $description,
            $raw_data
        );
    }

    /**
     * Log and return a JSON error for AI advisor AJAX requests.
     *
     * @param string $message      User-facing error message.
     * @param string $request_type Request type slug.
     * @param string $prompt_id    Chip prompt id when applicable.
     * @param string $connector_id Connector id when known.
     * @param string $error_code   Machine-readable error code.
     * @param string $raw_error    Optional raw provider error for technical details.
     * @return void
     */
    private static function ajax_request_fail(
        $message,
        $request_type = '',
        $prompt_id = '',
        $connector_id = '',
        $error_code = 'unknown',
        $raw_error = ''
    ) {
        self::log_ai_advisor_request_event( 'error', $request_type, self::build_ai_advisor_event_context(
            $prompt_id,
            $connector_id,
            null,
            $message
        ) );
        wp_send_json_error( self::build_ajax_error_payload(
            $message,
            $error_code,
            $connector_id,
            $raw_error
        ) );
    }

    /**
     * Structured AJAX error payload for the Advisor UI.
     *
     * @param string $message      User-facing message.
     * @param string $error_code   Error code slug.
     * @param string $connector_id Connector id.
     * @param string              $raw_error    Raw provider error.
     * @param array<string,mixed> $diagnostics  Optional AI diagnostics for technical panel.
     * @return array<string, mixed>
     */
    private static function build_ajax_error_payload(
        $message,
        $error_code,
        $connector_id = '',
        $raw_error = '',
        array $diagnostics = array()
    ) {
        $configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $actions = array('retry', 'view_results');
        if ( is_array( $configured ) && count( $configured ) > 1 ) {
            $actions[] = 'switch_connector';
        }
        $technical_error = self::format_connector_error_for_display( $raw_error );
        if ( 'parse' === sanitize_key( (string) $error_code ) && is_string( $raw_error ) && '' !== trim( $raw_error ) ) {
            $technical_error = self::format_connector_error_for_display( $raw_error );
        } elseif ( '' === trim( (string) $raw_error ) && is_string( $message ) ) {
            $technical_error = $message;
        }
        $technical = array(
            'provider'   => ( '' !== $connector_id ? sanitize_key( (string) $connector_id ) : '' ),
            'time'       => gmdate( 'Y-m-d H:i:s' ),
            'error'      => $technical_error,
            'request_id' => wp_generate_uuid4(),
        );
        if ( !empty( $diagnostics['finish_reason'] ) ) {
            $technical['finish_reason'] = sanitize_key( (string) $diagnostics['finish_reason'] );
        }
        if ( isset( $diagnostics['max_tokens'] ) && is_numeric( $diagnostics['max_tokens'] ) ) {
            $technical['max_tokens'] = (int) $diagnostics['max_tokens'];
        }
        if ( isset( $diagnostics['output_tokens'] ) && is_numeric( $diagnostics['output_tokens'] ) ) {
            $technical['output_tokens'] = (int) $diagnostics['output_tokens'];
        }
        if ( isset( $diagnostics['input_tokens'] ) && is_numeric( $diagnostics['input_tokens'] ) ) {
            $technical['input_tokens'] = (int) $diagnostics['input_tokens'];
        }
        if ( !empty( $diagnostics['generation_mode'] ) ) {
            $technical['generation_mode'] = sanitize_key( (string) $diagnostics['generation_mode'] );
        }
        if ( !empty( $diagnostics['model'] ) ) {
            $technical['model'] = sanitize_text_field( (string) $diagnostics['model'] );
        }
        if ( isset( $diagnostics['response_chars'] ) && is_numeric( $diagnostics['response_chars'] ) ) {
            $technical['response_chars'] = (int) $diagnostics['response_chars'];
        }
        return array(
            'message'        => $message,
            'error_code'     => sanitize_key( (string) $error_code ),
            'actions'        => $actions,
            'technical'      => $technical,
            'snapshot_saved' => (bool) get_transient( self::PENDING_SNAPSHOT_TRANSIENT ),
        );
    }

    /**
     * Map provider/raw errors to stable error codes.
     *
     * @param string $error Raw or formatted error message.
     * @return string
     */
    private static function classify_error_code( $error ) {
        $text = strtolower( (string) $error );
        if ( false !== strpos( $text, 'not available' ) || false !== strpos( $text, 'unavailable' ) ) {
            return 'unavailable';
        }
        if ( false !== strpos( $text, 'rate limit' ) || false !== strpos( $text, '429' ) ) {
            return 'rate_limit';
        }
        if ( false !== strpos( $text, 'timeout' ) || false !== strpos( $text, 'timed out' ) || false !== strpos( $text, 'curl error 28' ) ) {
            return 'timeout';
        }
        if ( false !== strpos( $text, 'unauthorized' ) || false !== strpos( $text, 'authentication' ) || false !== strpos( $text, '401' ) || false !== strpos( $text, '403' ) ) {
            return 'auth';
        }
        if ( false !== strpos( $text, 'could not be parsed' ) || false !== strpos( $text, 'json' ) ) {
            return 'parse';
        }
        if ( false !== strpos( $text, 'empty response' ) || false !== strpos( $text, 'token limit' ) ) {
            return 'invalid_response';
        }
        if ( false !== strpos( $text, 'curl' ) || false !== strpos( $text, 'http' ) ) {
            return 'http';
        }
        return 'provider';
    }

    /**
     * Resolve a valid connector id from stored preference and configured providers.
     *
     * @param string        $stored     Saved connector id.
     * @param array<string> $configured Configured provider ids.
     * @return string
     */
    private static function resolve_connector_id( $stored, array $configured ) {
        if ( empty( $configured ) ) {
            return '';
        }
        if ( '' !== $stored && in_array( $stored, $configured, true ) ) {
            return $stored;
        }
        return (string) $configured[0];
    }

    /**
     * Sanitize a connector error for display (pass-through with redaction).
     *
     * @param mixed $error Raw error from provider.
     * @return string
     */
    private static function format_connector_error_for_display( $error ) {
        $fallback = __( 'The AI request could not be completed. Try again or check your connector under Settings → Connectors.', 'security-ninja' );
        if ( !is_string( $error ) || '' === trim( $error ) ) {
            return $fallback;
        }
        $clean = wp_strip_all_tags( $error );
        $clean = preg_replace( '/\\s+/', ' ', $clean );
        $clean = ( is_string( $clean ) ? trim( $clean ) : '' );
        // Redact obvious secret patterns if a provider ever echoes them.
        $clean = preg_replace( '/\\bsk-[A-Za-z0-9_-]{8,}\\b/', '[redacted]', $clean );
        $clean = preg_replace( '/Bearer\\s+[A-Za-z0-9._-]+/i', 'Bearer [redacted]', $clean );
        if ( '' === $clean ) {
            return $fallback;
        }
        if ( strlen( $clean ) > 500 ) {
            $clean = substr( $clean, 0, 500 ) . '…';
        }
        return $clean;
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
        // Strip markdown code fences (with or without closing fence).
        if ( preg_match( '/^```(?:json)?\\s*(.*)/is', $trimmed, $fence_match ) ) {
            $trimmed = trim( $fence_match[1] );
            $trimmed = preg_replace( '/```\\s*$/', '', $trimmed );
            $trimmed = trim( (string) $trimmed );
        }
        $candidates = array($trimmed);
        $start = strpos( $trimmed, '{' );
        $end = strrpos( $trimmed, '}' );
        if ( false !== $start && false !== $end && $end > $start ) {
            $candidates[] = substr( $trimmed, $start, $end - $start + 1 );
        }
        if ( false !== $start ) {
            $candidates[] = substr( $trimmed, $start );
        }
        foreach ( array_unique( array_filter( $candidates, 'is_string' ) ) as $candidate ) {
            $data = self::json_decode_lenient( $candidate );
            if ( is_array( $data ) ) {
                return $data;
            }
            $repaired = self::repair_truncated_json_object( $candidate );
            if ( is_string( $repaired ) && '' !== $repaired ) {
                $data = self::json_decode_lenient( $repaired );
                if ( is_array( $data ) ) {
                    return $data;
                }
            }
        }
        return null;
    }

    /**
     * json_decode wrapper with trailing-comma cleanup.
     *
     * @param string $json JSON string.
     * @return array|null
     */
    private static function json_decode_lenient( $json ) {
        if ( !is_string( $json ) || '' === $json ) {
            return null;
        }
        $attempts = array($json);
        $cleaned = preg_replace( '/,\\s*([}\\]])/', '$1', $json );
        if ( is_string( $cleaned ) && $cleaned !== $json ) {
            $attempts[] = $cleaned;
        }
        foreach ( $attempts as $attempt ) {
            $data = json_decode( $attempt, true );
            if ( is_array( $data ) ) {
                return $data;
            }
        }
        return null;
    }

    /**
     * Best-effort repair for provider output truncated mid-JSON.
     *
     * @param string $json Partial JSON object string.
     * @return string
     */
    private static function repair_truncated_json_object( $json ) {
        $json = ( is_string( $json ) ? trim( $json ) : '' );
        if ( '' === $json || '{' !== $json[0] ) {
            return '';
        }
        $json = rtrim( $json, ", \n\r\t" );
        if ( preg_match( '/:\\s*"([^"\\\\]|\\\\.)*$/s', $json ) ) {
            $json .= '"';
        }
        $open_square = max( 0, substr_count( $json, '[' ) - substr_count( $json, ']' ) );
        $open_curly = max( 0, substr_count( $json, '{' ) - substr_count( $json, '}' ) );
        if ( 0 === $open_square && 0 === $open_curly ) {
            return '';
        }
        return $json . str_repeat( ']', $open_square ) . str_repeat( '}', $open_curly );
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
        echo '<div class="notice notice-info"><p>' . esc_html( sprintf( 
            /* translators: 1: plugin display name */
            __( '%1$s uses the AI connectors configured on this page to generate Security Advisor reports. After connecting a provider, choose which connector to use under %1$s → Security Advisor → AI settings.', 'security-ninja' ),
            \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name()
         ) ) . '</p></div>';
    }

}
