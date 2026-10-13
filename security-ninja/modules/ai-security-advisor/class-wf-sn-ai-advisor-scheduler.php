<?php

/**
 * AI Security Advisor – scheduled full-report generation.
 *
 * Ships in free (monthly) and Pro (weekly / daily).
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
require_once __DIR__ . '/class-wf-sn-ai-advisor-schedule-policy.php';
define( 'WF_SN_AI_ADVISOR_CRON', 'wf_sn_ai_advisor_cron' );
define( 'WF_SN_AI_ADVISOR_RUN_SCHEDULED', 'wf_sn_ai_advisor_run_scheduled_report' );
if ( !class_exists( 'ActionScheduler_Versions' ) ) {
    $action_scheduler_file = null;
    if ( defined( 'WF_SN_PLUGIN_DIR' ) ) {
        $path = WF_SN_PLUGIN_DIR . 'vendor/woocommerce/action-scheduler/action-scheduler.php';
        if ( file_exists( $path ) && is_readable( $path ) ) {
            $action_scheduler_file = $path;
        }
    }
    if ( !$action_scheduler_file ) {
        $plugin_root = dirname( __DIR__, 2 );
        $path = $plugin_root . '/vendor/woocommerce/action-scheduler/action-scheduler.php';
        if ( file_exists( $path ) && is_readable( $path ) ) {
            $action_scheduler_file = $path;
        }
    }
    if ( $action_scheduler_file ) {
        require_once $action_scheduler_file;
    }
}
/**
 * Schedules and runs automatic AI full reports.
 */
class Wf_Sn_Ai_Advisor_Scheduler {
    const LOCK_TRANSIENT = 'wf_sn_ai_advisor_scheduled_running';

    const RESCHEDULE_TRANSIENT = 'wf_sn_ai_advisor_reschedule_check';

    const NOTICE_OPTION = 'wf_sn_ai_scheduled_review_ready';

    /**
     * Bootstrap hooks.
     *
     * @return void
     */
    public static function init() {
        add_filter( 'cron_schedules', array(__CLASS__, 'register_monthly_schedule') );
        add_action( 'init', array(__CLASS__, 'maybe_reschedule'), 20 );
        add_action( WF_SN_AI_ADVISOR_CRON, array(__CLASS__, 'do_scheduled_report') );
        add_action( WF_SN_AI_ADVISOR_RUN_SCHEDULED, array(__CLASS__, 'do_scheduled_report') );
        add_action( 'wp_ajax_' . Wf_Sn_Ai_Advisor::AJAX_ACTION_PREFIX . 'run_scheduled_now', array(__CLASS__, 'ajax_run_scheduled_now') );
        add_action( 'admin_post_wf_sn_ai_advisor_save_schedule', array(__CLASS__, 'handle_save_schedule') );
        add_action( 'admin_enqueue_scripts', array(__CLASS__, 'enqueue_schedule_styles') );
        add_action( 'admin_notices', array(__CLASS__, 'admin_notice_scheduled_review_ready'), 7 );
    }

    /**
     * Register a 30-day cron interval.
     *
     * @param array $schedules Existing schedules.
     * @return array
     */
    public static function register_monthly_schedule( $schedules ) {
        if ( !is_array( $schedules ) ) {
            $schedules = array();
        }
        $schedules[Wf_Sn_Ai_Advisor_Schedule_Policy::CRON_MONTHLY] = array(
            'interval' => 30 * DAY_IN_SECONDS,
            'display'  => __( 'Once Monthly', 'security-ninja' ),
        );
        return $schedules;
    }

    /**
     * Styles for the Scheduler AI card on the main plugin page.
     *
     * @return void
     */
    public static function enqueue_schedule_styles() {
        if ( !class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn' ) || !\WPSecurityNinja\Plugin\Wf_Sn::is_plugin_page() ) {
            return;
        }
        $css = __DIR__ . '/css/ai-advisor-schedule.css';
        if ( !file_exists( $css ) ) {
            return;
        }
        wp_enqueue_style(
            'wf-sn-ai-advisor-schedule',
            plugins_url( 'css/ai-advisor-schedule.css', __FILE__ ),
            array('sn-css'),
            filemtime( $css )
        );
    }

    /**
     * Whether scheduled AI reports are enabled in settings.
     *
     * @return bool
     */
    public static function is_scheduling_enabled() {
        $options = get_option( 'wf_sn_ai_advisor', array() );
        if ( !is_array( $options ) ) {
            $options = array();
        }
        return !empty( $options['scheduled_report_enabled'] );
    }

    /**
     * Whether the current request may use premium schedule intervals.
     *
     * @return bool
     */
    public static function is_premium_schedule() {
        $is_premium = false;
        return $is_premium;
    }

    /**
     * Get configured interval slug (clamped to the current plan).
     *
     * @return string
     */
    public static function get_schedule_interval() {
        $options = get_option( 'wf_sn_ai_advisor', array() );
        if ( !is_array( $options ) ) {
            $options = array();
        }
        $interval = ( isset( $options['scheduled_report_interval'] ) ? sanitize_key( (string) $options['scheduled_report_interval'] ) : Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_MONTHLY );
        return Wf_Sn_Ai_Advisor_Schedule_Policy::normalize_interval( $interval, self::is_premium_schedule() );
    }

    /**
     * Persist a clamped interval when a leftover Pro value is no longer allowed.
     *
     * @return string Normalized interval.
     */
    public static function persist_normalized_interval() {
        $normalized = self::get_schedule_interval();
        $options = get_option( 'wf_sn_ai_advisor', array() );
        if ( !is_array( $options ) ) {
            $options = array();
        }
        $stored = ( isset( $options['scheduled_report_interval'] ) ? sanitize_key( (string) $options['scheduled_report_interval'] ) : '' );
        if ( $stored !== $normalized ) {
            $options['scheduled_report_interval'] = $normalized;
            update_option( 'wf_sn_ai_advisor', $options, true );
        }
        return $normalized;
    }

    /**
     * Next scheduled run timestamp and backend label.
     *
     * @return array{timestamp:int,backend:string}
     */
    public static function get_scheduler_state() {
        $state = array(
            'timestamp' => 0,
            'backend'   => 'none',
        );
        if ( self::ensure_action_scheduler_loaded() && function_exists( 'as_next_scheduled_action' ) ) {
            $as_timestamp = as_next_scheduled_action( WF_SN_AI_ADVISOR_RUN_SCHEDULED, array(), 'security-ninja' );
            if ( false !== $as_timestamp && 0 < (int) $as_timestamp ) {
                $state['timestamp'] = (int) $as_timestamp;
                $state['backend'] = 'action_scheduler';
                return $state;
            }
        }
        $wp_timestamp = wp_next_scheduled( WF_SN_AI_ADVISOR_CRON );
        if ( false !== $wp_timestamp && 0 < (int) $wp_timestamp ) {
            $state['timestamp'] = (int) $wp_timestamp;
            $state['backend'] = 'wp_cron';
        }
        return $state;
    }

    /**
     * Self-heal missing schedule when enabled and ready.
     *
     * @return void
     */
    public static function maybe_reschedule() {
        if ( !self::can_register_cron() ) {
            self::clear_all_scheduled_events();
            return;
        }
        if ( get_transient( self::RESCHEDULE_TRANSIENT ) ) {
            return;
        }
        set_transient( self::RESCHEDULE_TRANSIENT, 1, HOUR_IN_SECONDS );
        $state = self::get_scheduler_state();
        if ( 0 < (int) $state['timestamp'] ) {
            self::persist_normalized_interval();
            return;
        }
        self::setup_cron();
        if ( class_exists( 'WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
            \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                'security_ninja',
                'ai_advisor',
                __( 'Scheduled AI report event was missing and has been recreated automatically.', 'security-ninja' ),
                ''
            );
        }
    }

    /**
     * Whether cron may be registered right now.
     *
     * @return bool
     */
    public static function can_register_cron() {
        if ( !self::is_scheduling_enabled() ) {
            return false;
        }
        Wf_Sn_Ai_Advisor::load_dependencies();
        $state = Wf_Sn_Ai_Advisor_Schedule_Policy::get_connection_state();
        return Wf_Sn_Ai_Advisor_Schedule_Policy::can_queue( $state, true );
    }

    /**
     * Register or clear cron / Action Scheduler events.
     *
     * @return void
     */
    public static function setup_cron() {
        $interval = self::persist_normalized_interval();
        if ( !self::can_register_cron() ) {
            self::clear_all_scheduled_events();
            return;
        }
        $cron_slug = Wf_Sn_Ai_Advisor_Schedule_Policy::cron_schedule_slug( $interval );
        $seconds = Wf_Sn_Ai_Advisor_Schedule_Policy::interval_seconds( $interval );
        $has_action_scheduler = self::ensure_action_scheduler_loaded() && function_exists( 'as_schedule_recurring_action' ) && function_exists( 'as_unschedule_all_actions' );
        if ( $has_action_scheduler ) {
            wp_clear_scheduled_hook( WF_SN_AI_ADVISOR_CRON );
            as_unschedule_all_actions( WF_SN_AI_ADVISOR_RUN_SCHEDULED, array(), 'security-ninja' );
            as_schedule_recurring_action(
                time(),
                $seconds,
                WF_SN_AI_ADVISOR_RUN_SCHEDULED,
                array(),
                'security-ninja'
            );
            return;
        }
        wp_clear_scheduled_hook( WF_SN_AI_ADVISOR_CRON );
        wp_schedule_event( time(), $cron_slug, WF_SN_AI_ADVISOR_CRON );
    }

    /**
     * Run scheduled full report.
     *
     * @return void
     */
    public static function do_scheduled_report() {
        if ( !self::is_scheduling_enabled() ) {
            return;
        }
        if ( get_transient( self::LOCK_TRANSIENT ) ) {
            return;
        }
        set_transient( self::LOCK_TRANSIENT, 1, 15 * MINUTE_IN_SECONDS );
        Wf_Sn_Ai_Advisor::load_dependencies();
        $connection = Wf_Sn_Ai_Advisor_Schedule_Policy::get_connection_state();
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_READY !== $connection ) {
            self::log_skip_event( __( 'Scheduled AI report skipped: AI connector is not ready.', 'security-ninja' ) );
            delete_transient( self::LOCK_TRANSIENT );
            return;
        }
        self::refresh_security_tests_before_review();
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Readiness' ) && Wf_Sn_Ai_Advisor_Readiness::is_security_tests_missing() ) {
            self::log_skip_event( __( 'Scheduled AI report skipped: security tests could not be completed.', 'security-ninja' ) );
            delete_transient( self::LOCK_TRANSIENT );
            return;
        }
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        $connector_id = ( isset( $options['last_connector_provider'] ) ? sanitize_key( (string) $options['last_connector_provider'] ) : '' );
        $result = Wf_Sn_Ai_Advisor::run_full_report( array(
            'connector_id' => $connector_id,
            'ui_locale'    => get_locale(),
            'source'       => 'scheduled',
        ) );
        if ( empty( $result['ok'] ) ) {
            $error = ( isset( $result['error'] ) ? (string) $result['error'] : __( 'Scheduled AI report failed.', 'security-ninja' ) );
            self::log_skip_event( $error );
        } else {
            self::mark_scheduled_review_ready();
            if ( class_exists( 'WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'ai_advisor',
                    __( 'Scheduled AI security report generated successfully.', 'security-ninja' ),
                    ''
                );
            }
        }
        delete_transient( self::LOCK_TRANSIENT );
    }

    /**
     * Refresh security tests before an automatic review. Does not start malware or core scans.
     *
     * @return void
     */
    private static function refresh_security_tests_before_review() {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn' ) ) {
            return;
        }
        \WPSecurityNinja\Plugin\Wf_Sn::run_all_tests( true );
    }

    /**
     * Flag that a scheduled review is waiting to be seen.
     *
     * @return void
     */
    public static function mark_scheduled_review_ready() {
        update_option( self::NOTICE_OPTION, 1, false );
        delete_transient( 'secnin_dashboard_ai_advisor' );
    }

    /**
     * Admin notice after a scheduled review finishes.
     *
     * @return void
     */
    public static function admin_notice_scheduled_review_ready() {
        if ( !is_admin() || !current_user_can( 'manage_options' ) ) {
            return;
        }
        if ( !get_option( self::NOTICE_OPTION, 0 ) ) {
            return;
        }
        $page = ( isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '' );
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ( Wf_Sn_Ai_Advisor::SLUG === $page ) {
            delete_option( self::NOTICE_OPTION );
            return;
        }
        if ( !is_string( $page ) || 0 !== strpos( $page, 'wf-sn' ) ) {
            return;
        }
        $advisor_url = admin_url( 'admin.php?page=' . Wf_Sn_Ai_Advisor::SLUG );
        echo '<div class="notice notice-info is-dismissible"><p>';
        echo esc_html__( 'A new AI security review is ready.', 'security-ninja' );
        echo ' <a href="' . esc_url( $advisor_url ) . '">' . esc_html__( 'View latest review', 'security-ninja' ) . '</a>';
        echo '</p></div>';
    }

    /**
     * Save schedule settings from the Scheduler tab.
     *
     * @return void
     */
    public static function handle_save_schedule() {
        if ( !isset( $_POST['wf_sn_ai_advisor_schedule_nonce'] ) ) {
            wp_die( 'Missing nonce.' );
        }
        check_admin_referer( 'wf_sn_ai_advisor_save_schedule', 'wf_sn_ai_advisor_schedule_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        Wf_Sn_Ai_Advisor::load_dependencies();
        Wf_Sn_Ai_Advisor::maybe_select_single_connector();
        $enabled_raw = ( isset( $_POST['wf_sn_ai_advisor_scheduled_report_enabled'] ) ? sanitize_text_field( wp_unslash( $_POST['wf_sn_ai_advisor_scheduled_report_enabled'] ) ) : '0' );
        $enabled = ( '1' === $enabled_raw ? 1 : 0 );
        $interval_raw = ( isset( $_POST['wf_sn_ai_advisor_scheduled_report_interval'] ) ? sanitize_key( wp_unslash( $_POST['wf_sn_ai_advisor_scheduled_report_interval'] ) ) : Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_MONTHLY );
        $interval = Wf_Sn_Ai_Advisor_Schedule_Policy::normalize_interval( $interval_raw, self::is_premium_schedule() );
        $connection = Wf_Sn_Ai_Advisor_Schedule_Policy::get_connection_state();
        if ( !Wf_Sn_Ai_Advisor_Schedule_Policy::can_queue( $connection, (bool) $enabled ) ) {
            $enabled = 0;
        }
        Wf_Sn_Ai_Advisor_Page::set_option( 'scheduled_report_enabled', $enabled );
        Wf_Sn_Ai_Advisor_Page::set_option( 'scheduled_report_interval', $interval );
        self::setup_cron();
        $redirect = admin_url( 'admin.php?page=wf-sn#sn_schedule' );
        wp_safe_redirect( $redirect );
        exit;
    }

    /**
     * Shared Scheduler card (free and Pro).
     *
     * @return void
     */
    public static function render_settings_card() {
        Wf_Sn_Ai_Advisor::load_dependencies();
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        $is_premium = self::is_premium_schedule();
        $connection = Wf_Sn_Ai_Advisor_Schedule_Policy::get_connection_state();
        $enabled = self::is_scheduling_enabled();
        $interval = self::get_schedule_interval();
        $advisor_url = admin_url( 'admin.php?page=' . Wf_Sn_Ai_Advisor::SLUG );
        $scheduler_st = self::get_scheduler_state();
        $can_enable = Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_READY === $connection;
        $connectors = ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ? Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_admin_url() : admin_url( 'options-connectors.php' ) );
        echo '<div class="sncard settings-card wf-sn-ai-schedule-card" id="wf_sn_ai_schedule_card">';
        echo '<h2><span class="dashicons dashicons-admin-generic"></span> ' . esc_html__( 'Automatic AI review', 'security-ninja' ) . '</h2>';
        echo '<p>' . esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'Send the latest %s scan results, firewall activity, and security tests to your AI connector and save a review on the Security Advisor page. Uses your own AI account.', 'security-ninja' ),
            $plugin_name
         ) ) . '</p>';
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_UNAVAILABLE === $connection ) {
            echo '<p class="description">' . esc_html__( 'Automatic AI reviews need WordPress 7 AI Connectors. Security scans on this page still work.', 'security-ninja' ) . '</p>';
            echo '<p><a href="' . esc_url( $advisor_url ) . '">' . esc_html__( 'Open Security Advisor', 'security-ninja' ) . '</a></p>';
            echo '</div>';
            return;
        }
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NO_CONNECTOR === $connection ) {
            echo '<p class="wf-sn-ai-schedule-card__status wf-sn-ai-schedule-card__status--warn">' . esc_html__( 'No AI connector is configured. Add one under Settings → Connectors before turning this on.', 'security-ninja' ) . '</p>';
            echo '<p><a class="button button-secondary" href="' . esc_url( $connectors ) . '">' . esc_html__( 'Go to Settings → Connectors', 'security-ninja' ) . '</a> ';
            echo '<a href="' . esc_url( $advisor_url ) . '">' . esc_html__( 'Open Security Advisor', 'security-ninja' ) . '</a></p>';
            echo '</div>';
            return;
        }
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NOT_SELECTED === $connection ) {
            echo '<p class="wf-sn-ai-schedule-card__status wf-sn-ai-schedule-card__status--warn">' . esc_html__( 'Choose which AI connector Security Advisor should use, then come back here to turn on automatic reviews.', 'security-ninja' ) . '</p>';
            echo '<p><a class="button button-secondary" href="' . esc_url( $advisor_url ) . '">' . esc_html__( 'Choose AI connector', 'security-ninja' ) . '</a></p>';
            echo '</div>';
            return;
        }
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="wf-sn-ai-schedule-card__form">';
        echo '<input type="hidden" name="action" value="wf_sn_ai_advisor_save_schedule" />';
        wp_nonce_field( 'wf_sn_ai_advisor_save_schedule', 'wf_sn_ai_advisor_schedule_nonce' );
        echo '<table class="form-table"><tbody>';
        echo '<tr valign="top"><th scope="row"><label for="wf_sn_ai_advisor_scheduled_report_enabled"><h3>' . esc_html__( 'Automatic AI review', 'security-ninja' ) . '</h3>';
        echo '<p class="description">' . esc_html__( 'Each automatic review runs the security tests first, then sends those results and your latest stored scans to your AI connector. Malware scans stay on their own schedule.', 'security-ninja' ) . '</p>';
        echo '</label></th><td class="sn-cf-options">';
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_ai_advisor_scheduled_report_enabled', array(
            'value'       => 1,
            'saved_value' => ( $enabled && $can_enable ? 1 : 0 ),
            'option_key'  => 'wf_sn_ai_advisor_scheduled_report_enabled',
        ) );
        echo '</td></tr>';
        echo '<tr valign="top"><th scope="row"><label for="wf_sn_ai_advisor_scheduled_report_interval"><h3>' . esc_html__( 'How often', 'security-ninja' ) . '</h3>';
        if ( $is_premium ) {
            echo '<p class="description">' . esc_html__( 'Monthly is enough for most sites. Weekly or daily uses more of your AI account.', 'security-ninja' ) . '</p>';
        } else {
            echo '<p class="description">' . esc_html__( 'About once a month. Weekly and daily reviews are available in Pro.', 'security-ninja' ) . '</p>';
        }
        echo '</label></th><td class="sn-cf-options">';
        if ( $is_premium ) {
            $interval_options = array(array(
                'val'   => Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_MONTHLY,
                'label' => __( 'Monthly', 'security-ninja' ),
            ), array(
                'val'   => Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_WEEKLY,
                'label' => __( 'Weekly', 'security-ninja' ),
            ), array(
                'val'   => Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_DAILY,
                'label' => __( 'Daily', 'security-ninja' ),
            ));
            echo '<select name="wf_sn_ai_advisor_scheduled_report_interval" id="wf_sn_ai_advisor_scheduled_report_interval" class="regular-text">';
            \WPSecurityNinja\Plugin\Utils::create_select_options( $interval_options, $interval );
            echo '</select>';
        } else {
            echo '<input type="hidden" name="wf_sn_ai_advisor_scheduled_report_interval" value="' . esc_attr( Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_MONTHLY ) . '" />';
            echo '<p><strong>' . esc_html__( 'About once a month', 'security-ninja' ) . '</strong></p>';
        }
        echo '</td></tr>';
        echo '</tbody></table>';
        echo '<p class="wf-sn-ai-schedule-card__status">';
        echo esc_html( self::get_status_line(
            $enabled,
            $connection,
            $interval,
            $scheduler_st
        ) );
        echo '</p>';
        echo '<p class="submit"><input type="submit" value="' . esc_attr__( 'Save Changes', 'security-ninja' ) . '" class="input-button button-primary" name="Submit"></p>';
        echo '<p><a href="' . esc_url( $advisor_url ) . '">' . esc_html__( 'Open Security Advisor', 'security-ninja' ) . '</a></p>';
        echo '</form></div>';
    }

    /**
     * Status sentence for Scheduler and Advisor.
     *
     * @param bool   $enabled     Toggle.
     * @param string $connection  Connection state.
     * @param string $interval    Interval slug.
     * @param array  $state       Scheduler state.
     * @return string
     */
    public static function get_status_line(
        $enabled,
        $connection,
        $interval,
        $state = array()
    ) {
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_UNAVAILABLE === $connection ) {
            return __( 'Automatic reviews need WordPress 7 AI Connectors.', 'security-ninja' );
        }
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NO_CONNECTOR === $connection ) {
            return __( 'Automatic review is waiting: connect an AI provider under Settings → Connectors.', 'security-ninja' );
        }
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NOT_SELECTED === $connection ) {
            return __( 'Automatic review is waiting: choose an AI connector on the Security Advisor page.', 'security-ninja' );
        }
        if ( !$enabled ) {
            return __( 'Automatic review is off. Turn it on here when you want reviews without clicking Generate.', 'security-ninja' );
        }
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Readiness' ) && Wf_Sn_Ai_Advisor_Readiness::is_security_tests_missing() ) {
            return __( 'Automatic review is on. The next run will start with a security test pass.', 'security-ninja' );
        }
        $timestamp = ( isset( $state['timestamp'] ) ? (int) $state['timestamp'] : 0 );
        $label = Wf_Sn_Ai_Advisor_Schedule_Policy::interval_label( $interval );
        if ( $timestamp > 0 ) {
            $next_at = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
            $time_until = human_time_diff( current_time( 'timestamp' ), $timestamp );
            return sprintf(
                /* translators: 1: frequency label, 2: next run datetime, 3: human time until next run */
                __( 'Next automatic review: %2$s (%3$s from now). Frequency: %1$s.', 'security-ninja' ),
                $label,
                $next_at,
                $time_until
            );
        }
        return __( 'Automatic review is on, but no run is scheduled yet. Save settings to create the schedule.', 'security-ninja' );
    }

    /**
     * Queue or run a scheduled report immediately (Pro admin test).
     *
     * @return void
     */
    public static function ajax_run_scheduled_now() {
        check_ajax_referer( 'wf_sn_ai_advisor', 'nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Forbidden.', 'security-ninja' ),
            ) );
        }
        $can_use_premium = false;
        if ( !$can_use_premium ) {
            wp_send_json_error( array(
                'message' => __( 'Premium license required.', 'security-ninja' ),
            ) );
        }
        if ( self::ensure_action_scheduler_loaded() && function_exists( 'as_schedule_single_action' ) ) {
            $action_id = as_schedule_single_action(
                time(),
                WF_SN_AI_ADVISOR_RUN_SCHEDULED,
                array(),
                'security-ninja'
            );
            if ( $action_id ) {
                self::maybe_run_queue();
                wp_send_json_success( array(
                    'message' => __( 'AI report queued. It will appear on the Security Advisor page when generation finishes.', 'security-ninja' ),
                ) );
            }
        }
        self::do_scheduled_report();
        wp_send_json_success( array(
            'message' => __( 'AI report generation completed.', 'security-ninja' ),
        ) );
    }

    /**
     * Clear all scheduled events for this feature.
     *
     * @return void
     */
    private static function clear_all_scheduled_events() {
        wp_clear_scheduled_hook( WF_SN_AI_ADVISOR_CRON );
        if ( self::ensure_action_scheduler_loaded() && function_exists( 'as_unschedule_all_actions' ) ) {
            as_unschedule_all_actions( WF_SN_AI_ADVISOR_RUN_SCHEDULED, array(), 'security-ninja' );
        }
    }

    /**
     * Ensure Action Scheduler is loaded.
     *
     * @return bool
     */
    private static function ensure_action_scheduler_loaded() {
        if ( function_exists( 'as_schedule_single_action' ) && function_exists( 'as_has_scheduled_action' ) ) {
            return true;
        }
        $path = null;
        if ( defined( 'WF_SN_PLUGIN_DIR' ) ) {
            $p = WF_SN_PLUGIN_DIR . 'vendor/woocommerce/action-scheduler/action-scheduler.php';
            if ( file_exists( $p ) && is_readable( $p ) ) {
                $path = $p;
            }
        }
        if ( !$path ) {
            $plugin_root = dirname( __DIR__, 2 );
            $p = $plugin_root . '/vendor/woocommerce/action-scheduler/action-scheduler.php';
            if ( file_exists( $p ) && is_readable( $p ) ) {
                $path = $p;
            }
        }
        if ( $path ) {
            require_once $path;
            return function_exists( 'as_schedule_single_action' );
        }
        return false;
    }

    /**
     * Trigger Action Scheduler queue runner if needed.
     *
     * @return void
     */
    private static function maybe_run_queue() {
        if ( self::ensure_action_scheduler_loaded() && function_exists( 'as_has_scheduled_action' ) && function_exists( 'as_enqueue_async_action' ) ) {
            if ( !as_has_scheduled_action( 'action_scheduler_run_queue' ) ) {
                as_enqueue_async_action( 'action_scheduler_run_queue', array(), 'action-scheduler' );
            }
        }
    }

    /**
     * Log a skipped or failed scheduled run.
     *
     * @param string $message Message.
     * @return void
     */
    private static function log_skip_event( $message ) {
        if ( class_exists( 'WPSecurityNinja\\Plugin\\wf_sn_el_modules' ) ) {
            \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                'security_ninja',
                'ai_advisor',
                $message,
                ''
            );
        }
    }

}
