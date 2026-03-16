<?php

/**
 * AI Security Advisor – privacy-safe payload for AI context.
 *
 * Single source of truth: feature flags, test results (testid, summary/details when present; no status/score),
 * aggregated counts, optional vulnerability summary, and (when Pro) Pro-only options with descriptions.
 * No domain, URLs, IPs, usernames, emails, or file paths.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Ai_Advisor_Payload
 */
class Wf_Sn_Ai_Advisor_Payload {
    /**
     * Build the payload array used for WordPress Connectors (as prompt context).
     *
     * @param string $request_type       Request type; only full_report is used. Kept for API consistency.
     * @param string $ui_locale_override Optional UI locale override for this request.
     * @return array Context array safe for JSON; no PII.
     */
    public static function build( $request_type = 'full_report', $ui_locale_override = '' ) {
        $flags = self::get_feature_flags();
        $tests = self::get_test_results_safe();
        $counts = Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d();
        $prev_counts = Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d();
        $attack_state = self::build_attack_activity_summary( $counts, $prev_counts );
        $ui_locale = ( function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale() );
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Page' ) ) {
            $options = Wf_Sn_Ai_Advisor_Page::get_options();
            if ( isset( $options['ui_locale'] ) && '' !== $options['ui_locale'] ) {
                $ui_locale = $options['ui_locale'];
            }
        }
        if ( '' !== $ui_locale_override ) {
            $ui_locale = $ui_locale_override;
        }
        $plan_tier = 'free';
        $context = array(
            'blocked_logins_7d'        => $counts['blocked_logins_7d'],
            'xmlrpc_blocks_7d'         => $counts['xmlrpc_blocks_7d'],
            'firewall_events_7d'       => $counts['firewall_events_7d'],
            'failed_logins_7d'         => ( isset( $counts['failed_logins_7d'] ) ? $counts['failed_logins_7d'] : 0 ),
            'firewall_enabled'         => $flags['firewall_enabled'],
            'login_protection_enabled' => $flags['login_protection_enabled'],
            'two_factor_enabled'       => $flags['two_factor_enabled'],
            'tests'                    => $tests,
            'plan_tier'                => $plan_tier,
            'attack_activity'          => $attack_state,
            'ui_locale'                => $ui_locale,
            'ui_language_name'         => $ui_locale,
        );
        // Vulnerability summary (available in both free and premium).
        $vuln_summary = self::get_vulnerability_summary();
        if ( !empty( $vuln_summary ) ) {
            $context = array_merge( $context, $vuln_summary );
        }
        return $context;
    }

    /**
     * Get privacy-safe vulnerability summary (counts only). Available in both free and premium.
     *
     * @return array<string, int|bool> Empty if vulnerability module not available.
     */
    private static function get_vulnerability_summary() {
        if ( !class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Vu' ) || !method_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Vu', 'get_scan_summary' ) ) {
            return array();
        }
        $summary = \WPSecurityNinja\Plugin\Wf_Sn_Vu::get_scan_summary();
        if ( !is_array( $summary ) ) {
            return array();
        }
        $vuln_count = ( isset( $summary['vuln_count'] ) ? (int) $summary['vuln_count'] : 0 );
        $out = array(
            'vuln_count'          => $vuln_count,
            'has_vulnerabilities' => $vuln_count > 0,
        );
        if ( !empty( $summary['vulnerabilities'] ) && is_array( $summary['vulnerabilities'] ) ) {
            $plugins = ( isset( $summary['vulnerabilities']['plugins'] ) && is_array( $summary['vulnerabilities']['plugins'] ) ? count( $summary['vulnerabilities']['plugins'] ) : 0 );
            $themes = ( isset( $summary['vulnerabilities']['themes'] ) && is_array( $summary['vulnerabilities']['themes'] ) ? count( $summary['vulnerabilities']['themes'] ) : 0 );
            $out['vuln_plugins_count'] = $plugins;
            $out['vuln_themes_count'] = $themes;
        }
        return $out;
    }

    /**
     * Feature flags: firewall via is_active() (same as sidebar), login protection and 2FA from options.
     * Use canonical method so firewall state matches what the plugin actually reports.
     *
     * @return array{firewall_enabled: bool, login_protection_enabled: bool, two_factor_enabled: bool}
     */
    private static function get_feature_flags() {
        $flags = array(
            'firewall_enabled'         => false,
            'login_protection_enabled' => false,
            'two_factor_enabled'       => false,
        );
        $cf_class = '\\WPSecurityNinja\\Plugin\\Wf_sn_cf';
        if ( class_exists( $cf_class ) ) {
            $cf_class::get_options();
            // Ensure options are loaded.
            if ( method_exists( $cf_class, 'is_active' ) ) {
                $flags['firewall_enabled'] = (int) $cf_class::is_active() === 1;
            }
            $cf = $cf_class::get_options();
            if ( is_array( $cf ) ) {
                $flags['login_protection_enabled'] = !empty( $cf['protect_login_form'] );
                $flags['two_factor_enabled'] = !empty( $cf['2fa_enabled'] );
            }
        }
        return $flags;
    }

    /**
     * Redact user path segments (e.g. /Users/username/) from text to avoid sending usernames to AI.
     *
     * @param string $text Raw text that may contain filesystem paths.
     * @return string Text with user path segments replaced by [user-path].
     */
    private static function redact_user_paths_for_context( $text ) {
        if ( !is_string( $text ) || '' === $text ) {
            return $text;
        }
        // Unix/macOS: /Users/username/ or /Users/username
        $text = preg_replace( '#/Users/[^/\\s]+#', '/Users/[user-path]', $text );
        // Windows: \Users\username\ or C:\Users\username\
        $text = preg_replace( '#(?i)([A-Z]:)?\\\\Users\\\\[^\\\\\\s]+#', '$1\\Users\\[user-path]', $text );
        return $text;
    }

    /**
     * Strip HTML and normalize to plain text for AI context (privacy-safe: no paths, domains, IPs).
     *
     * @param string $text Raw text possibly containing HTML.
     * @return string
     */
    private static function strip_html_for_context( $text ) {
        if ( !is_string( $text ) || '' === $text ) {
            return '';
        }
        $text = wp_strip_all_tags( $text );
        $text = self::redact_user_paths_for_context( $text );
        $text = apply_filters( 'wf_sn_ai_advisor_redact_pii_text', $text );
        return trim( $text );
    }

    /**
     * Test results: testid and when present plain-text summary and details for the AI. No status or score.
     *
     * @return array List of arrays with testid and optionally summary, details.
     */
    private static function get_test_results_safe() {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn' ) ) {
            return array();
        }
        $response = \WPSecurityNinja\Plugin\Wf_Sn::get_test_results();
        if ( !is_array( $response ) || empty( $response['test'] ) ) {
            // Fallback to last run from option so AI gets findings after a full test run before table was synced.
            $results = get_option( 'wf_sn_results', array() );
            if ( !is_array( $results ) || empty( $results['test'] ) ) {
                return array();
            }
            $response = array(
                'test' => $results['test'],
            );
        }
        $out = array();
        foreach ( $response['test'] as $testid => $row ) {
            $entry = array(
                'testid' => $testid,
            );
            $msg = ( isset( $row['msg'] ) ? $row['msg'] : '' );
            $details = ( isset( $row['details'] ) ? $row['details'] : '' );
            if ( '' !== $msg ) {
                $entry['summary'] = self::strip_html_for_context( $msg );
            }
            if ( '' !== $details ) {
                $entry['details'] = self::strip_html_for_context( $details );
            }
            $out[] = $entry;
        }
        return $out;
    }

    /**
     * Build an aggregated attack-activity summary for the last 7 days versus the previous 7 days.
     *
     * @param array $counts      Current 7-day counts from Aggregation::get_counts_7d().
     * @param array $prev_counts Previous 7-day counts from Aggregation::get_counts_prev_7d().
     * @return array{current_total:int, previous_total:int, trend:string, reason:string}
     */
    private static function build_attack_activity_summary( array $counts, array $prev_counts ) {
        $current_total = (int) $counts['blocked_logins_7d'] + (int) $counts['xmlrpc_blocks_7d'] + (int) $counts['firewall_events_7d'] + (int) $counts['failed_logins_7d'];
        $previous_total = (int) $prev_counts['blocked_logins_prev_7d'] + (int) $prev_counts['xmlrpc_blocks_prev_7d'] + (int) $prev_counts['firewall_events_prev_7d'] + (int) $prev_counts['failed_logins_prev_7d'];
        $trend = 'unknown';
        $reason = '';
        if ( 0 === $current_total && 0 === $previous_total ) {
            $trend = 'stable';
            $reason = 'No recorded blocked or failed events in the last 14 days.';
        } elseif ( 0 === $previous_total && $current_total > 0 ) {
            $trend = 'up';
            $reason = sprintf( 
                /* translators: %d: number of blocked or failed events in the last 7 days */
                __( 'Detected %d blocked or failed events in the last 7 days, compared to none in the previous 7 days.', 'security-ninja' ),
                $current_total
             );
        } else {
            $delta = $current_total - $previous_total;
            $ratio = $delta / max( 1, $previous_total );
            if ( $ratio > 0.25 ) {
                $trend = 'up';
            } elseif ( $ratio < -0.25 ) {
                $trend = 'down';
            } else {
                $trend = 'stable';
            }
            /* translators: 1: current 7-day event count, 2: previous 7-day event count */
            $reason = sprintf( __( 'Current 7-day total is %1$d events versus %2$d in the previous 7 days.', 'security-ninja' ), $current_total, $previous_total );
        }
        return array(
            'current_total'  => $current_total,
            'previous_total' => $previous_total,
            'trend'          => $trend,
            'reason'         => $reason,
        );
    }

}
