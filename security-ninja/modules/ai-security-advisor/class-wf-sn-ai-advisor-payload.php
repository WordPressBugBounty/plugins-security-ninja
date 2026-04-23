<?php

/**
 * AI Security Advisor – payload for AI context.
 *
 * Single source of truth: feature flags, test results (testid, status, summary/details when present),
 * and aggregated counts. Plain text sent to the model is stripped of HTML and passed through
 * redact_sensitive_for_ai() to reduce filesystem paths and known username patterns from test output.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use WPSecurityNinja\Plugin\Wf_Sn_Test_Descriptions;
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
     * @return array Context array safe for JSON (paths/usernames in test copy redacted for AI).
     */
    public static function build( $request_type = 'full_report', $ui_locale_override = '' ) {
        $count_data = self::get_test_counts();
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
            'tests_passed'             => ( isset( $count_data['good'] ) ? (int) $count_data['good'] : 0 ),
            'tests_warning'            => ( isset( $count_data['warning'] ) ? (int) $count_data['warning'] : 0 ),
            'tests_failed'             => ( isset( $count_data['bad'] ) ? (int) $count_data['bad'] : 0 ),
            'tests_with_guidance'      => self::build_tests_with_guidance( $tests ),
            'plan_tier'                => $plan_tier,
            'attack_activity'          => $attack_state,
            'ui_locale'                => $ui_locale,
            'ui_language_name'         => $ui_locale,
        );
        return $context;
    }

    /**
     * Failing/warning tests with product guidance text for AI (no HTML).
     *
     * @param array $tests From get_test_results_safe().
     * @return array<int, array<string, mixed>>
     */
    private static function build_tests_with_guidance( array $tests ) {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_Test_Descriptions' ) ) {
            return array();
        }
        $out = array();
        foreach ( $tests as $t ) {
            if ( !is_array( $t ) || empty( $t['testid'] ) ) {
                continue;
            }
            $status = ( isset( $t['status'] ) ? (int) $t['status'] : 10 );
            // 10 = pass; 0 = fail; 5 = warning (Security Ninja test convention).
            if ( 10 === $status ) {
                continue;
            }
            $guidance = Wf_Sn_Test_Descriptions::get_guidance_for_ai( (string) $t['testid'] );
            if ( '' === $guidance['guidance'] && '' === $guidance['title'] ) {
                continue;
            }
            $tid = sanitize_key( (string) $t['testid'] );
            foreach ( array(
                'title',
                'short',
                'guidance',
                'caveats',
                'fix_hints'
            ) as $gk ) {
                if ( isset( $guidance[$gk] ) && is_string( $guidance[$gk] ) && '' !== $guidance[$gk] ) {
                    $guidance[$gk] = self::redact_sensitive_for_ai( $guidance[$gk], $tid );
                }
            }
            $row = $t;
            $row['guidance'] = $guidance;
            $out[] = $row;
        }
        return $out;
    }

    /**
     * Get test result counts from existing API (no overall score).
     *
     * @return array{good: int, bad: int, warning: int}
     */
    private static function get_test_counts() {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn' ) ) {
            return array(
                'good'    => 0,
                'bad'     => 0,
                'warning' => 0,
            );
        }
        $response = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
        if ( !is_array( $response ) ) {
            return array(
                'good'    => 0,
                'bad'     => 0,
                'warning' => 0,
            );
        }
        return array(
            'good'    => ( isset( $response['good'] ) ? (int) $response['good'] : 0 ),
            'bad'     => ( isset( $response['bad'] ) ? (int) $response['bad'] : 0 ),
            'warning' => ( isset( $response['warning'] ) ? (int) $response['warning'] : 0 ),
        );
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
     * Strip HTML and normalize to plain text for AI context, then redact paths and known username patterns.
     *
     * @param string $text   Raw text possibly containing HTML.
     * @param string $testid Optional test slug; when `user_exists`, username-regex redaction is skipped for that test's copy (admin check).
     * @return string
     */
    private static function strip_html_for_context( $text, $testid = '' ) {
        if ( !is_string( $text ) || '' === $text ) {
            return '';
        }
        $text = wp_strip_all_tags( $text );
        $text = trim( $text );
        return self::redact_sensitive_for_ai( $text, $testid );
    }

    /**
     * Remove or neutralize filesystem paths and Security Ninja test message usernames before sending text to AI.
     *
     * Skips username-pattern redaction for test `user_exists` so the model still sees the literal `admin` check result.
     *
     * @param string $text   Plain text.
     * @param string $testid Optional test slug (see strip_html_for_context).
     * @return string
     */
    public static function redact_sensitive_for_ai( $text, $testid = '' ) {
        if ( !is_string( $text ) || '' === $text ) {
            return '';
        }
        $original = $text;
        // WordPress install paths: replace longest prefixes first (ABSPATH before its parent directory).
        if ( defined( 'ABSPATH' ) && is_string( ABSPATH ) && '' !== ABSPATH ) {
            $abs_norm = wp_normalize_path( ABSPATH );
            $parent_norm = wp_normalize_path( dirname( $abs_norm ) );
            $pairs = array();
            foreach ( array($abs_norm, $parent_norm) as $base ) {
                if ( '' === $base || '.' === $base ) {
                    continue;
                }
                $slug = ( $base === $abs_norm ? '[WP_ROOT]' : '[WP_PARENT]' );
                foreach ( array(trailingslashit( $base ), untrailingslashit( $base )) as $variant ) {
                    if ( '' !== $variant && strlen( $variant ) > 1 ) {
                        $pairs[$variant] = $slug;
                    }
                }
            }
            uksort( $pairs, function ( $a, $b ) {
                return strlen( $b ) - strlen( $a );
            } );
            foreach ( $pairs as $from => $to ) {
                if ( strpos( $text, $from ) !== false ) {
                    $text = str_replace( $from, $to, $text );
                }
            }
        }
        // Common dev home-directory segments not covered by ABSPATH alone.
        $path_replacements = array(
            '#/Users/[^/]+/#'                           => '/Users/[user]/',
            '#/home/[^/]+/#'                            => '/home/[user]/',
            '#(?i)([a-z]:\\\\Users\\\\)[^\\\\]+(\\\\)#' => '$1[user]$2',
        );
        $username_replacements = array(
            '/(The user with ID 1 exists, and the username is)\\s+.+?\\./u' => '$1 [redacted].',
            '/(User\\s+")([^"]+)("\\s+exists\\.)/u'                         => '$1[redacted]$3',
            '/(User\\s+")([^"]+)("\\s+does not exist\\.)/u'                 => '$1[redacted]$3',
            '/(Vulnerable accounts:)\\s*.+$/um'                             => '$1 [redacted]',
            '/(Unexpected MySQL current user host:)\\s*.+$/um'              => '$1 [redacted]',
        );
        $replacements = $path_replacements;
        if ( 'user_exists' !== sanitize_key( (string) $testid ) ) {
            $replacements = array_merge( $replacements, $username_replacements );
        }
        foreach ( $replacements as $pattern => $replacement ) {
            $next = preg_replace( $pattern, $replacement, $text );
            if ( is_string( $next ) ) {
                $text = $next;
            }
        }
        /**
         * Filter plain text after AI advisor path/username redaction.
         *
         * @param string $text     Redacted text.
         * @param string $original Original plain text before redaction.
         * @param string $testid   Test slug passed to redact_sensitive_for_ai(), or empty string.
         */
        return (string) apply_filters(
            'wf_sn_ai_advisor_redacted_text',
            $text,
            $original,
            $testid
        );
    }

    /**
     * Test results: testid, status, and when failing/warning a plain-text summary (and details) for the AI.
     *
     * @return array List of arrays with testid, status, and optionally summary, details.
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
            $status = ( isset( $row['status'] ) ? (int) $row['status'] : 0 );
            $entry = array(
                'testid' => $testid,
                'status' => $status,
            );
            $msg = ( isset( $row['msg'] ) ? $row['msg'] : '' );
            $details = ( isset( $row['details'] ) ? $row['details'] : '' );
            if ( '' !== $msg ) {
                $entry['summary'] = self::strip_html_for_context( $msg, $testid );
            }
            if ( '' !== $details ) {
                $entry['details'] = self::strip_html_for_context( $details, $testid );
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
