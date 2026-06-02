<?php

/**
 * AI Security Advisor – payload for AI context.
 *
 * Single source of truth: feature flags, tests_with_guidance for non-passing tests,
 * aggregate test counts, and other module summaries.
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
     * @param string $ui_locale_override Optional UI locale override for this request.
     * @return array Context array safe for JSON (paths/usernames in test copy redacted for AI).
     */
    public static function build( $ui_locale_override = '' ) {
        $count_data = Wf_Sn_Ai_Advisor_Test_Scores::get_counts();
        $flags = self::get_feature_flags();
        $counts = Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d();
        $prev_counts = Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d();
        $attack_state = Wf_Sn_Ai_Advisor_Attack_Activity::build_summary( $counts, $prev_counts );
        $ui_locale = ( function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale() );
        $options = Wf_Sn_Ai_Advisor_Page::get_options();
        if ( isset( $options['ui_locale'] ) && '' !== $options['ui_locale'] ) {
            $ui_locale = $options['ui_locale'];
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
            'tests_passed'             => ( isset( $count_data['good'] ) ? (int) $count_data['good'] : 0 ),
            'tests_warning'            => ( isset( $count_data['warning'] ) ? (int) $count_data['warning'] : 0 ),
            'tests_failed'             => ( isset( $count_data['bad'] ) ? (int) $count_data['bad'] : 0 ),
            'tests_with_guidance'      => self::build_tests_with_guidance(),
            'plan_tier'                => $plan_tier,
            'attack_activity'          => $attack_state,
            'vulnerabilities'          => self::build_vulnerabilities_summary(),
            'core_scanner'             => self::build_core_scanner_summary(),
            'recent_events'            => self::build_recent_events_summary(),
            'ui_locale'                => $ui_locale,
            'ui_language_name'         => $ui_locale,
        );
        return $context;
    }

    /**
     * Build privacy-safe vulnerability summary.
     *
     * @return array<string,mixed>
     */
    private static function build_vulnerabilities_summary() {
        $out = array(
            'total' => 0,
            'items' => array(),
        );
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_Vu' ) ) {
            return $out;
        }
        $data = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vulnerabilities();
        if ( !is_array( $data ) ) {
            return $out;
        }
        $items = array();
        foreach ( array('plugins', 'themes', 'wordpress') as $type ) {
            if ( empty( $data[$type] ) || !is_array( $data[$type] ) ) {
                continue;
            }
            foreach ( $data[$type] as $slug => $row ) {
                if ( !is_array( $row ) ) {
                    continue;
                }
                $entry = array(
                    'type'              => $type,
                    'name'              => ( isset( $row['name'] ) ? self::redact_sensitive_for_ai( (string) $row['name'] ) : '' ),
                    'slug'              => sanitize_key( ( is_string( $slug ) ? $slug : '' ) ),
                    'installed_version' => ( isset( $row['installedVersion'] ) ? (string) $row['installedVersion'] : '' ),
                    'cve_id'            => ( isset( $row['CVE_ID'] ) ? (string) $row['CVE_ID'] : '' ),
                    'short_description' => ( isset( $row['desc'] ) ? self::redact_sensitive_for_ai( (string) $row['desc'] ) : '' ),
                );
                $items[] = $entry;
            }
        }
        $out['total'] = count( $items );
        $out['items'] = array_slice( $items, 0, 25 );
        return $out;
    }

    /**
     * Build summarized core scanner findings.
     *
     * @return array<string,mixed>
     */
    private static function build_core_scanner_summary() {
        $results = get_option( 'wf_sn_cs_results', array() );
        if ( !is_array( $results ) ) {
            $results = array();
        }
        return array(
            'last_run'          => ( isset( $results['last_run'] ) ? (int) $results['last_run'] : 0 ),
            'changed_bad_count' => ( isset( $results['changed_bad'] ) && is_array( $results['changed_bad'] ) ? count( $results['changed_bad'] ) : 0 ),
            'missing_bad_count' => ( isset( $results['missing_bad'] ) && is_array( $results['missing_bad'] ) ? count( $results['missing_bad'] ) : 0 ),
            'unknown_bad_count' => ( isset( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ? count( $results['unknown_bad'] ) : 0 ),
            'ok_count'          => ( isset( $results['ok'] ) && is_array( $results['ok'] ) ? count( $results['ok'] ) : 0 ),
            'changed_bad_files' => self::basename_list( ( isset( $results['changed_bad'] ) && is_array( $results['changed_bad'] ) ? $results['changed_bad'] : array() ), 20 ),
            'missing_bad_files' => self::basename_list( ( isset( $results['missing_bad'] ) && is_array( $results['missing_bad'] ) ? $results['missing_bad'] : array() ), 20 ),
            'unknown_bad_files' => self::basename_list( ( isset( $results['unknown_bad'] ) && is_array( $results['unknown_bad'] ) ? $results['unknown_bad'] : array() ), 20 ),
        );
    }

    /**
     * Build short list of recent event logger entries.
     *
     * @return array<int,array<string,string>>
     */
    private static function build_recent_events_summary() {
        $out = array();
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_El' ) || !\WPSecurityNinja\Plugin\Wf_Sn_El::is_active() ) {
            return $out;
        }
        global $wpdb;
        $table = $wpdb->prefix . 'wf_sn_el';
        $mods = array(
            'security_ninja',
            'installer',
            'users',
            'file_editor',
            'settings'
        );
        $in = implode( ',', array_fill( 0, count( $mods ), '%s' ) );
        $query = $wpdb->prepare( "SELECT module, action, description FROM {$table} WHERE timestamp >= DATE_SUB( NOW(), INTERVAL 7 DAY ) AND module IN ({$in}) ORDER BY timestamp DESC LIMIT 8", $mods );
        $rows = $wpdb->get_results( $query, ARRAY_A );
        if ( !is_array( $rows ) ) {
            return $out;
        }
        foreach ( $rows as $row ) {
            if ( !is_array( $row ) ) {
                continue;
            }
            $desc = ( isset( $row['description'] ) ? self::redact_sensitive_for_ai( (string) $row['description'] ) : '' );
            $desc = preg_replace( '/[A-Z0-9._%+\\-]+@[A-Z0-9.\\-]+\\.[A-Z]{2,}/i', '[redacted-email]', $desc );
            if ( !is_string( $desc ) ) {
                $desc = '';
            }
            $out[] = array(
                'module'      => ( isset( $row['module'] ) ? sanitize_key( (string) $row['module'] ) : '' ),
                'action'      => ( isset( $row['action'] ) ? sanitize_key( (string) $row['action'] ) : '' ),
                'description' => $desc,
            );
        }
        return $out;
    }

    /**
     * Convert paths to basename list.
     *
     * @param array<int,mixed> $items Input list.
     * @param int              $limit Maximum output.
     * @return array<int,string>
     */
    private static function basename_list( array $items, $limit ) {
        $out = array();
        foreach ( $items as $value ) {
            if ( !is_string( $value ) || '' === $value ) {
                continue;
            }
            $out[] = wp_basename( $value );
        }
        return array_slice( array_values( array_unique( $out ) ), 0, (int) $limit );
    }

    /**
     * Non-passing tests with live findings and product guidance (no HTML).
     *
     * @return array<int, array<string, mixed>>
     */
    private static function build_tests_with_guidance() {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_Test_Descriptions' ) ) {
            return array();
        }
        $max_items = (int) apply_filters( 'wf_sn_ai_advisor_guidance_max_items', 30 );
        $max_items = max( 5, min( 50, $max_items ) );
        $rows = self::get_raw_test_results();
        $out = array();
        foreach ( $rows as $testid => $row ) {
            if ( !is_array( $row ) ) {
                continue;
            }
            $status = ( isset( $row['status'] ) ? (int) $row['status'] : 10 );
            // 10 = pass; 0 = fail; 5 = warning; 7 = info (Security Ninja test convention).
            if ( 10 === $status ) {
                continue;
            }
            $tid = sanitize_key( (string) $testid );
            if ( '' === $tid ) {
                continue;
            }
            $guidance = Wf_Sn_Test_Descriptions::get_guidance_for_ai( $tid );
            $title = ( isset( $guidance['title'] ) && is_string( $guidance['title'] ) ? self::redact_sensitive_for_ai( $guidance['title'], $tid ) : '' );
            $summary = ( isset( $guidance['short'] ) && is_string( $guidance['short'] ) && '' !== $guidance['short'] ? self::redact_sensitive_for_ai( $guidance['short'], $tid ) : '' );
            if ( '' === $summary && !empty( $guidance['guidance'] ) && is_string( $guidance['guidance'] ) ) {
                $summary = self::truncate_text_for_ai( self::redact_sensitive_for_ai( $guidance['guidance'], $tid ) );
            }
            $entry = array(
                'testid' => (string) $testid,
                'status' => $status,
            );
            if ( '' !== $title ) {
                $entry['title'] = $title;
            }
            $msg = ( isset( $row['msg'] ) ? (string) $row['msg'] : '' );
            $details = ( isset( $row['details'] ) ? (string) $row['details'] : '' );
            if ( '' !== $msg ) {
                $entry['finding'] = self::truncate_text_for_ai( self::strip_html_for_context( $msg, $tid ), 220 );
            }
            if ( '' !== $details ) {
                $entry['details'] = self::truncate_text_for_ai( self::strip_html_for_context( $details, $tid ), 180 );
            }
            if ( '' !== $summary ) {
                $entry['guidance'] = $summary;
            }
            if ( empty( $entry['finding'] ) && empty( $entry['guidance'] ) && empty( $entry['title'] ) ) {
                continue;
            }
            $out[] = $entry;
            if ( count( $out ) >= $max_items ) {
                break;
            }
        }
        return $out;
    }

    /**
     * Raw Security Ninja test rows keyed by test id.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function get_raw_test_results() {
        if ( !class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn' ) ) {
            return array();
        }
        $response = \WPSecurityNinja\Plugin\Wf_Sn::get_test_results();
        if ( !is_array( $response ) || empty( $response['test'] ) || !is_array( $response['test'] ) ) {
            $results = get_option( 'wf_sn_results', array() );
            if ( !is_array( $results ) || empty( $results['test'] ) || !is_array( $results['test'] ) ) {
                return array();
            }
            return $results['test'];
        }
        return $response['test'];
    }

    /**
     * Truncate plain text for AI payload lines.
     *
     * @param string $text    Input text.
     * @param int    $max_len Max characters (UTF-8 when mbstring available).
     * @return string
     */
    private static function truncate_text_for_ai( $text, $max_len = 0 ) {
        if ( !is_string( $text ) || '' === $text ) {
            return '';
        }
        if ( $max_len <= 0 ) {
            /**
             * Max characters for compact test guidance sent to AI.
             *
             * @param int $default Default limit.
             */
            $max_len = (int) apply_filters( 'wf_sn_ai_advisor_guidance_summary_max_chars', 400 );
            $max_len = max( 120, min( 1200, $max_len ) );
        }
        if ( function_exists( 'mb_strlen' ) && mb_strlen( $text, 'UTF-8' ) <= $max_len ) {
            return $text;
        }
        if ( !function_exists( 'mb_strlen' ) && strlen( $text ) <= $max_len ) {
            return $text;
        }
        if ( function_exists( 'mb_substr' ) ) {
            return mb_substr(
                $text,
                0,
                $max_len,
                'UTF-8'
            ) . '…';
        }
        return substr( $text, 0, $max_len ) . '…';
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
        $next = preg_replace( '/\\[WP_ROOT\\](?=[^\\/\\s])/', '[WP_ROOT]/', $text );
        if ( is_string( $next ) ) {
            $text = $next;
        }
        $next = preg_replace( '/\\[WP_PARENT\\](?=[^\\/\\s])/', '[WP_PARENT]/', $text );
        if ( is_string( $next ) ) {
            $text = $next;
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

}
