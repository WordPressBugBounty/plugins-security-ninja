<?php

namespace WPSecurityNinja\Plugin;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
class WF_SN_Overview_Tab {
    /**
     * Renders the overview tab content.
     *
     * @return void
     */
    public static function tab_overview() : void {
        ?>
	<div class="sn-overview-container">
		<?php 
        self::render_card_test_scores();
        self::render_card_ai_advisor();
        self::render_card_next_actions();
        self::render_card_what_changed();
        self::render_card_vulnerabilities();
        self::render_card_updates();
        self::render_card_firewall();
        self::render_card_quick_actions();
        self::render_card_upgrade_pro();
        ?>
	</div>
		<?php 
    }

    /**
     * Security score / test results card.
     */
    private static function render_card_test_scores() : void {
        ?>
	<div id="testscores">
		<?php 
        $scores = wf_sn::return_test_scores();
        if ( 0 === $scores['score'] ) {
            echo '<div class="sncard">';
            echo '<h3><span class="dashicons dashicons-saved"></span> ' . esc_html__( 'No Test Results Yet', 'security-ninja' ) . '</h3>';
            echo '<p>' . esc_html__( 'You have not run any security tests yet. Visit the Tests tab to scan your site and get your security score.', 'security-ninja' ) . '</p>';
            echo '<p><a href="#sn_tests" class="">' . esc_html__( 'Run Security Tests', 'security-ninja' ) . '</a></p>';
            echo '</div>';
        }
        if ( $scores['good'] > 0 || $scores['bad'] > 0 || $scores['warning'] > 0 || $scores['score'] > 0 ) {
            echo '<div class="sncard">';
            echo '<h2><span class="dashicons dashicons-saved"></span> ' . esc_html__( 'Your Security Test Results', 'security-ninja' ) . '</h2>';
            echo '<p>' . esc_html__( 'Here is a quick overview of how your site is doing:', 'security-ninja' ) . '</p>';
            ?>
		<div id="secscore">
		<div class="sectitle"><?php 
            echo esc_html__( 'Security Score', 'security-ninja' );
            ?></div>
		<div class="secscore-value"><?php 
            echo absint( $scores['score'] );
            ?>%</div>
		</div>
		<div id="secscorerowrow">
		<div class="inner" style="width:<?php 
            echo esc_attr( (string) absint( $scores['score'] ) );
            ?>%;"></div>
		</div>
		<div id="secscore-details">
		<div class="secscore-passed"><span class="det-count"><?php 
            echo absint( $scores['good'] );
            ?></span><span class="det"><?php 
            echo esc_html__( 'Tests passed', 'security-ninja' );
            ?></span></div>
		<div class="secscore-warning"><span class="det-count"><?php 
            echo absint( $scores['warning'] );
            ?></span><span class="det"><?php 
            echo esc_html__( 'Warnings', 'security-ninja' );
            ?></span></div>
		<div class="secscore-failed"><span class="det-count"><?php 
            echo absint( $scores['bad'] );
            ?></span><span class="det"><?php 
            echo esc_html__( 'Tests failed', 'security-ninja' );
            ?></span></div>
		</div>
		<div class="secscore-link"><a href="#sn_tests" class="button snbtn alignright"><?php 
            echo esc_html__( 'Visit Security Tests', 'security-ninja' );
            ?> &rarr;</a></div>
		</div>
			<?php 
        }
        ?>
	</div>
		<?php 
    }

    /**
     * AI Security Advisor card (optional layer).
     */
    private static function render_card_ai_advisor() : void {
        if ( !apply_filters( 'wf_sn_ai_advisor_enabled', true ) ) {
            return;
        }
        if ( !class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor' ) ) {
            return;
        }
        $ai = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor::get_card_state();
        $advisor_url = $ai['advisor_url'];
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        echo '<div class="sncard sncard-ai-advisor">';
        echo '<h3><span class="dashicons dashicons-admin-generic"></span> ' . esc_html__( 'AI Security Advisor', 'security-ninja' ) . '</h3>';
        echo '<p class="description">' . esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( '%s scans your site. The AI Advisor explains what changed, what matters, and what to fix first.', 'security-ninja' ),
            $plugin_name
         ) ) . '</p>';
        if ( 1 === (int) $ai['state'] ) {
            echo '<p>' . esc_html__( 'The AI Security Advisor will be available when you update to WordPress 7. You will be able to get an AI-powered security review using WordPress AI Connectors.', 'security-ninja' ) . '</p>';
            echo '<p class="description">' . esc_html( sprintf( 
                /* translators: %s: plugin display name */
                __( 'AI is not required. %s still works fully without it.', 'security-ninja' ),
                $plugin_name
             ) ) . '</p>';
        } elseif ( 2 === (int) $ai['state'] ) {
            if ( !empty( $ai['last_reviewed'] ) ) {
                echo '<p>' . esc_html__( 'Last reviewed', 'security-ninja' ) . ' ' . esc_html( $ai['last_reviewed'] ) . ' ' . esc_html__( 'ago', 'security-ninja' ) . '.</p>';
                if ( !empty( $ai['teaser'] ) ) {
                    echo '<div class="wf-sn-ai-teaser">' . wp_kses_post( wpautop( esc_html( $ai['teaser'] ) ) ) . '</div>';
                }
                echo '<div class="secscore-link sn-overview-ai-actions">';
                echo '<a href="' . esc_url( $advisor_url ) . '" class="button snbtn">' . esc_html__( 'Ask AI what to fix first', 'security-ninja' ) . '</a> ';
                echo '<a href="' . esc_url( $advisor_url ) . '" class="button button-link">' . esc_html__( 'View last report', 'security-ninja' ) . '</a>';
                echo '</div>';
            } else {
                echo '<p>' . esc_html__( 'Get a plain-English security review based on your scans, firewall activity, vulnerabilities, and login events.', 'security-ninja' ) . '</p>';
                echo '<p class="description">' . esc_html__( 'Recommended before first review: run security tests, vulnerability scan, core scanner, and enable firewall/event logging.', 'security-ninja' ) . '</p>';
                echo '<div class="secscore-link sn-overview-ai-actions">';
                echo '<a href="' . esc_url( Wf_Sn_Admin_Links::url( 'tests' ) ) . '" class="button snbtn">' . esc_html__( 'Run recommended scans', 'security-ninja' ) . '</a> ';
                echo '<a href="' . esc_url( $advisor_url ) . '" class="button button-primary snbtn">' . esc_html__( 'Generate AI review', 'security-ninja' ) . '</a>';
                echo '</div>';
            }
        } else {
            echo '<p>' . esc_html( sprintf( 
                /* translators: %s: plugin display name */
                __( 'Optional: Get a plain-English review of your site security based on %s\'s latest findings.', 'security-ninja' ),
                $plugin_name
             ) ) . '</p>';
            echo '<p class="description">' . esc_html( sprintf( 
                /* translators: %s: plugin display name */
                __( 'AI is not required. %s still works fully without it.', 'security-ninja' ),
                $plugin_name
             ) ) . '</p>';
            echo '<div class="secscore-link sn-overview-ai-actions">';
            echo '<a href="' . esc_url( $advisor_url ) . '" class="button snbtn">' . esc_html__( 'Set up AI Advisor', 'security-ninja' ) . '</a>';
            echo '</div>';
        }
        echo '</div>';
    }

    /**
     * Deterministic next best actions (no AI).
     */
    private static function render_card_next_actions() : void {
        $actions = Wf_Sn_Priority_Resolver::get( 3 );
        echo '<div class="sncard sncard-next-actions">';
        echo '<h3><span class="dashicons dashicons-list-view"></span> ' . esc_html__( 'Next best actions', 'security-ninja' ) . '</h3>';
        if ( empty( $actions ) ) {
            echo '<p>' . esc_html__( 'No urgent actions right now. Keep scans and updates current.', 'security-ninja' ) . '</p>';
        } else {
            echo '<ol class="sn-next-actions-list">';
            foreach ( $actions as $action ) {
                echo '<li class="sn-next-action sn-next-action--' . esc_attr( $action['severity'] ) . '">';
                echo '<strong>' . esc_html( $action['title'] ) . '</strong>';
                echo '<p class="description">' . esc_html( $action['summary'] ) . '</p>';
                echo '<a href="' . esc_url( $action['action_url'] ) . '" class="button button-small snbtn">' . esc_html( $action['action_text'] ) . '</a>';
                echo '</li>';
            }
            echo '</ol>';
        }
        if ( class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor' ) && apply_filters( 'wf_sn_ai_advisor_enabled', true ) ) {
            $ai = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor::get_card_state();
            if ( 2 === (int) $ai['state'] && !empty( $ai['has_connectors'] ) ) {
                echo '<p class="sn-next-actions-ai-link"><a href="' . esc_url( $ai['advisor_url'] ) . '">' . esc_html__( 'Ask AI to explain priorities', 'security-ninja' ) . '</a></p>';
            }
        }
        echo '</div>';
    }

    /**
     * What changed card (deterministic diff vs last AI report snapshot).
     */
    private static function render_card_what_changed() : void {
        $diff = Wf_Sn_Security_Snapshot_Diff::get_overview_diff();
        echo '<div class="sncard sncard-what-changed">';
        echo '<h3><span class="dashicons dashicons-update"></span> ' . esc_html__( 'What changed', 'security-ninja' ) . '</h3>';
        if ( 'no_report' === $diff['empty_reason'] || !$diff['has_comparison'] ) {
            echo '<p>' . esc_html__( 'No previous comparison is available yet.', 'security-ninja' ) . '</p>';
            echo '<p class="description">' . esc_html__( 'Run a fresh AI review now. Future reports will show what improved, what changed, and what still needs attention.', 'security-ninja' ) . '</p>';
            if ( class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor' ) && apply_filters( 'wf_sn_ai_advisor_enabled', true ) ) {
                $ai = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor::get_card_state();
                if ( 2 === (int) $ai['state'] ) {
                    echo '<p><a href="' . esc_url( $ai['advisor_url'] ) . '" class="button snbtn">' . esc_html__( 'Generate AI review', 'security-ninja' ) . '</a></p>';
                }
            }
            echo '</div>';
            return;
        }
        self::render_diff_buckets( $diff );
        $details_url = admin_url( 'admin.php?page=wf-sn-advisor' );
        echo '<p><a href="' . esc_url( $details_url ) . '" class="button-link">' . esc_html__( 'View details in AI Advisor', 'security-ninja' ) . '</a></p>';
        echo '</div>';
    }

    /**
     * @param array{new: string[], improved: string[], needs_attention: string[]} $diff Diff buckets.
     */
    private static function render_diff_buckets( array $diff ) : void {
        foreach ( array(
            'new'             => __( 'New', 'security-ninja' ),
            'improved'        => __( 'Improved', 'security-ninja' ),
            'needs_attention' => __( 'Needs attention', 'security-ninja' ),
        ) as $key => $label ) {
            if ( empty( $diff[$key] ) || !is_array( $diff[$key] ) ) {
                continue;
            }
            echo '<h4>' . esc_html( $label ) . '</h4>';
            echo '<ul class="sn-what-changed-list">';
            foreach ( $diff[$key] as $line ) {
                echo '<li>' . esc_html( $line ) . '</li>';
            }
            echo '</ul>';
        }
        if ( empty( $diff['new'] ) && empty( $diff['improved'] ) && empty( $diff['needs_attention'] ) ) {
            echo '<p>' . esc_html__( 'No significant changes detected since your last AI review.', 'security-ninja' ) . '</p>';
        }
    }

    /**
     * Vulnerability scan results card.
     */
    private static function render_card_vulnerabilities() : void {
        ?>
	<div id="snvulns">
		<?php 
        if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Vu' ) && wf_sn_vu::$options['enable_vulns'] ) {
            $scan_data = wf_sn_vu::get_scan_summary();
            $vuln_results = $scan_data['vulnerabilities'];
            $scan_summary = $scan_data['scan_summary'];
            $has_vulnerabilities = $scan_data['has_vulnerabilities'];
            if ( $has_vulnerabilities ) {
                $checklist = array('plugins', 'themes', 'wordpress');
                $combined = array();
                foreach ( $checklist as $vulntype ) {
                    if ( isset( $vuln_results[$vulntype] ) ) {
                        foreach ( $vuln_results[$vulntype] as $data ) {
                            if ( 'WordPress' === $vulntype ) {
                                $combined[] = array(
                                    'name' => 'WordPress ' . ($data['CVE_ID'] ?? 'Vulnerability'),
                                    'ver'  => $scan_summary['wordpress']['current_version'] ?? get_bloginfo( 'version' ),
                                    'type' => 'wordpress',
                                );
                            } else {
                                $combined[] = array(
                                    'name' => $data['name'],
                                    'ver'  => $data['installedVersion'],
                                    'type' => $vulntype,
                                );
                            }
                        }
                    }
                }
                if ( $combined && count( $combined ) > 0 ) {
                    $total = count( $combined );
                    echo '<div class="sncard snerror">';
                    echo '<h3><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'Vulnerability Scan Results', 'security-ninja' ) . '</h3>';
                    echo '<p>' . esc_html__( 'Here are the vulnerabilities found on your site:', 'security-ninja' ) . '</p>';
                    echo '<ul style="list-style-type: none; padding: 0; margin-bottom:0px;">';
                    foreach ( $combined as $vuln ) {
                        $icon_class = ( 'plugins' === $vuln['type'] ? 'dashicons-admin-plugins' : (( 'themes' === $vuln['type'] ? 'dashicons-admin-appearance' : (( 'WordPress' === $vuln['type'] ? 'dashicons-wordpress' : '' )) )) );
                        echo '<li class="vuln-item"><span class="dashicons ' . esc_attr( $icon_class ) . '"></span><strong>' . esc_html( $vuln['name'] ) . '</strong>: ' . esc_html( $vuln['ver'] ) . '</li>';
                    }
                    echo '</ul>';
                    echo '<p>' . esc_html__( 'Total Vulnerabilities Found: ', 'security-ninja' ) . '<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>.';
                    echo ' <a href="#sn_vuln">' . esc_html__( 'Details', 'security-ninja' ) . '</a>.';
                    echo '</div>';
                }
            } else {
                echo '<div class="sncard">';
                echo '<h3><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'Vulnerability Scan Results', 'security-ninja' ) . '</h3>';
                echo '<div class="noerrorsfound"><h3>' . esc_html__( 'Great news!', 'security-ninja' ) . '</h3><p>' . esc_html__( 'No vulnerabilities found.', 'security-ninja' ) . '</p></div>';
                if ( $scan_summary ) {
                    echo '<p>' . sprintf(
                        esc_html__( 'Last scan: %1$s plugins, %2$s themes, WordPress %3$s checked.', 'security-ninja' ),
                        esc_html( number_format_i18n( $scan_summary['plugins']['plugins_checked'] ?? 0 ) ),
                        esc_html( number_format_i18n( $scan_summary['themes']['themes_checked'] ?? 0 ) ),
                        esc_html( $scan_summary['wordpress']['current_version'] ?? 'unknown' )
                    ) . '</p>';
                }
                echo '</div>';
            }
        } else {
            echo '<div class="sncard">';
            echo '<h3><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'Vulnerability Scan Results', 'security-ninja' ) . '</h3>';
            echo '<p>' . esc_html__( 'Vulnerability tracking is not enabled.', 'security-ninja' ) . '</p>';
            echo '</div>';
        }
        ?>
	</div>
		<?php 
    }

    /**
     * Available updates card (plugins, themes, core).
     */
    private static function render_card_updates() : void {
        $counts = Wf_Sn_Security_Snapshot::get_update_counts();
        $total = (int) $counts['total'];
        if ( $total <= 0 ) {
            return;
        }
        echo '<div class="sncard">';
        echo '<h3 class="warning"><span class="dashicons dashicons-warning"></span> ' . esc_html__( 'Available Updates', 'security-ninja' ) . '</h3>';
        $summary = '<span>' . sprintf( _n(
            '%d update available',
            '%d updates available',
            $total,
            'security-ninja'
        ), $total ) . '</span>';
        $parts = array();
        if ( $counts['plugins'] > 0 ) {
            $parts[] = sprintf( _n(
                '%d plugin',
                '%d plugins',
                $counts['plugins'],
                'security-ninja'
            ), $counts['plugins'] );
        }
        if ( $counts['themes'] > 0 ) {
            $parts[] = sprintf( _n(
                '%d theme',
                '%d themes',
                $counts['themes'],
                'security-ninja'
            ), $counts['themes'] );
        }
        if ( $counts['core'] > 0 ) {
            $parts[] = __( 'WordPress core', 'security-ninja' );
        }
        if ( !empty( $parts ) ) {
            $summary .= ' (' . implode( ', ', $parts ) . ')';
        }
        echo '<p class="sn-updates-summary">' . wp_kses_post( $summary ) . '</p>';
        echo '<div class="sn-updates-link"><a href="' . esc_url( admin_url( 'update-core.php' ) ) . '" class="button snbtn alignright">' . esc_html__( 'View update details', 'security-ninja' ) . ' &rarr; </a></div>';
        echo '</div>';
    }

    /**
     * Firewall summary card.
     */
    private static function render_card_firewall() : void {
        $free_actions_to_track = array(
            'wp_login'        => __( 'Successful login', 'security-ninja' ),
            'wp_login_failed' => __( 'Failed login attempt', 'security-ninja' ),
            'do_init_action'  => __( 'Blocked by firewall', 'security-ninja' ),
        );
        $actions_to_track = $free_actions_to_track;
        ?>
		<div class="sncard firewall-summary">
		<h3><span class="dashicons dashicons-warning"></span> <?php 
        echo esc_html__( 'Firewall Summary', 'security-ninja' );
        ?></h3>
		<?php 
        global $wpdb;
        $table_name = $wpdb->prefix . 'wf_sn_el';
        $placeholders = implode( ',', array_fill( 0, count( $actions_to_track ), '%s' ) );
        $action_counts = array_fill_keys( array_keys( $actions_to_track ), 0 );
        $action_results = $wpdb->get_results( $wpdb->prepare( "SELECT action, COUNT(*) as count FROM {$table_name} WHERE action IN ({$placeholders}) GROUP BY action", array_keys( $actions_to_track ) ), ARRAY_A );
        foreach ( $action_results as $action_result ) {
            $action_counts[$action_result['action']] = intval( $action_result['count'] );
        }
        $query = $wpdb->prepare( "SELECT id, timestamp, ip, action, raw_data FROM {$table_name} WHERE action IN ({$placeholders}) AND raw_data != 'N;' ORDER BY timestamp DESC LIMIT 10", array_keys( $actions_to_track ) );
        $results = $wpdb->get_results( $query, ARRAY_A );
        if ( !empty( $results ) ) {
            echo '<div class="action-counts"><h4>' . esc_html__( 'Action Counts', 'security-ninja' ) . '</h4><div class="action-counts-list">';
            $output = array();
            foreach ( $action_counts as $action => $count ) {
                if ( $count > 0 ) {
                    $output[] = '<span class="actiontype">' . esc_html( $actions_to_track[$action] ) . '  <strong>' . esc_html( number_format_i18n( $count ) ) . '</strong></span> ';
                }
            }
            echo wp_kses_post( implode( ' ', $output ) );
            echo '</div></div>';
            echo '<div class="recentandbtn"><div><h3>' . esc_html__( 'Recent Events', 'security-ninja' ) . '</h3></div><div><a href="#sn_logger" class="button snbtn alignright">' . esc_html__( 'View all events', 'security-ninja' ) . ' &rarr; </a></div></div>';
            $time_format = get_option( 'time_format' );
            echo '<div class="sn-events-list">';
            foreach ( $results as $row ) {
                $raw_data = maybe_unserialize( $row['raw_data'] );
                $details = array();
                if ( is_array( $raw_data ) && !is_null( $raw_data ) ) {
                    foreach ( $raw_data as $key => $value ) {
                        if ( is_wp_error( $value ) ) {
                            $display_value = $value->get_error_message();
                        } elseif ( is_object( $value ) ) {
                            $display_value = get_class( $value );
                        } else {
                            $display_value = $value;
                        }
                        $details[] = '<div><strong>' . esc_html( ucwords( str_replace( '_', ' ', $key ) ) ) . ':</strong> ' . esc_html( $display_value ) . '</div>';
                    }
                }
                $countryimg = '';
                echo '<div class="sn-event-row" id="sn-event-' . esc_attr( $row['id'] ) . '">';
                echo '<div class="sn-event-summary" onclick="this.parentElement.classList.toggle(\'expanded\')">';
                echo '<div class="sn-event-date">' . esc_html( date_i18n( get_option( 'date_format' ) . ' ' . $time_format, strtotime( $row['timestamp'] ) ) );
                echo '<div class="ipcountry">IP: ' . esc_html( $row['ip'] ) . wp_kses_post( $countryimg ) . '</div></div>';
                echo '<div class="sn-event-action">' . (( isset( $actions_to_track[$row['action']] ) ? esc_html( $actions_to_track[$row['action']] ) : esc_html( $row['action'] ) )) . '</div>';
                echo '<div class="sn-event-toggle"><span class="dashicons dashicons-arrow-down-alt2"></span></div></div>';
                echo '<div class="sn-event-details">' . wp_kses_post( implode( '', $details ) ) . '</div></div>';
            }
            echo '</div>';
        } else {
            echo '<p>' . esc_html__( 'Great, no firewall events found.', 'security-ninja' ) . '</p>';
        }
        ?>
		</div>
		<?php 
    }

    /**
     * Quick actions / security areas navigation.
     */
    private static function render_card_quick_actions() : void {
        $actions = Wf_Sn_Admin_Links::get_quick_actions();
        echo '<div class="sncard sncard-quick-actions">';
        echo '<h3><span class="dashicons dashicons-admin-links"></span> ' . esc_html__( 'Quick actions', 'security-ninja' ) . '</h3>';
        echo '<p class="description">' . esc_html__( 'Jump to setup, scanning, monitoring, and maintenance areas.', 'security-ninja' ) . '</p>';
        echo '<div class="sn-quick-actions-grid">';
        foreach ( $actions as $action ) {
            echo '<a class="button snbtn sn-quick-action" href="' . esc_url( $action['url'] ) . '">' . esc_html( $action['label'] ) . '</a>';
        }
        echo '</div></div>';
    }

    /**
     * Pro upsell card (free only).
     */
    private static function render_card_upgrade_pro() : void {
        $pricing_url = Utils::generate_sn_web_link( 'overview_upgrade', '/upgrade/' );
        $trial_url = Utils::generate_sn_web_link( 'overview_trial', '/upgrade/', array(
            'trial' => 'free',
        ) );
        ?>
		<div class="sncard upgradepro">
		<h3><?php 
        echo esc_html( 'Upgrade to WP Security Ninja Pro' );
        ?></h3>
		<div class="benefits-container">
		<div><strong><?php 
        echo esc_html( 'Peace of mind' );
        ?> </strong> - <?php 
        echo esc_html( 'Focus on your business. We handle the security.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Easy Install Wizard' );
        ?></strong> - <?php 
        echo esc_html( 'Install in minutes. No technical skills required.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Real-time firewall' );
        ?></strong> - <?php 
        echo esc_html( 'Blocks threats before they reach your site.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Proactive threat detection' );
        ?></strong> <?php 
        echo esc_html( 'Stays ahead of emerging vulnerabilities.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Blocks spam & bots' );
        ?></strong> - <?php 
        echo esc_html( 'Keeps your site clean and your visitors safe.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Login Protection' );
        ?></strong> - <?php 
        echo esc_html( 'Prevent brute force attacks. Rename login page and use 2FA.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'Malware Scanner' );
        ?></strong> - <?php 
        echo esc_html( 'Scan files for malicious code - warns you of any suspicious results.' );
        ?></div>
		<div><strong><?php 
        echo esc_html( 'White Label (25+ licenses)' );
        ?></strong> - <?php 
        echo esc_html( 'Put your own agency branding on the plugin.' );
        ?></div>
		</div>
		<div>
		<p style="text-align: center;">
		<a href="<?php 
        echo esc_url( $pricing_url );
        ?>" class="wf-sn-button button button-primary button-small" target="_blank" rel="noopener"><?php 
        echo esc_html( 'Upgrade now' );
        ?></a> <small> or try our <a href="<?php 
        echo esc_url( $trial_url );
        ?>" class="" target="_blank" rel="noopener">14 days FREE trial &raquo;</a></small></p>
		</div>
		</div>
		<?php 
    }

}
