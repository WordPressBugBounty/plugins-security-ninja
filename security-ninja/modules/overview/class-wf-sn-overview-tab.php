<?php

namespace WPSecurityNinja\Plugin;

if ( !function_exists( 'add_action' ) ) {
    die( 'Please don\'t open this file directly!' );
}
class WF_SN_Overview_Tab {
    /**
     * Renders the overview tab content
     *
     * @return void
     */
    public static function tab_overview() : void {
        ?>
    <div class="sn-overview-container">
    
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
            echo $scores['score'];
            ?>%</div>
      </div>
      <div id="secscorerowrow">
      <div class="inner" style="width:<?php 
            echo $scores['score'];
            ?>%;"></div>
      </div>
      <div id="secscore-details">
      <div class="secscore-passed"><span class="det-count"><?php 
            echo $scores['good'];
            ?></span><span class="det"><?php 
            echo esc_html__( 'Tests passed', 'security-ninja' );
            ?></span></div>
      <div class="secscore-warning"><span class="det-count"><?php 
            echo $scores['warning'];
            ?></span><span class="det"><?php 
            echo esc_html__( 'Warnings', 'security-ninja' );
            ?></span></div>
      <div class="secscore-failed"><span class="det-count"><?php 
            echo $scores['bad'];
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
  <div id="snvulns">
    
    <?php 
        if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Vu' ) && wf_sn_vu::$options['enable_vulns'] ) {
            // Get scan summary using the new function
            $scan_data = wf_sn_vu::get_scan_summary();
            $vuln_results = $scan_data['vulnerabilities'];
            $scan_summary = $scan_data['scan_summary'];
            $has_vulnerabilities = $scan_data['has_vulnerabilities'];
            if ( $has_vulnerabilities ) {
                $checklist = ['plugins', 'themes', 'wordpress'];
                $combined = [];
                foreach ( $checklist as $vulntype ) {
                    if ( isset( $vuln_results[$vulntype] ) ) {
                        foreach ( $vuln_results[$vulntype] as $data ) {
                            if ( $vulntype === 'wordpress' ) {
                                // WordPress vulnerabilities have different structure
                                $combined[] = [
                                    'name' => 'WordPress ' . ($data['CVE_ID'] ?? 'Vulnerability'),
                                    'ver'  => $wp_version ?? 'unknown',
                                    'type' => 'wordpress',
                                ];
                            } else {
                                $combined[] = [
                                    'name' => $data['name'],
                                    'ver'  => $data['installedVersion'],
                                    'type' => $vulntype,
                                ];
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
                        $icon_class = ( $vuln['type'] === 'plugins' ? 'dashicons-admin-plugins' : (( $vuln['type'] === 'themes' ? 'dashicons-admin-appearance' : (( $vuln['type'] === 'wordpress' ? 'dashicons-wordpress' : '' )) )) );
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
                // Show scan summary if available
                if ( $scan_summary ) {
                    echo '<p>' . sprintf(
                        esc_html__( 'Last scan: %1$s plugins, %2$s themes, WordPress %3$s checked.', 'security-ninja' ),
                        number_format_i18n( $scan_summary['plugins']['plugins_checked'] ?? 0 ),
                        number_format_i18n( $scan_summary['themes']['themes_checked'] ?? 0 ),
                        $scan_summary['wordpress']['current_version'] ?? 'unknown'
                    ) . '</p>';
                }
                echo '</div>';
            }
            ?>
      
      </div><!-- #snvulns -->
      <?php 
        } else {
            ?>
      
      <div class="sncard">
      <h3><span class="dashicons dashicons-shield-alt"></span><?php 
            echo esc_html__( 'Vulnerability Scan Results', 'security-ninja' ) . '</h3>';
            ?>
      <p><?php 
            echo esc_html__( 'Vulnerability tracking is not enabled.', 'security-ninja' ) . '</p>';
            echo '</div></div>';
        }
        // Check for plugin and theme updates
        $plugin_updates = get_plugin_updates();
        delete_site_transient( 'update_themes' );
        wp_update_themes();
        // Get available theme updates
        $theme_updates = get_site_transient( 'update_themes' );
        $plugin_count = count( $plugin_updates );
        $theme_count = 0;
        if ( !empty( $theme_updates->response ) ) {
            $theme_count = count( $theme_updates->response );
        }
        $total_updates = $plugin_count + $theme_count;
        if ( $total_updates > 0 ) {
            echo '<div class="sncard">';
            echo '<h3 class="warning"><span class="dashicons dashicons-warning"></span> ' . esc_html__( 'Available Updates', 'security-ninja' ) . '</h3>';
            $summary = '<span>' . sprintf( _n(
                '%d update available',
                '%d updates available',
                $total_updates,
                'security-ninja'
            ), $total_updates ) . '</span>';
            if ( $plugin_count > 0 ) {
                $summary .= ' ' . sprintf( _n(
                    '(%d plugin',
                    '(%d plugins',
                    $plugin_count,
                    'security-ninja'
                ), $plugin_count );
            }
            if ( $theme_count > 0 ) {
                if ( $plugin_count > 0 ) {
                    $summary .= ', ';
                } else {
                    $summary .= ' (';
                }
                $summary .= sprintf( _n(
                    '%d theme',
                    '%d themes',
                    $theme_count,
                    'security-ninja'
                ), $theme_count );
            }
            if ( $plugin_count > 0 || $theme_count > 0 ) {
                $summary .= ')';
            }
            echo '<p class="sn-updates-summary">' . wp_kses_post( $summary ) . '</p>';
            echo '<div class="sn-updates-link"><a href="' . esc_url( admin_url( 'update-core.php' ) ) . '" class="button snbtn alignright">' . esc_html__( 'Go to WordPress Updates', 'security-ninja' ) . ' &rarr; </a></div>';
            echo '</div>';
        }
        ?>
      
      <?php 
        // Define free user actions (available to all users)
        $free_actions_to_track = array(
            'wp_login'        => __( 'Successful login', 'security-ninja' ),
            'wp_login_failed' => __( 'Failed login attempt', 'security-ninja' ),
            'do_init_action'  => __( 'Blocked by firewall', 'security-ninja' ),
        );
        $actions_to_track = $free_actions_to_track;
        $show_pro_ad = true;
        // Show firewall summary for all users (free and premium)
        ?>
        <div class="sncard firewall-summary">
        <h3><span class="dashicons dashicons-warning"></span> <?php 
        echo esc_html__( 'Firewall Summary', 'security-ninja' );
        ?></h3>
        <?php 
        global $wpdb;
        // Prepare the table name
        $table_name = $wpdb->prefix . 'wf_sn_el';
        // Prepare placeholders for the query
        $placeholders = implode( ',', array_fill( 0, count( $actions_to_track ), '%s' ) );
        $action_counts = array_fill_keys( array_keys( $actions_to_track ), 0 );
        // Query to get the count of each action type
        $count_query = $wpdb->prepare( "SELECT action, COUNT(*) as count \n            FROM {$table_name} \n            WHERE action IN ({$placeholders}) \n            GROUP BY action", array_keys( $actions_to_track ) );
        $action_results = $wpdb->get_results( $count_query, ARRAY_A );
        // Populate the action_counts array with the results
        foreach ( $action_results as $action_result ) {
            $action_counts[$action_result['action']] = intval( $action_result['count'] );
        }
        // Fetch the last 10 events
        $query = $wpdb->prepare( "SELECT id, timestamp, ip, action, raw_data \n            FROM {$table_name} \n            WHERE action IN ({$placeholders}) AND raw_data != 'N;'\n            ORDER BY timestamp DESC \n            LIMIT 10", array_keys( $actions_to_track ) );
        $results = $wpdb->get_results( $query, ARRAY_A );
        if ( !empty( $results ) ) {
            // If we have results, don't show the upgrade ad
            $show_pro_ad = false;
            echo '<div class="action-counts">';
            echo '<h4>' . esc_html__( 'Action Counts', 'security-ninja' ) . '</h4>';
            echo '<div class="action-counts-list">';
            $output = array();
            foreach ( $action_counts as $action => $count ) {
                if ( $count > 0 ) {
                    $output[] = '<span class="actiontype">' . esc_html( $actions_to_track[$action] ) . '  <strong>' . esc_html( number_format_i18n( $count ) ) . '</strong></span> ';
                }
            }
            echo implode( ' ', $output );
            echo '</div>';
            echo '</div>';
            echo '<div class="recentandbtn"><div><h3>' . esc_html__( 'Recent Events', 'security-ninja' ) . '</h3></div><div><a href="#sn_logger" class="button snbtn alignright">' . esc_html__( 'View all events', 'security-ninja' ) . ' &rarr; </a></div></div>';
            $time_format = get_option( 'time_format' );
            echo '<div class="sn-events-list">';
            foreach ( $results as $row ) {
                $raw_data = maybe_unserialize( $row['raw_data'] );
                $event_id = 'sn-event-' . esc_attr( $row['id'] );
                $date = esc_html( date_i18n( get_option( 'date_format' ) . ' ' . $time_format, strtotime( $row['timestamp'] ) ) );
                // Safely get action label, fallback to action name if not found
                $action = ( isset( $actions_to_track[$row['action']] ) ? esc_html( $actions_to_track[$row['action']] ) : esc_html( $row['action'] ) );
                $ip = esc_html( $row['ip'] );
                // Prepare details
                $details = [];
                if ( is_array( $raw_data ) && !is_null( $raw_data ) ) {
                    foreach ( $raw_data as $key => $value ) {
                        $details[] = '<div><strong>' . esc_html( ucwords( str_replace( '_', ' ', $key ) ) ) . ':</strong> ' . esc_html( $value ) . '</div>';
                    }
                } else {
                    $details[] = '<div>' . esc_html( $row['raw_data'] ) . '</div>';
                }
                $countryimg = '';
                echo '<div class="sn-event-row" id="' . $event_id . '">';
                // Summary
                echo '<div class="sn-event-summary" onclick="this.parentElement.classList.toggle(\'expanded\')">';
                echo '<div class="sn-event-date">' . $date;
                echo '<div class="ipcountry">IP: ' . $ip . wp_kses_post( $countryimg ) . '</div>';
                echo '</div>';
                echo '<div class="sn-event-action">' . $action . '</div>';
                echo '<div class="sn-event-toggle"><span class="dashicons dashicons-arrow-down-alt2"></span></div>';
                echo '</div>';
                // Details (hidden by default)
                echo '<div class="sn-event-details">';
                echo implode( '', $details );
                echo '</div>';
                echo '</div>';
            }
            echo '</div>';
        } else {
            echo '<p>' . __( 'Great, no firewall events found.', 'security-ninja' ) . '</p>';
        }
        ?>
        </div>
        </div>
        <?php 
        if ( $show_pro_ad ) {
            ?>
        <div class="sncard upgradepro">
        <h3><?php 
            echo esc_html__( 'Upgrade to WP Security Ninja Pro', 'security-ninja' );
            ?></h3>
        <div class="benefits-container">
        
        <div><strong><?php 
            echo esc_html__( 'Peace of mind', 'security-ninja' );
            ?> </strong> - <?php 
            echo esc_html__( 'Focus on your business. We handle the security.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Easy Install Wizard', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Install in minutes. No technical skills required.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Real-time firewall', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Blocks threats before they reach your site.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Proactive threat detection', 'security-ninja' );
            ?></strong> <?php 
            echo esc_html__( 'Stays ahead of emerging vulnerabilities.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Blocks spam & bots', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Keeps your site clean and your visitors safe.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Login Protection', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Prevent brute force attacks. Rename login page and use 2FA.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'Malware Scanner', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Scan files for malicious code - warns you of any suspicious results.', 'security-ninja' );
            ?></div>
        
        <div><strong><?php 
            echo esc_html__( 'White Label (25+ licenses)', 'security-ninja' );
            ?></strong> - <?php 
            echo esc_html__( 'Put your own agency branding on the plugin.', 'security-ninja' );
            ?></div>
        </div>
        <?php 
            $url = 'https://wpsecurityninja.com/pricing/';
            $pricing_url = Utils::generate_sn_web_link( 'explore-pro', '/pricing/', array(
                'utm_source' => 'overview-tab',
            ) );
            $current_user = wp_get_current_user();
            $user_firstname = $current_user->first_name;
            $user_lastname = $current_user->last_name;
            if ( empty( $user_firstname ) ) {
                $user_firstname = $current_user->display_name;
            }
            if ( empty( $user_lastname ) ) {
                $user_lastname = '';
            }
            $trial_url = add_query_arg( array(
                'user_firstname' => $user_firstname,
                'user_lastname'  => $user_lastname,
                'trial'          => 'free',
                'utm_source'     => 'overview-tab',
            ), $url );
            ?>
        <p style="margin-top: 10px;text-align: center;">
        <a href="<?php 
            echo esc_url( $pricing_url );
            ?>" class="wf-sn-button button button-secondary" target="_blank"><?php 
            echo esc_html__( 'Explore WP Security Ninja Pro now!', 'security-ninja' );
            ?></a><br><small>or try our <a href="<?php 
            echo esc_url( $trial_url );
            ?>" class="" target="_blank">14 days FREE trial &raquo;</a></small>
        </p>
        
        </div>
        </div>
        <?php 
        }
        ?>
      
      
      <?php 
    }

}
