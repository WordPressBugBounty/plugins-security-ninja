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
            echo '<h3><span class="dashicons dashicons-saved"></span> ' . esc_html__( 'Your Security Test Results', 'security-ninja' ) . '</h3>';
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
        if ( wf_sn_vu::$options['enable_vulns'] ) {
            // Get the list of vulnerabilities
            $vuln_results = wf_sn_vu::return_vulnerabilities();
            if ( isset( $vuln_results['wordpress'] ) || isset( $vuln_results['plugins'] ) || isset( $vuln_results['themes'] ) ) {
                $checklist = ['plugins', 'themes'];
                $combined = [];
                foreach ( $checklist as $vulntype ) {
                    if ( isset( $vuln_results[$vulntype] ) ) {
                        foreach ( $vuln_results[$vulntype] as $data ) {
                            $combined[] = [
                                'name' => $data['name'],
                                'ver'  => $data['installedVersion'],
                                'type' => $vulntype,
                            ];
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
                        $icon_class = ( $vuln['type'] === 'plugins' ? 'dashicons-admin-plugins' : (( $vuln['type'] === 'themes' ? 'dashicons-admin-appearance' : '' )) );
                        echo '<li class="vuln-item"><span class="dashicons ' . esc_attr( $icon_class ) . '"></span><strong>' . esc_html( $vuln['name'] ) . '</strong>: ' . esc_html( $vuln['ver'] ) . '</li>';
                    }
                    echo '</ul>';
                    echo '<p>' . esc_html__( 'Total Vulnerabilities Found: ', 'security-ninja' ) . '<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>.';
                    echo ' <a href="#sn_vuln">' . esc_html__( 'Details', 'security-ninja' ) . '</a>.';
                    echo '</div>';
                }
            }
            if ( empty( $combined ) ) {
                echo '<div class="sncard">';
                echo '<h3><span class="dashicons dashicons-shield-alt"></span> ' . esc_html__( 'Vulnerability Scan Results', 'security-ninja' ) . '</h3>';
                echo '<div class="noerrorsfound"><h3>' . esc_html__( 'Great news!', 'security-ninja' ) . '</h3><p>' . esc_html__( 'No vulnerabilities found.', 'security-ninja' ) . '</p></div>';
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
        $show_pro_ad = true;
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
                'trial'          => 'paid',
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
            ?>" class="" target="_blank">30 days FREE trial &raquo;</a></small>
        </p>
        
        </div>
        </div>
        <?php 
        }
        ?>
      
      
      <?php 
    }

}
