<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Dashboard Widget Module
 *
 * Handles the Security Ninja dashboard widget functionality
 * Only loads on dashboard page for efficiency
 *
 * @author  Lars Koudal
 * @since   v001
 * @version v10  Sunday, May 11th,2025
 */
class Wf_Sn_Dashboard_Widget {
    /**
     * Initialize the dashboard widget module
     *
     * @author  Lars Koudal
     * @since   v00.1
     * @version v10  Sunday, May 11th,2025
     * @access  public static
     * @return  void
     */
    public static function init() {
        add_action( 'wp_dashboard_setup', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'add_dashboard_widgets') );
        add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'admin_enqueue_scripts') );
        // Clear updates cache when updates are completed
        add_action(
            'upgrader_process_complete',
            array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'clear_updates_cache'),
            10,
            2
        );
        add_action( 'wp_update_themes', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'clear_updates_cache') );
        add_action( 'wp_update_plugins', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'clear_updates_cache') );
    }

    /**
     * Clear updates cache when updates are completed
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  public static
     * @return  void
     */
    public static function clear_updates_cache() {
        delete_transient( 'secnin_dashboard_updates' );
    }

    /**
     * Enqueue scripts and styles for dashboard
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  public static
     * @param   string $hook Current admin page hook.
     * @return  void
     */
    public static function admin_enqueue_scripts( $hook ) {
        if ( 'wp-admin/update.php' === $GLOBALS['pagenow'] ) {
            return;
        }
        if ( 'index.php' === $hook ) {
            // Enqueue CSS
            wp_enqueue_style(
                'security-ninja-dashboard-css',
                WF_SN_PLUGIN_URL . 'modules/dashboard-widget/css/min/dashboard-widget-min.css',
                array(),
                filemtime( WF_SN_PLUGIN_DIR . 'modules/dashboard-widget/css/min/dashboard-widget-min.css' )
            );
        }
    }

    /**
     * Add a widget to the dashboard.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, January 13th, 2021.
     * @access  public static
     * @return  void
     */
    public static function add_dashboard_widgets() {
        $widget_title = 'WP Security Ninja';
        wp_add_dashboard_widget( 'wpsn_dashboard_widget', $widget_title, array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'wpsn_dashboard_widget_render') );
    }

    /**
     * Renders dashboard widget
     *
     * @author  Lars Koudal
     * @since   v0.1
     * @version v1.0.0  Wednesday, January 13th, 2021.
     * @access  public static
     * @return  void
     */
    public static function wpsn_dashboard_widget_render() {
        // Check if whitelabel is active
        echo '<div class="secnin-dashboard-widget">';
        // Render firewall protection section
        self::render_firewall_section();
        // Render updates section
        self::render_updates_section();
        // Render security score section
        self::render_security_score_section();
        // Render vulnerabilities section
        self::render_vulnerabilities_section();
        echo '</div>';
        // Close secnin-dashboard-widget div
    }

    /**
     * Render firewall protection section
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  private static
     * @return  void
     */
    private static function render_firewall_section() {
        return;
        $cache_key = 'secnin_dashboard_firewall_stats';
        $cached_stats = get_transient( $cache_key );
        if ( false === $cached_stats ) {
            $cached_stats = self::get_firewall_stats();
            set_transient( $cache_key, $cached_stats, 5 * MINUTE_IN_SECONDS );
        }
        ?>
		<div class="secnin-status-card secnin-status-card--firewall">
			<div class="secnin-card-content">
				<div>
					<span class="secnin-card-header secnin-card-header--firewall">
						<span class="dashicons dashicons-shield" style="color: #28a745;"></span> 
						<?php 
        esc_html_e( 'Firewall Protection', 'security-ninja' );
        ?>
					</span>
					<?php 
        if ( $cached_stats['has_activity'] ) {
            ?>
						<div class="secnin-card-stats secnin-card-stats--firewall">
							<span><?php 
            esc_html_e( 'Last 24h: ', 'security-ninja' );
            ?> <strong><?php 
            echo number_format_i18n( $cached_stats['total_events'] );
            ?></strong></span>
						</div>
					<?php 
        } else {
            ?>
						<div class="secnin-card-stats secnin-card-stats--firewall">
							<span>✓ <?php 
            esc_html_e( 'No threats detected', 'security-ninja' );
            ?></span>
						</div>
					<?php 
        }
        ?>
				</div>
				<div class="secnin-score-display">
					<?php 
        if ( $cached_stats['has_activity'] ) {
            ?>
						<?php 
            if ( $cached_stats['blocked_count'] > 0 ) {
                ?>
							<span class="secnin-update-count"><?php 
                echo number_format_i18n( $cached_stats['blocked_count'] );
                ?></span>
							<br>
						<?php 
            }
            ?>
						<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_logger' ) );
            ?>" class="secnin-card-link secnin-card-link--firewall">
							<?php 
            esc_html_e( 'View details', 'security-ninja' );
            ?> →
						</a>
					<?php 
        } else {
            ?>
						<span class="secnin-update-count" style="color: #28a745;">✓</span>
						<br>
						<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_logger' ) );
            ?>" class="secnin-card-link secnin-card-link--firewall">
							<?php 
            esc_html_e( 'View logs', 'security-ninja' );
            ?> →
						</a>
					<?php 
        }
        ?>
				</div>
			</div>
		</div>
		<?php 
    }

    /**
     * Get firewall statistics
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  private static
     * @return  array
     */
    private static function get_firewall_stats() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wf_sn_el';
        // Check if table exists first
        $table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table_name ) );
        if ( $table_exists ) {
            // Get recent security events (last 24h) with more attack types
            $recent_events = $wpdb->get_results( $wpdb->prepare(
                "SELECT action, COUNT(*) as count \n\t\t\t\t\t\tFROM `{$table_name}` \n\t\t\t\t\t\tWHERE `action` IN (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) \n\t\t\t\t\t\tAND `module` = %s \n\t\t\t\t\t\tAND `timestamp` >= DATE_SUB(NOW(), INTERVAL 24 HOUR)\n\t\t\t\t\t\tGROUP BY action\n\t\t\t\t\t\tLIMIT 1000",
                'blocked_ip',
                'blocked_ip_banned',
                'banned_ip',
                'blacklisted_IP',
                'blocked_ip_suspicious_request',
                'failed_login',
                'login_denied_banned_ip',
                'login_form_blocked_ip',
                'blockadminlogin',
                'login_error',
                'blocked_ip_country_ban',
                'firewall_ip_banned',
                'security_ninja'
            ) );
            $total_events = 0;
            foreach ( $recent_events as $event ) {
                $total_events += $event->count;
            }
            $blocked_count = get_option( 'wf_sn_cf_blocked_count' );
            return array(
                'total_events'  => $total_events,
                'blocked_count' => $blocked_count,
                'has_activity'  => $total_events > 0 || $blocked_count > 0,
                'table_exists'  => true,
            );
        }
        return array(
            'total_events'  => 0,
            'blocked_count' => 0,
            'has_activity'  => false,
            'table_exists'  => false,
        );
    }

    /**
     * Render updates section
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  private static
     * @return  void
     */
    private static function render_updates_section() {
        $updates_cache_key = 'secnin_dashboard_updates';
        $cached_updates = get_transient( $updates_cache_key );
        if ( false === $cached_updates ) {
            $plugin_updates = get_plugin_updates();
            $theme_updates = get_site_transient( 'update_themes' );
            $plugin_count = count( $plugin_updates );
            $theme_count = ( !empty( $theme_updates->response ) ? count( $theme_updates->response ) : 0 );
            $total_updates = $plugin_count + $theme_count;
            $cached_updates = array(
                'total_updates' => $total_updates,
                'plugin_count'  => $plugin_count,
                'theme_count'   => $theme_count,
            );
            // Cache for 10 minutes
            set_transient( $updates_cache_key, $cached_updates, 10 * MINUTE_IN_SECONDS );
        }
        ?>
		<div class="secnin-status-card secnin-status-card--updates">
			<div class="secnin-card-content">
				<span class="secnin-card-header secnin-card-header--updates">
					<?php 
        if ( $cached_updates['total_updates'] > 0 ) {
            ?>
						<span class="dashicons dashicons-update" style="color: #17a2b8;"></span> 
						<?php 
            esc_html_e( 'Updates Available', 'security-ninja' );
            ?>
					<?php 
        } else {
            ?>
						<span class="dashicons dashicons-yes-alt" style="color: #28a745;"></span> 
						<?php 
            esc_html_e( 'All Updates Applied', 'security-ninja' );
            ?>
					<?php 
        }
        ?>
				</span>
				<div class="secnin-score-display">
					<?php 
        if ( $cached_updates['total_updates'] > 0 ) {
            ?>
						<span class="secnin-update-count"><?php 
            echo number_format_i18n( $cached_updates['total_updates'] );
            ?></span>
						<br>
						<a href="<?php 
            echo esc_url( admin_url( 'update-core.php' ) );
            ?>" class="secnin-card-link secnin-card-link--updates">
							<?php 
            esc_html_e( 'Update', 'security-ninja' );
            ?> →
						</a>
					<?php 
        } else {
            ?>
						<span class="secnin-update-count" style="color: #28a745;">✓</span>
						<br>
						<a href="<?php 
            echo esc_url( admin_url( 'update-core.php' ) );
            ?>" class="secnin-card-link secnin-card-link--updates">
							<?php 
            esc_html_e( 'Check Updates', 'security-ninja' );
            ?> →
						</a>
					<?php 
        }
        ?>
				</div>
			</div>
		</div>
		<?php 
    }

    /**
     * Render security score section
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  private static
     * @return  void
     */
    private static function render_security_score_section() {
        $test_scores = \WPSecurityNinja\Plugin\wf_sn::return_test_scores();
        $last_scan_time = '';
        // Get last scan time from existing results
        $test_results = get_option( 'wf_sn_results' );
        if ( $test_results && isset( $test_results['last_run'] ) ) {
            $time_diff = human_time_diff( $test_results['last_run'], current_time( 'timestamp' ) );
            $last_scan_time = sprintf( __( '%s ago', 'security-ninja' ), $time_diff );
        }
        ?>
		<div class="secnin-status-card secnin-status-card--security">
			<div class="secnin-card-content">
				<span class="secnin-card-header secnin-card-header--security">
					<span class="dashicons dashicons-shield-alt" style="color: #6c757d;"></span> 
					<?php 
        esc_html_e( 'Security Score', 'security-ninja' );
        ?>
				</span>
				<div class="secnin-score-display">
					<?php 
        if ( isset( $test_scores['score'] ) && '0' !== $test_scores['score'] ) {
            ?>
						<span class="secnin-score-value"><?php 
            echo intval( $test_scores['score'] );
            ?>%</span>
						<?php 
            if ( $last_scan_time ) {
                ?>
							<br>
							<span class="secnin-last-scan"><?php 
                echo esc_html( $last_scan_time );
                ?></span>
						<?php 
            }
            ?>
						<br>
						<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_tests' ) );
            ?>" class="secnin-card-link secnin-card-link--security">
							<?php 
            esc_html_e( 'Run Tests', 'security-ninja' );
            ?> →
						</a>
					<?php 
        } else {
            ?>
						<span class="secnin-score-value" style="color: #6c757d;">-</span>
						<br>
						<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn' ) );
            ?>" class="secnin-card-link secnin-card-link--security">
							<?php 
            esc_html_e( 'Run Tests', 'security-ninja' );
            ?> →
						</a>
					<?php 
        }
        ?>
				</div>
			</div>
		</div>
		<?php 
    }

    /**
     * Render vulnerabilities section
     *
     * @author  Lars Koudal
     * @since   v10
     * @version v10  Sunday, May 11th,2025
     * @access  private static
     * @return  void
     */
    private static function render_vulnerabilities_section() {
        try {
            $vulns = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vulnerabilities();
            $total = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vuln_count();
        } catch ( \Exception $e ) {
            return;
        }
        if ( !$vulns ) {
            return;
        }
        ?>
		<div class="secnin-status-card secnin-status-card--vulnerabilities">
			<div class="secnin-card-content">
				<span class="secnin-card-header secnin-card-header--vulnerabilities">
					<span class="dashicons dashicons-warning" style="color: #f39c12;"></span> 
					<?php 
        echo esc_html( sprintf( _n(
            '%s Vulnerability Found',
            '%s Vulnerabilities Found',
            $total,
            'security-ninja'
        ), number_format_i18n( $total ) ) );
        ?>
				</span>
				<div class="secnin-score-display">
					<span class="secnin-update-count" style="color: #f39c12;"><?php 
        echo number_format_i18n( $total );
        ?></span>
					<br>
					<a href="<?php 
        echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_vuln' ) );
        ?>" class="secnin-card-link secnin-card-link--vulnerabilities">
						<?php 
        esc_html_e( 'View', 'security-ninja' );
        ?> →
					</a>
				</div>
			</div>
		</div>
		<?php 
    }

}
