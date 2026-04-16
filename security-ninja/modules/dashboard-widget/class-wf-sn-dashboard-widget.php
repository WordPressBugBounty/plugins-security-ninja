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
                WF_SN_PLUGIN_URL . 'modules/dashboard-widget/css/dashboard-widget.css',
                array(),
                filemtime( WF_SN_PLUGIN_DIR . 'modules/dashboard-widget/css/dashboard-widget.css' )
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
        // Render updates section
        self::render_updates_section();
        // Render security score section
        self::render_security_score_section();
        // Render AI Security Advisor section (when enabled)
        self::render_ai_advisor_section();
        // Render vulnerabilities section
        self::render_vulnerabilities_section();
        echo '</div>';
        // Close secnin-dashboard-widget div
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
            echo esc_html( number_format_i18n( $cached_updates['total_updates'] ) );
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
            $time_diff = human_time_diff( $test_results['last_run'], time() );
            $last_scan_time = sprintf( 
                /* translators: %s: human-readable time difference */
                __( '%s ago', 'security-ninja' ),
                $time_diff
             );
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
     * Render AI Security Advisor section.
     * Only shown when advisor is enabled and module is loaded.
     * Uses transient cache to avoid DB/registry lookups on every dashboard load.
     *
     * @return void
     */
    private static function render_ai_advisor_section() {
        if ( !apply_filters( 'wf_sn_ai_advisor_enabled', true ) ) {
            return;
        }
        if ( !class_exists( 'WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ) {
            return;
        }
        $cache_key = 'secnin_dashboard_ai_advisor';
        $cached = get_transient( $cache_key );
        if ( is_array( $cached ) && isset( $cached['state'] ) ) {
            $state = (int) $cached['state'];
            $last_reviewed = ( isset( $cached['last_reviewed'] ) ? $cached['last_reviewed'] : '' );
            $teaser = ( isset( $cached['teaser'] ) ? $cached['teaser'] : '' );
        } else {
            $available = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available();
            $configured = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
            $options = \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Page::get_options();
            $site_registered = !empty( $options['site_registered'] );
            $ready = $available && (is_array( $configured ) && count( $configured ) > 0 || $site_registered);
            $reports = ( $available ? \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Reports::get_reports( 1, 0, 'full_report' ) : array() );
            $has_reports = is_array( $reports ) && isset( $reports[0] );
            $state = 1;
            $last_reviewed = '';
            $teaser = '';
            if ( $ready || $has_reports ) {
                $state = 2;
                if ( is_array( $reports ) && isset( $reports[0] ) ) {
                    $report = $reports[0];
                    if ( !empty( $report['created'] ) ) {
                        $last_reviewed = human_time_diff( strtotime( $report['created'] ), time() );
                    }
                    $text = ( isset( $report['report_text'] ) ? $report['report_text'] : '' );
                    if ( is_string( $text ) && '' !== $text ) {
                        $decoded = json_decode( $text, true );
                        if ( is_array( $decoded ) ) {
                            if ( !empty( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ) {
                                $teaser = wp_trim_words( $decoded['executive_summary'], 20 );
                            } elseif ( !empty( $decoded['overview'] ) && is_string( $decoded['overview'] ) ) {
                                $teaser = wp_trim_words( $decoded['overview'], 20 );
                            }
                        }
                    }
                }
            } elseif ( $available ) {
                $state = 3;
            }
            set_transient( $cache_key, array(
                'state'         => $state,
                'last_reviewed' => $last_reviewed,
                'teaser'        => $teaser,
            ), 5 * MINUTE_IN_SECONDS );
        }
        $advisor_url = admin_url( 'admin.php?page=wf-sn-advisor' );
        ?>
		<div class="secnin-status-card secnin-status-card--advisor">
			<div class="secnin-card-content">
				<div>
					<span class="secnin-card-header secnin-card-header--advisor">
						<span class="dashicons dashicons-admin-generic" style="color: #6c757d;"></span>
						<?php 
        esc_html_e( 'Security Advisor', 'security-ninja' );
        ?>
						<span class="secnin-ai-badge">AI</span>
					</span>
					<div class="secnin-card-stats secnin-card-stats--advisor">
						<?php 
        if ( 1 === $state ) {
            esc_html_e( 'Coming with WordPress 7', 'security-ninja' );
        } elseif ( 2 === $state && $last_reviewed ) {
            echo esc_html( sprintf( 
                /* translators: %s: human-readable time since last review */
                __( 'Last reviewed %s ago', 'security-ninja' ),
                $last_reviewed
             ) );
        } elseif ( 2 === $state ) {
            esc_html_e( 'Ready for first review', 'security-ninja' );
        } else {
            esc_html_e( 'Set up for anonymized AI review', 'security-ninja' );
        }
        ?>
					</div>
					<?php 
        if ( 2 === $state && '' !== $teaser ) {
            ?>
						<div class="secnin-card-teaser"><?php 
            echo esc_html( $teaser );
            ?></div>
					<?php 
        }
        ?>
					<?php 
        if ( 2 === $state ) {
            ?>
						<p class="description secnin-advisor-hint" style="margin: 0.5em 0 0; font-size: 12px;"><?php 
            esc_html_e( 'Run Security Tests first, then generate for latest results.', 'security-ninja' );
            ?></p>
					<?php 
        }
        ?>
				</div>
				<div class="secnin-score-display">
					<?php 
        if ( 1 === $state ) {
            ?>
						<span class="secnin-update-count" style="color: #6c757d;">-</span>
					<?php 
        } else {
            ?>
						<a href="<?php 
            echo esc_url( $advisor_url );
            ?>" class="secnin-card-link secnin-card-link--advisor">
							<?php 
            if ( 2 === $state && $last_reviewed ) {
                esc_html_e( 'Security Advisor', 'security-ninja' );
            } elseif ( 2 === $state ) {
                esc_html_e( 'Run AI review', 'security-ninja' );
            } else {
                esc_html_e( 'Set up', 'security-ninja' );
            }
            ?>
							→
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
        echo esc_html( sprintf( 
            /* translators: %s: number of vulnerabilities (used for both singular and plural) */
            _n(
                '%s Vulnerability Found',
                '%s Vulnerabilities Found',
                $total,
                'security-ninja'
            ),
            number_format_i18n( $total )
         ) );
        ?>
				</span>
				<div class="secnin-score-display">
					<span class="secnin-update-count" style="color: #f39c12;"><?php 
        echo esc_html( number_format_i18n( $total ) );
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
