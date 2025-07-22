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
     * @version v10  Sunday, May 11th,2025 * @access  public static
     * @return  void
     */
    public static function init() {
        add_action( 'wp_dashboard_setup', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'add_dashboard_widgets') );
        add_action( 'wp_ajax_secnin_fetch_rss_feed', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'ajax_fetch_rss_feed') );
        add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'admin_enqueue_scripts') );
    }

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
            wp_enqueue_script(
                'security-ninja-dashboard',
                WF_SN_PLUGIN_URL . 'modules/dashboard-widget/js/min/sn-wp_dashboard-min.js',
                array('jquery'),
                filemtime( WF_SN_PLUGIN_DIR . 'modules/dashboard-widget/js/min/sn-wp_dashboard-min.js' ),
                true
            );
            $utm_source = 'security_ninja_free';
            wp_localize_script( 'security-ninja-dashboard', 'dashboardData', array(
                'headline'     => 'Latest from WPSecurityNinja.com',
                'blog_link'    => \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'dashboard', '/blog/' ),
                'utm_source'   => esc_attr( $utm_source ),
                'utm_medium'   => 'plugin',
                'utm_content'  => 'dashboard_widget',
                'utm_campaign' => esc_attr( 'security_ninja_v' . \WPSecurityNinja\Plugin\wf_sn::get_plugin_version() ),
                'nonce'        => wp_create_nonce( 'secnin_dashboard_rss_feed' ),
            ) );
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
        wp_add_dashboard_widget( 
            'wpsn_dashboard_widget',
            'WP Security Ninja',
            // Is not whitelabelled, so nevermind
            array(__NAMESPACE__ . '\\Wf_Sn_Dashboard_Widget', 'wpsn_dashboard_widget_render')
         );
    }

    /**
     * Renders dashboard widget
     *
     * @author  Lars Koudal
     * @since   v0.1
     * @version v1.0.0  Wednesday, January 13221 * @access  public static
     * @return  void
     */
    public static function wpsn_dashboard_widget_render() {
        // Check if whitelabel is active
        $is_whitelabel = false;
        echo '<div class="secnin-dashboard-widget">';
        // Show icon only if not whitelabeled
        if ( !$is_whitelabel && class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
            $icon_url = \WPSecurityNinja\Plugin\Utils::get_icon_svg( true, '000000' );
            echo '<img src="' . esc_url( $icon_url ) . '" class="secnin-widget-icon">';
        }
        // Updates Available (Moved up under firewall)
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
        // Always show updates status
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
        // Security Score (Compact - matching firewall style)
        $test_scores = \WPSecurityNinja\Plugin\wf_sn::return_test_scores();
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
							<br>
							<div class="secnin-score-breakdown">
								<span class="secnin-score-good">✓ <?php 
            echo intval( $test_scores['good'] );
            ?></span>
								<span class="secnin-score-warning">⚠ <?php 
            echo intval( $test_scores['warning'] );
            ?></span>
								<span class="secnin-score-bad">✗ <?php 
            echo intval( $test_scores['bad'] );
            ?></span>
								<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_tests' ) );
            ?>" class="secnin-card-link secnin-card-link--security">
								<?php 
            esc_html_e( 'Run Tests', 'security-ninja' );
            ?> →
							</a>
							</div>
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
        // Vulnerabilities (Compact)
        $vulns = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vulnerabilities();
        if ( $vulns ) {
            $total = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vuln_count();
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
						<a href="<?php 
            echo esc_url( admin_url( 'admin.php?page=wf-sn#sn_vuln' ) );
            ?>" class="secnin-card-link secnin-card-link--vulnerabilities">
							<?php 
            esc_html_e( 'View', 'security-ninja' );
            ?> →
						</a>
					</div>
				</div>
				<?php 
        }
        // RSS Feed Section (hidden by default, shown only if content available)
        ?>
			<div id="secnin-dashboard-feed" class="secnin-rss-feed"></div>
			<?php 
        echo '</div>';
        // Close secnin-dashboard-widget div
    }

    /**
     * AJAX handler for fetching and caching the RSS feed for the dashboard widget
     */
    public static function ajax_fetch_rss_feed() {
        // Check permissions and nonce if sent
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_success( array() );
        }
        if ( !isset( $_POST['nonce'] ) || !wp_verify_nonce( $_POST['nonce'], 'secnin_dashboard_rss_feed' ) ) {
            wp_send_json_success( array() );
        }
        $feed_url = 'https://secnin.b-cdn.net/feed/?limit=2';
        $limit = ( isset( $_POST['limit'] ) ? intval( $_POST['limit'] ) : 2 );
        $cache_key = 'secnin_dashboard_rss_cache';
        $cache_time = 3 * DAY_IN_SECONDS;
        // 3 days
        // Try to get cached data first
        $cached = get_transient( $cache_key );
        if ( $cached && is_array( $cached ) ) {
            wp_send_json_success( $cached );
        }
        // Try to fetch new data
        try {
            require_once ABSPATH . WPINC . '/feed.php';
            $rss = fetch_feed( $feed_url );
            if ( is_wp_error( $rss ) ) {
                wp_send_json_success( array() );
            }
            $maxitems = $rss->get_item_quantity( $limit );
            $rss_items = $rss->get_items( 0, $maxitems );
            $posts = array();
            foreach ( $rss_items as $item ) {
                $title = wp_strip_all_tags( $item->get_title() );
                $link = esc_url_raw( $item->get_link() );
                $posts[] = array(
                    'title' => $title,
                    'link'  => $link,
                );
            }
            // Cache the results
            set_transient( $cache_key, $posts, $cache_time );
            wp_send_json_success( $posts );
        } catch ( \Exception $e ) {
            // Log error to console only, return empty array
            wp_send_json_success( array() );
        }
    }

}
