<?php

/*
Plugin Name: Security Ninja
Plugin URI: https://wpsecurityninja.com/
Description: Check your site for security vulnerabilities and get precise suggestions for corrective actions on passwords, user accounts, file permissions, database security, version hiding, plugins, themes, security headers and other security aspects.
Author: WP Security Ninja
Version: 5.267
Author URI: https://wpsecurityninja.com/
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html
Text Domain: security-ninja
Domain Path: /languages

Copyright
2011-2019 Web Factory Ltd
2019-     Larsik Corp

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


This plugin uses the following 3rd party MIT licensed projects - Thank you for making other developer lives easier :-)

* Rename login module based on the WordPress Rename Login by Prathap Rathod.

* Country flags Copyright (c) 2017 Go Squared Ltd. http://www.gosquared.com/ - https://github.com/gosquared/flags. MIT license.

* PHP malware scanner - https://github.com/scr34m/php-malware-scanner
This plugin works on a modified version of the excellent PHP malware scanner.
*/
namespace WPSecurityNinja\Plugin;

use Error;
use wf_sn_cf;
use Wf_Sn_Cs;
use Wf_Sn_Wl;
use Utils;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
if ( function_exists( '\\WPSecurityNinja\\Plugin\\secnin_fs' ) ) {
    secnin_fs()->set_basename( false, __FILE__ );
} elseif ( !function_exists( '\\WPSecurityNinja\\Plugin\\secnin_fs' ) ) {
    // Create a helper function for easy SDK access.
    function secnin_fs() {
        global $secnin_fs;
        include_once __DIR__ . '/vendor/autoload.php';
        if ( !isset( $secnin_fs ) ) {
            // Activate multisite network integration.
            if ( !defined( 'WP_FS__PRODUCT_3690_MULTISITE' ) ) {
                define( 'WP_FS__PRODUCT_3690_MULTISITE', true );
            }
            $secnin_fs = fs_dynamic_init( array(
                'id'                  => '3690',
                'slug'                => 'security-ninja',
                'enable_anonymous'    => true,
                'type'                => 'plugin',
                'public_key'          => 'pk_f990ec18700a90c02db544f1aa986',
                'is_premium'          => false,
                'has_addons'          => true,
                'has_paid_plans'      => true,
                'trial'               => array(
                    'days'               => 14,
                    'is_require_payment' => false,
                ),
                'has_affiliation'     => false,
                'menu'                => ( is_multisite() ? array(
                    'support' => false,
                    'network' => false,
                ) : array(
                    'slug'       => 'wf-sn',
                    'first-path' => 'admin.php?page=wf-sn&welcome=1',
                    'support'    => false,
                    'network'    => false,
                ) ),
                'parallel_activation' => array(
                    'enabled'                  => true,
                    'premium_version_basename' => 'security-ninja-premium/security-ninja.php',
                ),
                'is_live'             => true,
            ) );
        }
        return $secnin_fs;
    }

    // Init Freemius.
    secnin_fs();
    // Signal that SDK was initiated.
    do_action( 'secnin_fs_loaded' );
    define( 'WF_SN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
    define( 'WF_SN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
    define( 'WF_SN_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
    define( 'WF_SN_BASE_FILE', __FILE__ );
    include_once WF_SN_PLUGIN_DIR . 'modules/overview/class-wf-sn-overview-tab.php';
    // Dashboard widget
    include_once WF_SN_PLUGIN_DIR . 'modules/dashboard-widget/class-wf-sn-dashboard-widget.php';
    \WPSecurityNinja\Plugin\Wf_Sn_Dashboard_Widget::init();
    // Vulnerabilities
    include_once WF_SN_PLUGIN_DIR . 'modules/vulnerabilities/class-wf-sn-vu.php';
    // Core Scanner
    include_once WF_SN_PLUGIN_DIR . 'modules/core-scanner/core-scanner.php';
    // File viewer
    include_once WF_SN_PLUGIN_DIR . 'modules/file-viewer/class-secnin-file-viewer.php';
    include_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-utils.php';
    include_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/cloud-firewall.php';
    include_once WF_SN_PLUGIN_DIR . 'includes/class-wf-sn-utils.php';
    include_once WF_SN_PLUGIN_DIR . 'includes/class-wf-sn-free-render.php';
    include_once WF_SN_PLUGIN_DIR . 'includes/class-wf-sn-crypto.php';
    include_once WF_SN_PLUGIN_DIR . 'modules/events-logger/events-logger.php';
    class Wf_Sn {
        /**
         * Plugin version
         *
         * @var integer
         */
        public static $version = null;

        public static $test_scores = null;

        /**
         * Plugin name
         *
         * @var string
         */
        public static $name = 'Security Ninja';

        /**
         * List of tests to skip
         *
         * @var array
         */
        public static $skip_tests = array();

        public static $options;

        /**
         * Load plugin text domain for translations
         *
         * @author  Lars Koudal
         * @since   v1.0.1
         * @version v1.0.0  Tuesday, November 11th, 2025.
         * @access  public static
         * @return  void
         */
        public static function load_textdomain() {
            load_plugin_textdomain( 'security-ninja', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
        }

        /**
         * Init the plugin
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, April 29th, 2021.
         * @access  public static
         * @return  void
         */
        public static function init() {
            self::$options = self::get_options();
            // loads persistent admin notices
            add_action( 'admin_init', array('PAnD', 'init') );
            // Load security tests
            include_once WF_SN_PLUGIN_DIR . 'class-wf-sn-tests.php';
            include_once WF_SN_PLUGIN_DIR . 'includes/class-wf-sn-utils.php';
            include_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-security-utils.php';
            // MainWP integration - run here to make sure it's loaded
            add_filter(
                'mainwp_child_extra_execution',
                array(__NAMESPACE__ . '\\Utils', 'do_filter_mainwp_child_extra_execution'),
                10,
                2
            );
            add_filter(
                'mainwp_site_sync_others_data',
                array(__NAMESPACE__ . '\\Utils', 'do_filter_mainwp_site_sync_others_data'),
                10,
                2
            );
            add_action( 'secnin_run_tests_event', array(__NAMESPACE__ . '\\Wf_Sn', 'do_event_run_tests') );
            // does the user have enough privilages to use the plugin?
            if ( current_user_can( 'activate_plugins' ) ) {
                // Adds extra permission to Freemius
                if ( function_exists( '\\WPSecurityNinja\\Plugin\\secnin_fs' ) ) {
                    secnin_fs()->add_filter( 'permission_list', array(__NAMESPACE__ . '\\Utils', 'add_freemius_extra_permission') );
                    secnin_fs()->add_filter(
                        'show_admin_notice',
                        array(__NAMESPACE__ . '\\Utils', 'do_filter_show_admin_notice'),
                        10,
                        2
                    );
                    secnin_fs()->add_filter( 'checkout/parameters', array(__NAMESPACE__ . '\\Utils', 'extra_modern_checkout_parameters') );
                    add_action( 'admin_init', array(__NAMESPACE__ . '\\Utils', 'secnin_fs_license_key_migration') );
                    secnin_fs()->add_filter( 'plugin_icon', array(__NAMESPACE__ . '\\Wf_Sn', 'secnin_fs_custom_icon') );
                }
                add_filter(
                    'sn_tabs',
                    array(__NAMESPACE__ . '\\Wf_Sn', 'return_tabs'),
                    PHP_INT_MAX,
                    1
                );
                add_action( 'admin_menu', array(__NAMESPACE__ . '\\Wf_Sn', 'admin_menu') );
                add_action(
                    'activated_plugin',
                    array(__NAMESPACE__ . '\\Wf_Sn', 'do_action_activated_plugin'),
                    10,
                    2
                );
                add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn', 'enqueue_scripts') );
                add_action( 'admin_init', array(__NAMESPACE__ . '\\Wf_Sn', 'register_settings') );
                add_action( 'admin_init', array(__NAMESPACE__ . '\\Wf_Sn', 'do_action_admin_init') );
                add_action( 'wp_ajax_sn_run_single_test', array(__NAMESPACE__ . '\\Wf_Sn', 'run_single_test') );
                add_action( 'wp_ajax_sn_get_single_test_details', array(__NAMESPACE__ . '\\Wf_Sn', 'get_single_test_details') );
                add_action( 'wp_ajax_sn_run_tests', array(__NAMESPACE__ . '\\Wf_Sn', 'run_tests') );
                add_action( 'wp_ajax_sn_reset_secret_url', array(__NAMESPACE__ . '\\Wf_Sn', 'reset_secret_url') );
                add_action( 'admin_notices', array(__NAMESPACE__ . '\\Utils', 'do_admin_notices') );
                add_action( 'wp_ajax_wf_sn_dismiss_review', array(__NAMESPACE__ . '\\Wf_Sn', 'wf_sn_dismiss_review') );
                add_action( 'admin_footer', array(__NAMESPACE__ . '\\Utils', 'admin_footer') );
                add_action( 'secnin_signup_to_newsletter', array(__NAMESPACE__ . '\\Utils', 'signup_to_newsletter') );
                add_filter( 'manage_users_columns', array(__NAMESPACE__ . '\\Utils', 'add_user_last_login_column') );
                add_filter(
                    'manage_users_custom_column',
                    array(__NAMESPACE__ . '\\Utils', 'return_last_login_column'),
                    10,
                    3
                );
            }
        }

        /**
         * do_event_run_tests.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, December 12th, 2023.
         * @version v1.0.1  Thursday, December 14th, 2023.
         * @access  public static
         * @return  void
         */
        public static function do_event_run_tests() {
            $security_tests = wf_sn_tests::return_security_tests();
            $resultssofar = get_option( 'security_tests_results', array() );
            $set_time_limit = set_time_limit( 200 );
            $resultssofar['last_run'] = time();
            foreach ( $security_tests as $test_name => $test ) {
                $class_with_namespace = __NAMESPACE__ . '\\Wf_Sn_Tests';
                if ( !method_exists( $class_with_namespace, $test_name ) ) {
                    continue;
                }
                // Call the method dynamically
                $response = $class_with_namespace::$test_name();
                if ( !is_array( $response ) || empty( $response ) ) {
                    continue;
                }
                // Setting appropriate message
                if ( 10 === intval( $response['status'] ) ) {
                    $return_message = sprintf( $test['msg_ok'], $response['msg'] ?? '' );
                } elseif ( 0 === intval( $response['status'] ) ) {
                    $return_message = sprintf( $test['msg_bad'], $response['msg'] ?? '' );
                } else {
                    $return_message = sprintf( $test['msg_warning'], $response['msg'] ?? '' );
                }
                // Updates the results
                $resultssofar['test'][$test_name] = array(
                    'title'  => $test['title'],
                    'status' => $response['status'],
                    'score'  => $test['score'],
                    'msg'    => $return_message,
                );
                $end_time = \WPSecurityNinja\Plugin\Utils::timerstart( 'run_test_' . esc_attr( $test_name ) );
                $testresult = array(
                    'testid'    => $test_name,
                    'timestamp' => current_time( 'mysql' ),
                    'title'     => $test['title'],
                    'status'    => $response['status'],
                    'score'     => $test['score'],
                    'runtime'   => $end_time,
                    'msg'       => $return_message,
                    'details'   => '',
                );
                self::update_test_score( $testresult );
                // Update the last test run
                $resultssofar['last_test_run'] = $test_name;
                update_option( 'security_tests_results', $resultssofar );
            }
        }

        /**
         * Redirects the user after plugin activation.
         *
         * @author  Unknown
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, February 22nd, 2022.
         * @version v1.0.1  Saturday, March 5th, 2022.
         * @access  public static
         * @global
         * @return  void
         */
        public static function do_action_admin_init() {
            // Check for secret URL reset success notice
            $reset_success_url = get_transient( 'sn_secret_url_reset_success' );
            if ( $reset_success_url ) {
                delete_transient( 'sn_secret_url_reset_success' );
                add_action( 'admin_notices', function () use($reset_success_url) {
                    echo '<div class="notice notice-success secnin-notice"><p>' . esc_html__( 'Secret access URL has been reset successfully.', 'security-ninja' ) . ' <strong>' . esc_html__( 'New URL:', 'security-ninja' ) . '</strong> <code>' . esc_url( $reset_success_url ) . '</code></p></div>';
                } );
            }
            $target_admin_url = 'admin.php?page=wf-sn';
            // Make sure it's the correct user
            if ( !wp_doing_ajax() && intval( get_option( 'secnin_activation_redirect', false ) ) === wp_get_current_user()->ID ) {
                // Make sure we don't redirect again after this one
                delete_option( 'secnin_activation_redirect' );
                wp_safe_redirect( admin_url( $target_admin_url ) );
                exit;
            }
        }

        /**
         * do_action_activated_plugin.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Saturday, March 6th, 2021.
         * @access  public static
         * @param   mixed $plugin
         * @param   mixed $network_wide
         * @return  void
         */
        public static function do_action_activated_plugin( $plugin, $network_wide ) {
            // Bail if activating from network or bulk sites.
            if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) {
                return;
            }
        }

        /**
         * Handle new site creation in multisite.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, December 7th, 2021.
         * @access  public static
         * @param   int $site_id The site ID.
         * @return  void
         */
        public static function handle_new_site( $site_id ) {
            if ( !is_multisite() ) {
                return;
            }
            switch_to_blog( $site_id );
            global $wpdb;
            include_once ABSPATH . 'wp-admin/includes/upgrade.php';
            $charset = $wpdb->get_charset_collate();
            \WPSecurityNinja\Plugin\Utils::create_tables_for_site( $charset );
            restore_current_blog();
        }

        /**
         * Custom logo URL for Freemius dialogue
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Wednesday, January 13th, 2021.
         * @access  public static
         * @return  mixed
         */
        public static function secnin_fs_custom_icon() {
            return __DIR__ . '/images/plugin-icon.png';
        }

        /**
         * Update dismissed notice
         *
         * @author  Lars Koudal
         * @author  Unknown
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, January 12th, 2021.
         * @version v1.0.1  Friday, September 8th, 2023.
         * @version v1.0.2  Thursday, November 30th, 2023.
         * @access  public static
         * @return  void
         */
        public static function wf_sn_dismiss_review() {
            check_ajax_referer( 'wf_sn_dismiss_pointer' );
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'message' => 'Error saving dismiss pointer.',
                ) );
                wp_die();
            }
            $review = get_option( 'wf_sn_review_notice' );
            if ( !$review ) {
                $review = array();
            }
            $review['time'] = time() + WEEK_IN_SECONDS * 4;
            $review['dismissed'] = true;
            if ( isset( $_POST['user_data'] ) ) {
                $review['signed_up'] = true;
            }
            update_option( 'wf_sn_review_notice', $review, false );
            die;
        }

        /**
         * Prepares the tabs for the plugin interface
         *
         * @author  Lars Koudal <me@larsik.com>
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Saturday, March 5th, 2022.
         * @version v1.0.1  Friday, November 17th, 2023.
         * @access  public static
         * @param   mixed $intabs Array of tabs for plugin to be processed
         * @return  mixed
         */
        public static function return_tabs( $intabs ) {
            $malware_tab = array(
                'id'       => 'sn_malware',
                'class'    => 'profeature',
                'label'    => esc_html__( 'Malware', 'security-ninja' ),
                'callback' => array(__NAMESPACE__ . '\\Free_Render', 'render_malware_page'),
            );
            $schedule_tab = array(
                'id'       => 'sn_schedule',
                'class'    => 'profeature',
                'label'    => esc_html__( 'Scheduler', 'security-ninja' ),
                'callback' => array(__NAMESPACE__ . '\\Free_Render', 'render_scheduled_scanner_page'),
            );
            $whitelabel_tab = array(
                'id'       => 'sn_whitelabel',
                'class'    => 'profeature',
                'label'    => esc_html__( 'White label', 'security-ninja' ),
                'callback' => array(__NAMESPACE__ . '\\Utils', 'render_whitelabel_page'),
            );
            $outtabs = $intabs;
            $outtabs[] = $schedule_tab;
            $outtabs[] = $malware_tab;
            $outtabs[] = $whitelabel_tab;
            return $outtabs;
        }

        /**
         * Checks if the current page is a part of this plugin.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Wednesday, January 13th, 2021.
         * @access  public static
         * @return  bool Returns true if the current page is a part of this plugin, otherwise false.
         */
        public static function is_plugin_page() {
            $current_screen = get_current_screen();
            if ( !$current_screen ) {
                return false;
            }
            // Get the current screen ID
            $current_id = $current_screen->id;
            // Extract the page part after the last underscore
            $page_part = substr( $current_id, strrpos( $current_id, '_' ) + 1 );
            // Define our plugin pages using just the page part
            $plugin_pages = [];
            $plugin_pages[] = 'wf-sn';
            $plugin_pages[] = 'wf-sn-visitor-log';
            $plugin_pages[] = 'wf-sn-tools';
            $plugin_pages[] = 'wf-sn-fixes';
            $plugin_pages[] = 'security-ninja-welcome';
            $plugin_pages[] = 'security-ninja-wizard';
            $plugin_pages[] = 'wf-sn-overview';
            $plugin_pages[] = 'wf-sn-firewall';
            $plugin_pages[] = 'wf-sn-scanner';
            $plugin_pages[] = 'wf-sn-events';
            $plugin_pages[] = 'wf-sn-settings';
            // Check if the page part matches any of our plugin pages
            return in_array( $page_part, $plugin_pages, true );
        }

        /**
         * Define footer scripts - WP-Pointer tour
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, April 29th, 2021.
         * @access  public static
         * @return  void
         */
        public static function admin_print_footer_scripts() {
            $show_pointer = true;
            $pointer_content = '<h3>Security Ninja v.' . \WPSecurityNinja\Plugin\Utils::get_plugin_version() . '</h3>';
            $pointer_content .= '<p>' . __( 'Thank you for installing Security Ninja &hearts;', 'security-ninja' ) . '</p>';
            $link_to_url = admin_url( 'admin.php?page=wf-sn' );
            $pointer_content .= '<p><a href="' . esc_url( $link_to_url ) . '" class="startsecnin alignright button button-primary">' . esc_html__( 'Get started', 'security-ninja' ) . '</a></p>';
            if ( $show_pointer ) {
                ?>
				<script type="text/javascript">
					jQuery(document).ready(function($) {
						var $menu_item = $('#toplevel_page_wf-sn');

						$menu_item.pointer({
							content: '<?php 
                echo wp_kses( $pointer_content, 'post' );
                ?>',
							position: {
								edge: 'left',
								align: 'center'
							},
							close: function() {
								$.post(ajaxurl, {
									pointer: 'secninja_tour_pointer',
									action: 'dismiss-wp-pointer'
								});
							}
						}).pointer('open');


						jQuery(document).on('click', '.startsecnin', function() {
							event.preventDefault(); // Prevent the default action of the <a> element

							// AJAX request to dismiss the pointer
							var dismissPointer = jQuery.post(ajaxurl, {
								pointer: 'secninja_tour_pointer',
								action: 'dismiss-wp-pointer'
							});

							// Wait for the AJAX request to complete
							dismissPointer.done(function(response) {
								// Close the pointer
								$menu_item.pointer('close');
								// Continue with any other actions, e.g., navigating to the link
								window.location.href = jQuery('.startsecnin').attr('href');
							});

							dismissPointer.fail(function(jqXHR, textStatus, errorThrown) {
								// Handle failure
							});
						});

					});
				</script>
			<?php 
            }
        }

        /**
         * Enqueue CSS and JS scripts on plugin's pages
         *
         * @author  Lars Koudal
         * @author  Unknown
         * @since   v0.0.1
         * @version v1.0.0  Wednesday, January 13th, 2021.
         * @version v1.0.1  Sunday, May 11th, 2025.
         * @access  public static
         * @param   mixed $hook
         * @return  void
         */
        public static function enqueue_scripts( $hook ) {
            if ( 'wp-admin/update.php' === $GLOBALS['pagenow'] ) {
                return;
            }
            wp_enqueue_script(
                'sn-global',
                WF_SN_PLUGIN_URL . 'js/min/sn-global-min.js',
                array('jquery'),
                filemtime( WF_SN_PLUGIN_DIR . 'js/min/sn-global-min.js' ),
                true
            );
            // Test if we should show pointer - introduced in version 5.118
            if ( current_user_can( 'manage_options' ) ) {
                // Check to see if user has already dismissed the pointer tour
                $dismissed = array_filter( explode( ',', (string) get_user_meta( get_current_user_id(), 'dismissed_wp_pointers', true ) ) );
                $do_tour = !in_array( 'secninja_tour_pointer', $dismissed, true );
                // If not, we are good to continue - We check if the plugin has been registered or user wants to be anon
                if ( $do_tour ) {
                    wp_enqueue_style( 'wp-pointer' );
                    wp_enqueue_script( 'wp-pointer' );
                    add_action( 'admin_print_footer_scripts', array(__NAMESPACE__ . '\\wf_sn', 'admin_print_footer_scripts') );
                }
            }
            if ( self::is_plugin_page() ) {
                wp_enqueue_script( 'jquery-ui-tabs' );
                wp_enqueue_script(
                    'sn-jquery-plugins',
                    WF_SN_PLUGIN_URL . 'js/min/sn-jquery-plugins-min.js',
                    array('jquery'),
                    filemtime( WF_SN_PLUGIN_DIR . 'js/min/sn-jquery-plugins-min.js' ),
                    true
                );
                wp_enqueue_style( 'wp-jquery-ui-dialog' );
                wp_enqueue_script( 'jquery-ui-dialog' );
                $is_registered = false;
                if ( secnin_fs()->is_registered() ) {
                    $is_registered = true;
                }
                $is_tracking_allowed = false;
                if ( secnin_fs()->is_tracking_allowed() ) {
                    $is_tracking_allowed = true;
                }
                if ( $is_registered && $is_tracking_allowed ) {
                    // Checks if user opted-in (or activated a license) and didn't opt out from tracking.
                    wp_enqueue_script(
                        'security-ninja-widget-sdk',
                        'https://securityninja.productlift.dev/widgets_sdk',
                        array(),
                        \WPSecurityNinja\Plugin\Utils::get_plugin_version(),
                        // Add version to prevent caching issues
                        true
                    );
                }
                // Parsing data to sn-common-min.js via $cp_sn_data
                wp_register_script(
                    'sn-js',
                    WF_SN_PLUGIN_URL . 'js/min/sn-common-min.js',
                    array('jquery', 'wp-i18n'),
                    filemtime( WF_SN_PLUGIN_DIR . 'js/min/sn-common-min.js' ),
                    true
                );
                wp_enqueue_script( 'sn-js' );
                $js_vars = array(
                    'sn_plugin_url'          => WF_SN_PLUGIN_URL,
                    'nonce_run_tests'        => wp_create_nonce( 'wf_sn_run_tests' ),
                    'nonce_refresh_update'   => wp_create_nonce( 'wf_sn_refresh_update' ),
                    'nonce_dismiss_pointer'  => wp_create_nonce( 'wf_sn_dismiss_pointer' ),
                    'nonce_reset_activation' => wp_create_nonce( 'wf_sn_reset_activation' ),
                    'nonce_latest_events'    => wp_create_nonce( 'wf_sn_latest_events' ),
                    'nonce_install_routines' => wp_create_nonce( 'wf-sn-install-routines' ),
                    'lc_version'             => \WPSecurityNinja\Plugin\Utils::get_plugin_version(),
                    'lc_site'                => get_home_url(),
                    'lc_ip'                  => $_SERVER['REMOTE_ADDR'],
                    'strings'                => array(
                        'reset_secret_url_confirm' => esc_html__( 'Are you sure you want to reset the secret access URL? The old link will no longer function.', 'security-ninja' ),
                        'resetting'                => esc_html__( 'Resetting...', 'security-ninja' ),
                        'resetting_message'        => esc_html__( 'Resetting secret access URL...', 'security-ninja' ),
                        'reset_button_text'        => esc_html__( 'Reset Secret Access URL', 'security-ninja' ),
                        'error_unknown'            => esc_html__( 'Unknown error occurred', 'security-ninja' ),
                        'error_failed'             => esc_html__( 'Failed to reset secret access URL. Please try again.', 'security-ninja' ),
                    ),
                );
                wp_localize_script( 'sn-js', 'wf_sn', $js_vars );
                wp_enqueue_style(
                    'sn-css',
                    WF_SN_PLUGIN_URL . 'css/min/sn-style.css',
                    array(),
                    filemtime( WF_SN_PLUGIN_DIR . 'css/min/sn-style.css' )
                );
                // Removing scripts and styles from other plugins we know mess up the interface
                wp_dequeue_style( 'uiStyleSheet' );
                wp_dequeue_style( 'wpcufpnAdmin' );
                wp_dequeue_style( 'unifStyleSheet' );
                wp_dequeue_style( 'wpcufpn_codemirror' );
                wp_dequeue_style( 'wpcufpn_codemirrorTheme' );
                wp_dequeue_style( 'collapse-admin-css' );
                wp_dequeue_style( 'jquery-ui-css' );
                wp_dequeue_style( 'tribe-common-admin' );
                wp_dequeue_style( 'file-manager__jquery-ui-css' );
                wp_dequeue_style( 'file-manager__jquery-ui-css-theme' );
                wp_dequeue_style( 'wpmegmaps-jqueryui' );
                wp_dequeue_style( 'facebook-plugin-css' );
                wp_dequeue_style( 'facebook-tip-plugin-css' );
                wp_dequeue_style( 'facebook-member-plugin-css' );
                wp_dequeue_style( 'kc-testimonial-admin' );
                wp_dequeue_style( 'jquery-ui-style' );
            }
        }

        /**
         * add entry to admin menu
         *
         * @author  Unknown
         * @since   v0.0.1
         * @version v1.0.0  Friday, February 5th, 2021.
         * @access  public static
         * @return  void
         */
        public static function admin_menu() {
            // Define menu constants
            $page_title = 'Security';
            $menu_title = 'Security Ninja';
            $capability = 'manage_options';
            $menu_slug = 'wf-sn';
            $icon_url = \WPSecurityNinja\Plugin\Utils::get_icon_svg( true );
            // Add notification count if needed
            $notification_count = false;
            if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Vu' ) ) {
                $vu_options = wf_sn_vu::get_options();
                if ( $vu_options['enable_admin_notification'] ) {
                    try {
                        $notification_count = Wf_Sn_Vu::return_vuln_count();
                    } catch ( \Exception $e ) {
                        $notification_count = false;
                    }
                }
            }
            // Register main menu only if it doesn't exist
            if ( !menu_page_url( $menu_slug, false ) ) {
                add_menu_page(
                    $page_title,
                    ( $notification_count ? sprintf( $menu_title . ' <span class="awaiting-mod">%d</span>', $notification_count ) : $menu_title ),
                    $capability,
                    $menu_slug,
                    array(__NAMESPACE__ . '\\wf_sn', 'main_page'),
                    $icon_url
                );
            }
        }

        /**
         * Add an error to the settings_error
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @param   mixed  $message
         * @param   string $type    Default: 'error'
         * @param   string $code    Default: 'wf_sn'
         * @return  void
         */
        public static function add_settings_error( $message, $type = 'error', $code = 'wf_sn' ) {
            global $wp_settings_errors;
            $new_wp_settings = $wp_settings_errors;
            $new_wp_settings[] = array(
                'setting' => 'wf_sn_options',
                'code'    => $code,
                'message' => $message,
                'type'    => $type,
            );
            set_transient( 'settings_errors', $new_wp_settings );
        }

        /**
         * return default options
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  mixed
         */
        public static function default_options() {
            $defaults = array(
                'license_key'                => '',
                'license_active'             => false,
                'license_expires'            => '',
                'license_type'               => '',
                'license_hide'               => false,
                'first_version'              => '',
                'first_install'              => '',
                'remove_settings_deactivate' => 0,
            );
            return $defaults;
        }

        /**
         * get plugin's options
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  mixed
         */
        public static function get_options() {
            if ( isset( self::$options ) && 0 < count( self::$options ) ) {
                return self::$options;
            }
            $options = get_option( 'wf_sn_options', array() );
            if ( isset( $options[0] ) ) {
                unset($options[0]);
            }
            if ( !is_array( $options ) ) {
                $options = array();
            }
            $options = array_merge( self::default_options(), $options );
            self::$options = $options;
            // her sætter vi globale options.
            return $options;
        }

        /**
         * all settings are saved in one option
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  void
         */
        public static function register_settings() {
            register_setting( 'wf_sn_options', 'wf_sn_options', array(__NAMESPACE__ . '\\wf_sn', 'sanitize_settings') );
            // we do not want to redirect everyone
            $redirect_user = false;
            if ( isset( $_POST['foo'], $_POST['_wpnonce'] ) && wp_verify_nonce( sanitize_key( $_POST['_wpnonce'] ), 'wf-sn-install-routines' ) ) {
                if ( !current_user_can( 'manage_options' ) ) {
                    wp_send_json_error( array(
                        'success' => false,
                        'message' => esc_html__( 'You do not have permission to do this.', 'security-ninja' ),
                    ) );
                }
                $redirect_user = true;
            }
            if ( $redirect_user ) {
                // Set to false per default, so isset check not needed.
                if ( !isset( $_POST['_wp_http_referer'] ) ) {
                    $_POST['_wp_http_referer'] = wp_login_url();
                }
                $url = sanitize_text_field( wp_unslash( $_POST['_wp_http_referer'] ) );
                wp_safe_redirect( urldecode( $url ) );
                exit;
            }
        }

        /**
         * Sanitize settings on save
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, January 12th, 2021.
         * @access  public static
         * @param   mixed $new_values
         * @return  void
         */
        public static function sanitize_settings( $new_values ) {
            // Get the raw options from database without merging with defaults
            $old_options = get_option( 'wf_sn_options', array() );
            // Only merge with defaults if the options are actually empty or corrupted
            if ( empty( $old_options ) || !is_array( $old_options ) ) {
                $old_options = self::default_options();
            }
            $old_options['remove_settings_deactivate'] = 0;
            if ( !is_array( $new_values ) ) {
                $arr = array();
                $arr[] = $new_values;
                $new_values = $arr;
            }
            foreach ( $new_values as $key => $value ) {
                $new_values[$key] = sanitize_text_field( $value );
            }
            return array_merge( $old_options, $new_values );
        }

        /**
         * whole options page
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  void
         */
        public static function main_page() {
            global $secnin_fs;
            // Display setting errors
            settings_errors();
            $tabs = array();
            $tabs[] = array(
                'id'       => 'sn_overview',
                'class'    => '',
                'label'    => __( 'Overview', 'security-ninja' ),
                'callback' => array(__NAMESPACE__ . '\\WF_SN_Overview_Tab', 'tab_overview'),
            );
            $tabs[] = array(
                'id'       => 'sn_tests',
                'class'    => '',
                'label'    => __( 'Tests', 'security-ninja' ),
                'callback' => array(__NAMESPACE__ . '\\wf_sn', 'tab_tests'),
            );
            $tabs = apply_filters( 'sn_tabs', $tabs );
            ?>
			<div class="wrap">
				<?php 
            \WPSecurityNinja\Plugin\Utils::show_topbar();
            ?>
				<div class="secnin_content_wrapper">
					<div class="secnin_content_cell" id="secnin_content_top">

						<?php 
            $show_welcome = isset( $_GET['welcome'] ) && '1' === sanitize_text_field( $_GET['welcome'] );
            if ( class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Wl' ) && \WPSecurityNinja\Plugin\Wf_Sn_Wl::is_active() ) {
                $show_welcome = false;
            }
            if ( $show_welcome ) {
                $docs_url = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'welcome_notice', '/docs/' );
                $help_url = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'welcome_notice', '/help/' );
                $getting_started = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'welcome_notice', '/get-started/' );
                ?>
							<div class="secnin-welcome-notice sncard">
								<h2>👋 <?php 
                esc_html_e( 'Awesome move! You have just added a powerful layer of protection to your WordPress site.', 'security-ninja' );
                ?></h2>
								<?php 
                $letsstart = true;
                if ( $letsstart ) {
                    ?>
									<div class="sncard">
										<p>Let's kick things off — run your first security test below to quickly scan for any vulnerabilities hiding in your setup.</p>
										<a href="#sn_tests" class="button-large button snbtn greenbtn"><span class="dashicons dashicons-shield-alt"></span> <?php 
                    esc_html_e( 'Run Security Tests', 'security-ninja' );
                    ?></a>
									</div>


								<?php 
                }
                ?>

								<?php 
                ?>

								<p>You're just a few clicks away from a safer, smarter website. Let's go!</p>
								<div class="closeme">X</div>
							</div>
						<?php 
            }
            do_action( 'secnin_signup_to_newsletter' );
            ?>

						<div class="nav-tab-wrapper" id="wf-sn-tabs">
							<?php 
            foreach ( $tabs as $tab ) {
                $extra = '';
                $class = 'nav-tab ' . $tab['class'];
                if ( 'sn_overview' === $tab['id'] ) {
                    $class .= ' nav-tab-active';
                }
                if ( !empty( $tab['label'] ) ) {
                    if ( isset( $tab['count'] ) ) {
                        $extra = ' <span class="warn-count">' . intval( $tab['count'] ) . '</span>';
                    }
                    echo '<a href="#' . esc_attr( $tab['id'] ) . '" class="' . esc_attr( $class ) . '" id="' . esc_attr( $tab['id'] ) . '-tab">' . esc_html( $tab['label'] ) . wp_kses( $extra, array(
                        'span' => array(
                            'class' => array(),
                        ),
                    ) ) . '</a>';
                }
            }
            ?>
						</div>
						<div id="sn_tabscont">
							<?php 
            foreach ( $tabs as $tab ) {
                if ( !empty( $tab['callback'] ) ) {
                    $class = 'wf-sn-tab';
                    if ( 'sn_overview' === $tab['id'] ) {
                        $class .= ' active';
                    }
                    echo '<div id="' . esc_attr( $tab['id'] ) . '" class="' . esc_attr( $class ) . '">';
                    call_user_func( $tab['callback'] );
                    echo '</div>';
                }
            }
            ?>
						</div>
						<?php 
            include_once 'includes/sidebar.php';
            ?>
					</div>
				</div>
			</div>

		<?php 
        }

        /**
         * returns the current score of the tests + output
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  mixed
         */
        public static function return_test_scores() {
            if ( !is_null( self::$test_scores ) ) {
                return self::$test_scores;
            }
            global $wpdb;
            $testsresults = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}wf_sn_tests LIMIT 100;", ARRAY_A );
            $bad = 0;
            $warning = 0;
            $good = 0;
            $score = 0;
            $total = 0;
            if ( $testsresults ) {
                foreach ( $testsresults as $test_details ) {
                    $total += $test_details['score'];
                    if ( 10 === intval( $test_details['status'] ) ) {
                        ++$good;
                        $score += $test_details['score'];
                    } elseif ( 0 === intval( $test_details['status'] ) ) {
                        ++$bad;
                    } else {
                        ++$warning;
                    }
                }
            }
            if ( $total > 0 && $score > 0 ) {
                $score = round( $score / $total * 100 );
            } else {
                $score = 0;
            }
            $response = array();
            $response['good'] = $good;
            $response['bad'] = $bad;
            $response['warning'] = $warning;
            $response['score'] = $score;
            // generate output
            $output = '';
            $output .= '<div id="counters">';
            $output .= '<span class="edge good"><span class="val">' . $good . '</span><i>' . __( 'Passed', 'security-ninja' ) . '</i></span>';
            $output .= '<span class="edge warning"><span class="val">' . $warning . '</span><i>' . __( 'Warnings', 'security-ninja' ) . '</i></span>';
            $output .= '<span class="edge bad"><span class="val">' . $bad . '</span><i>' . __( 'Failed', 'security-ninja' ) . '</i></span>';
            $output .= '<span class="edge score"><span class="val">' . $score . '%</span><i>' . __( 'Score', 'security-ninja' ) . '</i></span>';
            $output .= '</div>';
            $response['output'] = $output;
            self::$test_scores = $response;
            return $response;
        }

        /**
         * Gets test results from database
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  mixed
         */
        public static function get_test_results() {
            global $wpdb;
            $table_name = $wpdb->prefix . 'wf_sn_tests';
            $testsresults = $wpdb->get_results( 'SELECT * FROM ' . $wpdb->_real_escape( $table_name ), ARRAY_A );
            if ( !$testsresults ) {
                return false;
            }
            $response = array();
            foreach ( $testsresults as $tr ) {
                $response['test'][$tr['testid']] = $tr;
            }
            return $response;
        }

        /**
         * tab_tests.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Wednesday, February 3rd, 2021.
         * @access  public static
         * @return  void
         */
        public static function tab_tests() {
            $testsresults = self::get_test_results();
            ?>
			<div class="submit-test-container">
				<h2><span class="dashicons dashicons-list-view"></span>
					<?php 
            esc_html_e( 'Test your website security', 'security-ninja' );
            ?>
				</h2>
				<p class="description">
					<?php 
            esc_html_e( 'Run comprehensive security tests to identify potential vulnerabilities and strengthen your website\'s defenses', 'security-ninja' );
            ?>
				</p>
				<div class="testresults" id="testscores">
					<?php 
            $scores = self::return_test_scores();
            if ( isset( $scores['output'] ) ) {
                $allowed_html = array(
                    'div'  => array(
                        'id' => array(),
                    ),
                    'span' => array(
                        'class' => array(),
                    ),
                    'br'   => array(),
                    'i'    => array(),
                );
                echo wp_kses( $scores['output'], $allowed_html );
            }
            ?>
				</div>

				<?php 
            $tests = wf_sn_tests::return_security_tests();
            $out = '<div id="runtestsrow"><input type="submit" value="' . __( 'Run Tests', 'security-ninja' ) . '" id="run-selected-tests" class="button button-primary button-hero" name="Submit" />';
            $out .= '<span class="runtestsbn spinner"></span>';
            $out .= '<div id="secninja-tests-quickselect">';
            $out .= '<span>' . __( 'Quick Filter', 'security-ninja' ) . ':</span><ul><li><a href="#" id="sn-quickselect-all">' . __( 'All', 'security-ninja' ) . '</a></li><li><a href="#" id="sn-quickselect-failed">' . __( 'Failed', 'security-ninja' ) . '</a></li><li><a href="#"  id="sn-quickselect-warning">' . __( 'Warning', 'security-ninja' ) . '</a></li><li><a href="#" id="sn-quickselect-okay">' . __( 'Passed', 'security-ninja' ) . '</a></li><li><a href="#" id="sn-quickselect-untested">' . __( 'Untested', 'security-ninja' ) . '</a></li></ul>';
            $out .= '</div></div>';
            $out .= '<table class="wp-list-table widefat" cellspacing="0" id="security-ninja">';
            $out .= '<thead><tr>';
            $out .= '<td id="cb" class="manage-column column-cb check-column">';
            $out .= '<label class="screen-reader-text" for="cb-select-all-1">' . __( 'Select All', 'security-ninja' ) . '</label>';
            $out .= '<input id="cb-select-all-1" type="checkbox"></td>';
            $out .= '<th>' . __( 'Status', 'security-ninja' ) . '</th>';
            $out .= '<th class="column-primary">' . __( 'Security Test', 'security-ninja' ) . '</th>';
            $out .= '<th>' . __( 'Actions', 'security-ninja' );
            $out .= '</th>';
            $out .= '</tr></thead>';
            $out .= '<tbody>';
            if ( is_array( $tests ) ) {
                $stepid = 0;
                foreach ( $tests as $test_name => $details ) {
                    if ( 'ad_' === substr( $test_name, 0, 3 ) || '_' === $test_name[0] ) {
                        continue;
                    }
                    ++$stepid;
                    $outlabel = '';
                    // hvis vi har kørt testen før
                    if ( isset( $testsresults['test'][$test_name]['status'] ) ) {
                        $out .= '<tr class="wf-sn-test-row-status-' . $testsresults['test'][$test_name]['status'] . ' test test_' . $test_name . '">';
                        if ( 0 === intval( $testsresults['test'][$test_name]['status'] ) ) {
                            $outlabel = '<span class="teststatus fail">' . __( '✗', 'security-ninja' ) . '</span>';
                        } elseif ( 5 === intval( $testsresults['test'][$test_name]['status'] ) ) {
                            $outlabel = '<span class="teststatus warning">' . __( '-;', 'security-ninja' ) . '</span>';
                        } elseif ( 10 === intval( $testsresults['test'][$test_name]['status'] ) ) {
                            $outlabel = '<span class="teststatus pass">' . __( '✓', 'security-ninja' ) . '</span>';
                        }
                    } else {
                        // lars - kommenteret ud ellers kom der er et "d" med
                        $out .= '<tr class="wf-sn-test-row-status-null test test_' . $test_name . '">';
                        $outlabel = '<span class="teststatus untested">' . __( 'Untested', 'security-ninja' ) . '</span>';
                    }
                    $checkedoutput = checked( true, true, false );
                    if ( !isset( $options['run_tests'] ) ) {
                        $checkedoutput = checked( true, true, false );
                    } else {
                        $options = self::get_options();
                        if ( in_array( $test_name, $options['run_tests'], true ) ) {
                            $checkedoutput = checked( true, true, false );
                        } else {
                            $checkedoutput = checked( false, true, false );
                        }
                    }
                    $out .= '<th scope="row" class="check-column"><input id="cb-select-' . $stepid . '" type="checkbox" name="sntest[]" value="' . sanitize_key( $test_name ) . '" ' . $checkedoutput . '/></th>';
                    $out .= '<td scope="row" class="">' . $outlabel . '</td>';
                    $out .= '<td class="column-primary" data-colname="Test"><label for="cb-select-' . $stepid . '"><span class="wf-sn-test-title">' . $details['title'] . '</span></label></br>';
                    if ( isset( $testsresults['test'][$test_name]['msg'] ) ) {
                        // only add details if failed or warning
                        $outmessage = $testsresults['test'][$test_name]['msg'];
                        // Add the details if exists
                        if ( $testsresults['test'][$test_name]['details'] ) {
                            $outmessage .= ' ' . $testsresults['test'][$test_name]['details'];
                        }
                        $out .= '<span class="sn-result-details">' . $outmessage . '</span>';
                    } else {
                        // empty - can be filled via ajax response
                        $out .= '<span class="sn-result-details"></span>';
                    }
                    $out .= '<button type="button" class="toggle-row"> <span class="screen-reader-text">' . __( 'Show details', 'security-ninja' ) . '</span> </button>';
                    $testcssid = 'tdesc-test-id-' . $test_name;
                    $out .= '<div class="testdesc ' . esc_attr( $testcssid ) . '"></div>';
                    if ( class_exists( __NAMESPACE__ . '\\wf_sn_af_fix_' . $test_name ) && isset( $details['status'] ) && 10 !== $details['status'] ) {
                        $details_label = __( 'Details &amp; Fix', 'security-ninja' );
                    } else {
                        $details_label = __( 'Details', 'security-ninja' );
                    }
                    $out .= '<div class="testtimedetails ' . esc_attr( $test_name ) . '"><span class="spinner"></span><span class="lasttest"></span><span class="runtime"></span><span class="score"></span>';
                    $outstatus = '';
                    if ( isset( $testsresults['test'][$test_name]['status'] ) ) {
                        $outstatus = $testsresults['test'][$test_name]['status'];
                    }
                    $out .= '<div class="snautofix" data-test-id="' . esc_attr( $test_name ) . '" data-test-status="' . esc_attr( $outstatus ) . '"></div>';
                    $out .= '</div>';
                    $out .= '</td><td><div class="sn-details"><a data-test-id="' . esc_attr( $test_name ) . '" data-test-status="' . esc_attr( $outstatus ) . '" href="#' . esc_attr( $test_name ) . '" class="action">' . $details_label . '</a></div>';
                    $out .= '</td></tr>';
                }
            }
            $out .= '</tbody>';
            $out .= '<tfoot><tr>';
            $out .= '<th class="manage-column column-cb check-column"><label class="screen-reader-text" for="cb-select-all-2">' . __( 'Select All', 'security-ninja' ) . '</label><input id="cb-select-all-2" type="checkbox"></th>';
            $out .= '<th></th>';
            $out .= '<th class="column-primary">' . __( 'Security Test', 'security-ninja' ) . '</th><th>Actions</th>';
            $out .= '</tr></tfoot>';
            $out .= '</table>';
            $allowed_html = array_merge( wp_kses_allowed_html( 'post' ), array(
                'input' => array(
                    'type'    => array(),
                    'name'    => array(),
                    'id'      => array(),
                    'value'   => array(),
                    'checked' => array(),
                    'class'   => array(),
                ),
            ) );
            $out = apply_filters( 'sn_tests_table', $out, $tests );
            echo wp_kses( $out, $allowed_html );
            ?>
				<p>
					<?php 
            esc_html_e( 'Although these tests cover years of best practices in security, getting all test green does not guarantee your site will not get hacked. Likewise, having them all red does not mean you will get hacked.', 'security-ninja' );
            ?>
				</p>
				<p>
					<?php 
            esc_html_e( "Please read each test's detailed information to see if it represents a real security issue for your site.", 'security-ninja' );
            ?>
				</p>
			</div>
<?php 
        }

        /**
         * Returns all details about a test in JSON - used in AJAX
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Saturday, March 5th, 2022.
         * @access  public static
         * @return  void
         */
        public static function get_single_test_details() {
            if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
                check_ajax_referer( 'wf_sn_run_tests' );
            }
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'message' => __( 'Failed.', 'security-ninja' ),
                ) );
            }
            if ( isset( $_POST['testid'] ) ) {
                $testid = sanitize_key( $_POST['testid'] );
                if ( $testid !== $_POST['testid'] ) {
                    wp_send_json_error();
                }
                global $wpdb;
                $table_name = $wpdb->prefix . 'wf_sn_tests';
                $testdata = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}wf_sn_tests WHERE testid = %s", $testid ) );
                if ( $testdata ) {
                    wp_send_json_success( $testdata );
                } else {
                    wp_send_json_error();
                }
            } else {
                wp_send_json_error();
            }
            die;
        }

        /**
         * Runs single test via AJAX call
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @return  void
         */
        public static function run_single_test() {
            if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
                check_ajax_referer( 'wf_sn_run_tests' );
            }
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'message' => __( 'Error. Please contact support', 'security-ninja' ),
                ) );
            }
            if ( isset( $_POST['stepid'] ) ) {
                $stepid = intval( $_POST['stepid'] );
                // Validate and sanitize the testarr input
                $testarr = array();
                if ( isset( $_POST['testarr'] ) && is_array( $_POST['testarr'] ) ) {
                    // Only allow alphanumeric characters, underscores, and hyphens in test IDs
                    $testarr = array_filter( $_POST['testarr'], function ( $test_id ) {
                        return preg_match( '/^[a-zA-Z0-9_-]+$/', $test_id );
                    } );
                }
                if ( !isset( $testarr[$stepid] ) ) {
                    return false;
                }
                $response = false;
                $testid = sanitize_key( $testarr[$stepid] );
                if ( $testid ) {
                    \WPSecurityNinja\Plugin\Utils::timerstart( $testid );
                    $response = wf_sn_tests::$testid();
                }
                if ( $response ) {
                    $json_response = array();
                    if ( isset( $testarr[$stepid + 1] ) ) {
                        $json_response['nexttest'] = $stepid + 1;
                    } else {
                        $json_response['nexttest'] = -1;
                    }
                    $security_tests = wf_sn_tests::return_security_tests();
                    // allow overwriting with function response
                    if ( isset( $response['msg_bad'] ) ) {
                        $test['msg_bad'] = $response['msg_bad'];
                    }
                    if ( isset( $response['msg_ok'] ) ) {
                        $test['msg_ok'] = $response['msg_ok'];
                    }
                    if ( isset( $response['msg_warning'] ) ) {
                        $test['msg_warning'] = $response['msg_warning'];
                    }
                    if ( !isset( $response['msg'] ) ) {
                        $response['msg'] = '';
                    }
                    $json_response['msg'] = $response['msg'];
                    // Get the previous status from the database table
                    $previous_status = null;
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'wf_sn_tests';
                    $previous_test = $wpdb->get_row( $wpdb->prepare( "SELECT status FROM {$table_name} WHERE testid = %s", $testid ) );
                    if ( $previous_test ) {
                        $previous_status = $previous_test->status;
                    }
                    // Check if status changed - ensure both are integers for comparison
                    $previous_status_int = ( $previous_status !== null ? intval( $previous_status ) : null );
                    $new_status_int = intval( $response['status'] );
                    $status_changed = $previous_status_int !== $new_status_int;
                    // Determine change direction for highlighting
                    $change_direction = null;
                    if ( $status_changed && $previous_status_int !== null ) {
                        if ( $new_status_int === 10 && $previous_status_int < 10 ) {
                            $change_direction = 'improved';
                            // Went from fail/warning to pass
                        } elseif ( 10 === $previous_status_int && $new_status_int < 10 ) {
                            $change_direction = 'declined';
                            // Went from pass to fail/warning
                        } else {
                            $change_direction = 'changed';
                            // Other status changes
                        }
                    }
                    $json_response['status_changed'] = $status_changed;
                    $json_response['previous_status'] = $previous_status_int;
                    $json_response['new_status'] = $new_status_int;
                    $json_response['change_direction'] = $change_direction;
                    // Return the correct status icon HTML for the frontend
                    if ( 10 === $response['status'] ) {
                        $json_response['status_icon'] = '<span class="teststatus pass">' . __( '✓', 'security-ninja' ) . '</span>';
                    } elseif ( 0 === $response['status'] ) {
                        $json_response['status_icon'] = '<span class="teststatus fail">' . __( '✗', 'security-ninja' ) . '</span>';
                    } else {
                        $json_response['status_icon'] = '<span class="teststatus warning">' . __( '&#9888;', 'security-ninja' ) . '</span>';
                    }
                    // Keep the label for backward compatibility
                    if ( 10 === $response['status'] ) {
                        $json_response['label'] = '<span class="wf-sn-label sn-success">' . __( 'OK', 'security-ninja' ) . '</span>';
                    } elseif ( 0 === $response['status'] ) {
                        $json_response['label'] = '<span class="wf-sn-label sn-error">' . __( 'Fail', 'security-ninja' ) . '</span>';
                    } else {
                        $json_response['label'] = '<span class="wf-sn-label sn-warning">' . __( 'Warning', 'security-ninja' ) . '</span>';
                    }
                    $json_response['status'] = $response['status'];
                    $testscorearr = array(
                        'testid'    => $testid,
                        'timestamp' => current_time( 'mysql' ),
                        'title'     => $security_tests[$testid]['title'],
                        'status'    => $response['status'],
                        'score'     => $security_tests[$testid]['score'],
                        'msg'       => $json_response['msg'],
                    );
                    // A way to add details
                    if ( isset( $response['details'] ) ) {
                        $testscorearr['details'] = $response['details'];
                        $json_response['details'] = $response['details'];
                    }
                    $endtime = \WPSecurityNinja\Plugin\Utils::timerstop( $testid );
                    if ( $endtime ) {
                        $testscorearr['runtime'] = $endtime;
                    }
                    self::update_test_score( $testscorearr );
                    $scores = self::return_test_scores();
                    if ( $scores ) {
                        $json_response['scores'] = $scores;
                    }
                    wp_send_json_success( $json_response );
                } else {
                    wp_send_json_error( $testid );
                }
            }
            wp_send_json_error( '$stepid not set' );
            die;
        }

        /**
         * Reset Secret Access URL via AJAX
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Monday, January 13th, 2025.
         * @access  public static
         * @return  void
         */
        public static function reset_secret_url() {
            check_ajax_referer( 'wf-sn-install-routines' );
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'message' => esc_html__( 'You do not have sufficient permissions to perform this action.', 'security-ninja' ),
                ) );
            }
            // Check if firewall module is available
            if ( !class_exists( __NAMESPACE__ . '\\Wf_sn_cf' ) ) {
                wp_send_json_error( array(
                    'message' => esc_html__( 'Firewall module not available.', 'security-ninja' ),
                ) );
            }
            // Get firewall options
            $firewall_options = \WPSecurityNinja\Plugin\Wf_sn_cf::get_options();
            // Generate new secret access URL
            $firewall_options['unblock_url'] = md5( time() . wp_rand() );
            // Update the options
            update_option( 'wf_sn_cf', $firewall_options, false );
            // Log the event
            if ( class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_El_Modules' ) ) {
                \WPSecurityNinja\Plugin\Wf_Sn_El_Modules::log_event( 'security_ninja', 'secret_access_url_reset', 'Secret access URL was reset by user ID: ' . get_current_user_id() );
            }
            // Get the new URL for response
            $new_url = \WPSecurityNinja\Plugin\Wf_sn_cf::get_unblock_url();
            // Set a transient to show notice on page reload
            set_transient( 'sn_secret_url_reset_success', $new_url, 60 );
            wp_send_json_success( array(
                'message' => esc_html__( 'Secret access URL has been reset successfully.', 'security-ninja' ),
            ) );
        }

        /**
         * Runs the tests
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @access  public static
         * @param   boolean $return Default: false
         * @return  void
         */
        public static function run_tests( $return_response = false ) {
            if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
                // Attempt to verify the first nonce
                $nonce_verified = wp_verify_nonce( sanitize_text_field( $_REQUEST['_wpnonce'] ), 'wf_sn_run_tests' );
                // If the first nonce verification fails, try the second nonce
                if ( !$nonce_verified ) {
                    $nonce_verified = wp_verify_nonce( sanitize_text_field( $_REQUEST['_wpnonce'] ), 'secnin_scheduled_scanner' );
                }
                // If both nonce verifications fail, terminate the AJAX call
                if ( !$nonce_verified ) {
                    wp_die( 'Nonce verification failed.', 'Nonce Verification', array(
                        'response' => 403,
                    ) );
                }
            }
            if ( !current_user_can( 'manage_options' ) ) {
                wp_send_json_error( array(
                    'success' => false,
                    'message' => esc_html__( 'You do not have permission to do this.', 'security-ninja' ),
                ) );
            }
            $step = ( isset( $_POST['step'] ) ? absint( $_POST['step'] ) : 1 );
            if ( 1 === $step ) {
                \WPSecurityNinja\Plugin\Utils::timerstart( 'wf_sn_run_tests' );
            }
            if ( !$step ) {
                $step = 0;
            }
            ++$step;
            $json_response = array();
            if ( $step ) {
                $json_response['step'] = $step;
            }
            $security_tests = \WPSecurityNinja\Plugin\Wf_Sn_Tests::return_security_tests();
            if ( $security_tests ) {
                $totaltests = count( $security_tests );
                $json_response['totaltests'] = $totaltests;
            }
            $set_time_limit = set_time_limit( 200 );
            $loop_count = 1;
            $start_time = microtime( true );
            $test_description['last_run'] = time();
            if ( is_array( $security_tests ) ) {
                foreach ( $security_tests as $test_name => $test ) {
                    if ( '_' === $test_name[0] || in_array( $test_name, self::$skip_tests, true ) || 'ad_' === substr( $test_name, 0, 3 ) ) {
                        continue;
                    }
                    // If this is the one to be tested ...
                    if ( $step === $loop_count ) {
                        $response = wf_sn_tests::$test_name();
                        $json_response['last_test'] = $test['title'];
                        if ( isset( $response['status'] ) ) {
                            $json_response['last_status'] = $response['status'];
                        }
                        $json_response['last_score'] = $test['score'];
                        // allow overwriting with function response
                        if ( isset( $response['msg_bad'] ) ) {
                            $test['msg_bad'] = $response['msg_bad'];
                        }
                        if ( isset( $response['msg_ok'] ) ) {
                            $test['msg_ok'] = $response['msg_ok'];
                        }
                        if ( isset( $response['msg_warning'] ) ) {
                            $test['msg_warning'] = $response['msg_warning'];
                        }
                        if ( !isset( $response['msg'] ) ) {
                            $response['msg'] = '';
                        }
                        if ( 10 === intval( $response['status'] ) ) {
                            $json_response['last_msg'] = sprintf( $test['msg_ok'], $response['msg'] );
                        } elseif ( 0 === intval( $response['status'] ) ) {
                            $json_response['last_msg'] = sprintf( $test['msg_bad'], $response['msg'] );
                        } else {
                            $json_response['last_msg'] = sprintf( $test['msg_warning'], $response['msg'] );
                        }
                        // Updates the results
                        $resultssofar['test'][$test_name] = array(
                            'title'  => $test['title'],
                            'status' => $response['status'],
                            'score'  => $test['score'],
                            'msg'    => $json_response['last_msg'],
                        );
                        // A way to add details
                        if ( isset( $response['details'] ) ) {
                            $resultssofar['test'][$test_name]['details'] = $response['details'];
                        }
                        // No more tests - let us stop
                        if ( $step >= $totaltests ) {
                            $json_response['step'] = 'done';
                            $resultssofar['last_run'] = time();
                            $stoptime = \WPSecurityNinja\Plugin\Utils::timerstop( 'wf_sn_run_tests' );
                            if ( $stoptime ) {
                                $resultssofar['run_time'] = $stoptime;
                            }
                            do_action( 'security_ninja_done_testing', $test_description, $resultssofar['run_time'] );
                        }
                        update_option( 'wf_sn_results', $resultssofar, false );
                        wp_send_json_success( $json_response );
                    }
                    ++$loop_count;
                }
            }
            if ( $return_response ) {
                $resultssofar = get_option( 'wf_sn_results' );
                return $resultssofar;
            } else {
                wp_send_json_success( $json_response );
            }
        }

        /**
         * Runs all tests with multisite compatibility
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @version v1.0.1  Tuesday, June 11th, 2024.
         * @access  public static
         * @param   boolean $return_data Default: false
         * @return  void
         */
        public static function run_all_tests( $return_data = false ) {
            if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
                // Attempt to verify the first nonce.
                $nonce_verified = wp_verify_nonce( sanitize_text_field( $_REQUEST['nonce'] ), 'wf_sn_run_tests' );
                // If the first nonce verification fails, try the second nonce
                if ( !$nonce_verified ) {
                    $nonce = wp_unslash( $_REQUEST['nonce'] );
                    $nonce = sanitize_text_field( $nonce );
                    $nonce_verified = wp_verify_nonce( $nonce, 'secnin_scheduled_scanner' );
                }
                // If both nonce verifications fail, terminate the AJAX call.
                if ( !$nonce_verified ) {
                    wp_die( 'Nonce verification failed.', 'Nonce Verification', array(
                        'response' => 403,
                    ) );
                }
            }
            \WPSecurityNinja\Plugin\Utils::timerstart( 'wf_sn_run_all_tests' );
            $security_tests = wf_sn_tests::return_security_tests();
            $resultssofar = array();
            $set_time_limit = set_time_limit( 200 );
            $loop_count = 1;
            $resultssofar['last_run'] = time();
            // Add multisite context information
            if ( is_multisite() ) {
                $resultssofar['multisite'] = array(
                    'is_multisite'    => true,
                    'current_site_id' => get_current_blog_id(),
                    'is_main_site'    => is_main_site(),
                    'network_id'      => get_current_network_id(),
                );
            } else {
                $resultssofar['multisite'] = array(
                    'is_multisite' => false,
                );
            }
            if ( is_array( $security_tests ) ) {
                foreach ( $security_tests as $test_name => $test ) {
                    if ( '_' === $test_name[0] || in_array( $test_name, self::$skip_tests, true ) || 'ad_' === substr( $test_name, 0, 3 ) ) {
                        continue;
                    }
                    // Skip certain tests in multisite subsites if they're network-level concerns
                    if ( is_multisite() && !is_main_site() && self::should_skip_test_in_subsite( $test_name ) ) {
                        $resultssofar['test'][$test_name] = array(
                            'title'  => $test['title'],
                            'status' => 5,
                            'score'  => $test['score'],
                            'msg'    => __( 'This test is typically handled at the network level in multisite installations.', 'security-ninja' ),
                        );
                        ++$loop_count;
                        continue;
                    }
                    $response = wf_sn_tests::$test_name();
                    $json_response = array();
                    $json_response['last_test'] = $test['title'];
                    $json_response['last_status'] = $response['status'];
                    $json_response['last_score'] = $test['score'];
                    if ( !isset( $response['msg'] ) ) {
                        $response['msg'] = '';
                    }
                    // Setting appropriate message.
                    if ( 10 === intval( $response['status'] ) ) {
                        $json_response['last_msg'] = $response['msg'];
                    } elseif ( 0 === intval( $response['status'] ) ) {
                        $json_response['last_msg'] = $response['msg'];
                    } else {
                        $json_response['last_msg'] = $response['msg'];
                    }
                    // Updates the results
                    $resultssofar['test'][$test_name] = array(
                        'title'  => $test['title'],
                        'status' => $response['status'],
                        'score'  => $test['score'],
                        'msg'    => $json_response['last_msg'],
                    );
                    ++$loop_count;
                }
                // No more tests - let us stop
                $json_response['step'] = 'done';
                $resultssofar['last_run'] = time();
                $stoptime = \WPSecurityNinja\Plugin\Utils::timerstop( 'wf_sn_run_all_tests' );
                if ( $stoptime ) {
                    $resultssofar['run_time'] = $stoptime;
                }
                update_option( 'wf_sn_results', $resultssofar, false );
            }
            // her stopper det sjove?
            do_action( 'security_ninja_done_testing', __( 'Security Tests - Completed Scanning', 'security-ninja' ), $resultssofar['run_time'] );
            if ( $return_data ) {
                $resultssofar = get_option( 'wf_sn_results' );
                return $resultssofar;
            } else {
                wp_send_json_success( $json_response );
            }
        }

        /**
         * Determines if a test should be skipped in multisite subsites
         *
         * @author  Lars Koudal
         * @since   v1.0.1
         * @version v1.0.0  Tuesday, June 11th, 2024.
         * @access  private static
         * @param   string $test_name The name of the test
         * @return  boolean True if the test should be skipped
         */
        private static function should_skip_test_in_subsite( $test_name ) {
            // Tests that are typically network-level concerns in multisite
            $network_level_tests = array(
                'core_updates_check',
                'config_chmod',
                'config_location',
                'db_password_check',
                'salt_keys_check',
                'salt_keys_age_check',
                'register_globals_check',
                'safe_mode_check',
                'allow_url_include_check',
                'expose_php_check',
                'display_errors_check',
                'php_headers',
                'strict_transport_security',
                'referrer_policy',
                'feature_policy',
                'content_security_policy',
                'x_frame_options',
                'x_content_type_options'
            );
            return in_array( $test_name, $network_level_tests, true );
        }

        /**
         * Resets pointers on activation and saves some information.
         *
         * This method is responsible for resetting pointers and saving specific information during the plugin's activation process.
         * It checks if the plugin is being activated for the first time and sets the initial version and install time if so.
         * Additionally, it may create a database table for storing security test results and performs other activation routines.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Tuesday, December 7th, 2021.
         * @access  public static
         * @param   bool $network_wide Whether the plugin is being activated network-wide.
         * @return  void
         */
        public static function activate( $network_wide = false ) {
            $options = self::get_options();
            // Runs on first activation.
            global $wpdb;
            include_once ABSPATH . 'wp-admin/includes/upgrade.php';
            $charset = $wpdb->get_charset_collate();
            if ( $network_wide && is_multisite() ) {
                // Network activation - create tables for all sites
                $sites = get_sites( array(
                    'fields' => 'ids',
                ) );
                foreach ( $sites as $site_id ) {
                    switch_to_blog( $site_id );
                    \WPSecurityNinja\Plugin\Utils::create_tables_for_site( $charset );
                    // Ensure Events Logger is enabled by default on first activation
                    if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_El' ) ) {
                        \WPSecurityNinja\Plugin\Wf_Sn_El::default_settings( false );
                    }
                    restore_current_blog();
                }
            } elseif ( !$network_wide ) {
                // Single site activation (only when not network-wide)
                \WPSecurityNinja\Plugin\Utils::create_tables_for_site( $charset );
                // Ensure Events Logger is enabled by default on first activation
                if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_El' ) ) {
                    \WPSecurityNinja\Plugin\Wf_Sn_El::default_settings( false );
                }
            }
        }

        /**
         * Performs cleanup operations when the plugin is deactivated.
         *
         * This method checks if the option to remove settings on deactivation is set and if so, it should implement the removal functionality.
         * Currently, the removal functionality is not implemented and is marked as a todo.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Saturday, March 5th, 2022.
         * @access  public static
         * @return  void
         */
        public static function deactivate() {
            $centraloptions = self::get_options();
            if ( !isset( $centraloptions['remove_settings_deactivate'] ) || !$centraloptions['remove_settings_deactivate'] ) {
                return;
            }
            // @todo - implement remove functionality here
        }

        /**
         * Performs cleanup operations when the plugin is uninstalled.
         *
         * This method drops the security tests table, deletes various options and usermeta, and drops additional tables and options if the plugin is premium.
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Saturday, March 5th, 2022.
         * @access  public static
         * @return  void
         */
        public static function uninstall() {
            global $wpdb;
            // Drop security tests table
            if ( self::table_exists( $wpdb->prefix . 'wf_sn_tests' ) ) {
                $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wf_sn_tests' );
            }
            // Delete options
            delete_option( 'wf_sn_results' );
            delete_option( 'wf_sn_options' );
            delete_option( 'wfsn_freemius_state' );
            delete_option( 'wf_sn_active_plugins' );
            delete_option( 'wf_sn_review_notice' );
            delete_option( 'wf_sn_tests' );
            // Delete usermeta
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", 'sn_last_login' ) );
        }

        /**
         * Updates test score in database - multisite compatible
         *
         * @author  Lars Koudal
         * @since   v0.0.1
         * @version v1.0.0  Thursday, January 14th, 2021.
         * @version v1.0.1  Tuesday, June 11th, 2024.
         * @access  public static
         * @param   array $testresult Test result data
         * @return  boolean Success status
         */
        public static function update_test_score( $testresult ) {
            if ( !$testresult ) {
                return false;
            }
            global $wpdb;
            // Ensure we're using the correct database prefix for the current site
            $table_name = $wpdb->prefix . 'wf_sn_tests';
            if ( !isset( $testresult['details'] ) ) {
                $testresult['details'] = '';
            }
            // Ensure the table exists before attempting to insert/update
            if ( !self::table_exists( $table_name ) ) {
                // Create the table if it doesn't exist
                include_once ABSPATH . 'wp-admin/includes/upgrade.php';
                $charset = $wpdb->get_charset_collate();
                \WPSecurityNinja\Plugin\Utils::create_tables_for_site( $charset );
            }
            $result = $wpdb->replace( $table_name, $testresult, array(
                '%s',
                '%s',
                '%s',
                '%d',
                '%d',
                '%s',
                '%s'
            ) );
            return false !== $result;
        }

        /**
         * Checks if a database table exists
         *
         * @author  Lars Koudal
         * @since   v1.0.1
         * @version v1.0.0  Tuesday, June 11th, 2024.
         * @access  private static
         * @param   string $table_name The table name to check
         * @return  boolean True if the table exists
         */
        private static function table_exists( $table_name ) {
            global $wpdb;
            $result = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );
            return $result === $table_name;
        }

    }

}
register_activation_hook( __FILE__, array(__NAMESPACE__ . '\\WF_SN', 'activate') );
register_deactivation_hook( __FILE__, array(__NAMESPACE__ . '\\WF_SN', 'deactivate') );
register_uninstall_hook( __FILE__, array(__NAMESPACE__ . '\\WF_SN', 'uninstall') );
// Load translations on init hook with priority 1 (WordPress 6.7+ requirement)
// This ensures translations are loaded early in the init cycle, before any code uses them
add_action( 'init', array(__NAMESPACE__ . '\\WF_SN', 'load_textdomain'), 1 );
add_action( 'init', array(__NAMESPACE__ . '\\WF_SN', 'init') );
// Multisite hooks
if ( is_multisite() ) {
    add_action( 'wpmu_new_blog', array(__NAMESPACE__ . '\\WF_SN', 'handle_new_site') );
    add_action( 'wp_insert_site', array(__NAMESPACE__ . '\\WF_SN', 'handle_new_site') );
}