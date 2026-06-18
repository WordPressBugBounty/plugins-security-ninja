<?php

namespace WPSecurityNinja\Plugin;

use WPSecurityNinja\Plugin\Wf_Sn;
use WPSecurityNinja\Plugin\Wf_sn_cf;
use WPSecurityNinja\Plugin\Wf_Sn_El;
use WPSecurityNinja\Plugin\Utils;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Wizard class for Security Ninja plugin.
 *
 * This class handles the setup wizard functionality for the Security Ninja plugin.
 * It's based on the Whizzie package but has been heavily customized.
 *
 * @package WPSecurityNinja\Plugin
 * @since   0.0.1
 * @version 1.0.0
 */
class Wf_Sn_Wiz {
    /**
     * The version of the wizard.
     *
     * @var string
     */
    protected static $version = '1.3.0';

    /**
     * The slug for the wizard page.
     *
     * @var string
     */
    protected static $page_slug = 'security-ninja-wizard';

    /**
     * The title for the wizard page.
     *
     * @var string
     */
    protected static $page_title = 'Security Ninja Wizard';

    /**
     * An array of wizard steps set by the user.
     *
     * @var array
     */
    protected static $config_steps = array();

    /**
     * The relative plugin URL for this plugin folder.
     *
     * @var string
     */
    protected static $plugin_url = '';

    /**
     * Check if a string ends with a given substring.
     *
     * @since  0.0.1
     * @access public static
     * @param  string $haystack The string to search in.
     * @param  string $needle   The substring to search for.
     * @return bool             True if the string ends with the substring, false otherwise.
     */
    public static function str_ends_with( $haystack, $needle ) {
        if ( '' === $haystack && '' !== $needle ) {
            return false;
        }
        $len = strlen( $needle );
        return 0 === substr_compare(
            $haystack,
            $needle,
            -$len,
            $len
        );
    }

    /**
     * Initialize hooks and filters for the wizard.
     *
     * This method sets up the necessary WordPress hooks and filters
     * to handle AJAX actions and enqueue scripts for the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function init() {
        add_action( 'wp_ajax_secnin_activate_firewall', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_firewall') );
        add_action( 'wp_ajax_secnin_activate_events', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_events') );
        add_action( 'wp_ajax_secnin_activate_vulnerabilities', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_vulnerabilities') );
        add_action( 'wp_ajax_secnin_activate_login_protection', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_login_protection') );
        add_action( 'wp_ajax_secnin_activate_default_fixes', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_default_fixes') );
        add_action( 'wp_ajax_secnin_activate_woocommerce', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'activate_woocommerce') );
        add_action( 'wp_ajax_secnin_wizard_all_done', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'all_done') );
        add_action( 'admin_enqueue_scripts', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'enqueue_scripts') );
    }

    /**
     * Plugin name shown in wizard headings (whitelabel when premium).
     *
     * @return string
     */
    private static function get_plugin_display_name() {
        $plugin_name = 'Security Ninja';
        return $plugin_name;
    }

    /**
     * Whether the setup wizard has been completed at least once.
     *
     * @return bool
     */
    public static function is_wizard_completed() {
        $options = Wf_Sn::get_options();
        return !empty( $options['wizard_completed_at'] ) && is_numeric( $options['wizard_completed_at'] );
    }

    /**
     * Whether the wizard has been completed before (rerun).
     *
     * @return bool
     */
    public static function is_wizard_rerun() {
        return self::is_wizard_completed();
    }

    /**
     * Prominent warning when rerunning the wizard.
     *
     * @return string
     */
    private static function get_rerun_warning_markup() {
        $markup = '<div class="notice notice-warning secnin-wizard-rerun-warning"><p><strong>' . esc_html__( 'You have run this wizard before.', 'security-ninja' ) . '</strong></p>';
        $markup .= '<p>' . esc_html__( 'Clicking Activate on any step replaces your saved settings for that module with the wizard defaults. Use Skip or Continue on steps you do not want to change.', 'security-ninja' ) . '</p>';
        $markup .= '<p>' . esc_html__( 'Affected modules: Firewall, Events Logger, Vulnerability Scanner, Login Protection, Default Fixes, and WooCommerce Protection.', 'security-ninja' ) . '</p></div>';
        return $markup;
    }

    /**
     * Short reminder on Activate steps during a rerun.
     *
     * @return string
     */
    private static function get_rerun_activate_reminder_markup() {
        return '<p class="secnin-wizard-activate-reminder"><em>' . esc_html__( 'Activate replaces this module\'s settings with wizard defaults.', 'security-ninja' ) . '</em></p>';
    }

    /**
     * Persist wizard completion timestamp.
     *
     * @return void
     */
    private static function mark_wizard_completed() {
        $options = Wf_Sn::get_options();
        $options['wizard_completed_at'] = (string) time();
        update_option( 'wf_sn_options', $options, false );
    }

    /**
     * Single Pro overview for free-tier wizard (intro only).
     *
     * @return string
     */
    private static function get_pro_overview_markup() {
        $text = __( 'Everything in this wizard works on the free plan. Pro adds stronger protection when you need it: cloud firewall with 600M+ bad IPs, login brute-force blocking, one-click security fixes, WooCommerce hardening, malware scanning, and more.', 'security-ninja' );
        $url = Utils::generate_sn_web_link( 'install_wizard', '/pricing/' );
        if ( $url ) {
            $text .= ' <a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html__( 'Compare plans', 'security-ninja' ) . '</a>';
        }
        return '<p class="wizard-pro-overview">' . $text . '</p>';
    }

    /**
     * Save an option and confirm the critical wizard flags were stored.
     *
     * A strict comparison against the payload cannot be used here: several of these
     * options are registered with register_setting() sanitize callbacks (wf_sn_cf,
     * wf_sn_el, wf_sn_vu_settings_group) that run on every update_option() call and
     * rebuild, reorder, recast, or drop keys. The stored array therefore never
     * equals the array the wizard passed in, even on a successful save, which made
     * every activate step report "Failed to save settings". Instead we verify that
     * the option persisted as an array and that the specific flags the step turned
     * on are present with the expected value (loose comparison tolerates 1 vs '1').
     *
     * @param string $option_name Option name.
     * @param mixed  $value       Full option value to store.
     * @param array  $expected    Optional map of key => expected value to confirm.
     * @return bool True when the option was stored and the expected flags match.
     */
    private static function persist_wizard_option( $option_name, $value, $expected = array() ) {
        update_option( $option_name, $value, false );
        $stored = get_option( $option_name );
        if ( !is_array( $stored ) ) {
            return false;
        }
        foreach ( $expected as $key => $expected_value ) {
            if ( !array_key_exists( $key, $stored ) ) {
                return false;
            }
            // Loose comparison: sanitize callbacks may recast 1 as '1' or true.
            if ( $stored[$key] != $expected_value ) {
                // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison, Universal.Operators.StrictComparisons.LooseNotEqual
                return false;
            }
        }
        return true;
    }

    /**
     * Render the wizard page.
     *
     * This method generates the HTML for the wizard page, including the steps
     * and the navigation menu.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function wizard_page() {
        ?>

		<div class="wrap secnin-wizard-page">
			<?php 
        echo '<div class="secnin-wizard-notices" role="alert" aria-live="assertive"></div>';
        if ( self::is_wizard_rerun() ) {
            echo wp_kses_post( self::get_rerun_warning_markup() );
        }
        echo '<div class="card whizzie-wrap">';
        \WPSecurityNinja\Plugin\Utils::show_topbar();
        echo '<div class="secnin-wizard-body">';
        // The wizard is a list with only one item visible at a time
        $steps = self::get_steps();
        $step_count = count( $steps );
        echo '<ul class="whizzie-menu">';
        $allowed_html = wp_kses_allowed_html( 'post' );
        foreach ( $steps as $step ) {
            $class = 'step step-' . esc_attr( $step['id'] );
            echo '<li data-step="' . esc_attr( $step['id'] ) . '" class="' . esc_attr( $class ) . '">';
            $step_title = str_replace( array(' &hearts;', '&hearts;'), '', $step['title'] );
            if ( 'intro' === $step['id'] || 'security_tests' === $step['id'] ) {
                printf( '<h2>%s <span class="secnin-wizard-heart" aria-hidden="true">♥</span></h2>', esc_html( $step_title ) );
            } else {
                printf( '<h2>%s</h2>', esc_html( $step_title ) );
            }
            // $content is split into summary and detail
            $content = call_user_func( array(__NAMESPACE__ . '\\Wf_Sn_Wiz', $step['view']) );
            if ( isset( $content['summary'] ) ) {
                printf( '<div class="summary">%s</div>', wp_kses( $content['summary'], $allowed_html ) );
            }
            $is_activate_step = isset( $step['callback'] ) && 0 === strpos( $step['callback'], 'activate_' );
            if ( self::is_wizard_rerun() && $is_activate_step ) {
                echo wp_kses_post( self::get_rerun_activate_reminder_markup() );
            }
            // Primary and optional Skip in one .button-wrap (layout + accessibility grouping).
            if ( isset( $step['button_text'] ) && $step['button_text'] ) {
                $button_class = '';
                if ( isset( $step['button_class'] ) ) {
                    $button_class = $step['button_class'];
                }
                echo '<div class="button-wrap">';
                printf(
                    '<a href="#" class="button button-hero button-primary do-it %s" data-callback="%s" data-step="%s">%s</a>',
                    esc_attr( $button_class ),
                    esc_attr( $step['callback'] ),
                    esc_attr( $step['id'] ),
                    esc_html( $step['button_text'] )
                );
                if ( isset( $step['can_skip'] ) && $step['can_skip'] ) {
                    printf( '<a href="#" class="button button-secondary do-it secnin-wizard-step-skip" data-callback="do_next_step" data-step="%s">%s</a>', esc_attr( $step['id'] ), esc_html( __( 'Skip', 'security-ninja' ) ) );
                }
                if ( isset( $step['skip_wizard_url'] ) && $step['skip_wizard_url'] ) {
                    printf( '<a href="#" class="secnin-wizard-skip-link secnin-wizard-exit" data-href="%s">%s</a>', esc_url( $step['skip_wizard_url'] ), esc_html__( 'Skip to Dashboard', 'security-ninja' ) );
                }
                echo '</div>';
            }
            echo '</li>';
        }
        echo '</ul>';
        echo '</div>';
        echo '<div class="secnin-wizard-footer">';
        echo '<nav aria-label="' . esc_attr__( 'Setup wizard progress', 'security-ninja' ) . '">';
        echo '<ol class="whizzie-nav">';
        $nav_index = 0;
        foreach ( $steps as $step ) {
            if ( isset( $step['icon'] ) && $step['icon'] ) {
                ++$nav_index;
                if ( isset( $step['skip_icon'] ) && $step['skip_icon'] ) {
                    $iconout = '';
                } else {
                    $iconout = '<span class="dashicons dashicons-' . esc_attr( $step['icon'] ) . '" aria-hidden="true"></span>';
                }
                $nav_li_class = 'nav-step-' . $step['id'];
                if ( !empty( $step['pro_badge'] ) ) {
                    $nav_li_class .= ' profeature';
                }
                $nav_aria_label = sprintf(
                    /* translators: 1: step number, 2: total steps, 3: step name */
                    __( 'Step %1$d of %2$d: %3$s', 'security-ninja' ),
                    $nav_index,
                    $step_count,
                    $step['title_short']
                );
                echo '<li id="' . esc_attr( 'secnin-wizard-nav-' . $step['id'] ) . '" class="' . esc_attr( $nav_li_class ) . '" aria-label="' . esc_attr( $nav_aria_label ) . '"';
                if ( 1 === $nav_index ) {
                    echo ' aria-current="step"';
                }
                echo '>' . wp_kses_post( $iconout );
                echo '<span class="screen-reader-text secnin-wizard-nav-status">' . esc_html__( 'Upcoming step', 'security-ninja' ) . '</span>';
                echo '<span class="titleshort" aria-hidden="true">' . esc_html( $step['title_short'] ) . '</span></li>';
            }
        }
        echo '</ol>';
        echo '</nav>';
        echo '</div>';
        ?>
			<div class="step-loading"><span class="spinner"></span></div>
		</div>
					</div>
		<?php 
    }

    /**
     * Get the steps for the wizard.
     *
     * This method returns an array of steps for the wizard, including their
     * configuration and options. It also allows for customization of the
     * steps by the theme developer.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array of wizard steps.
     */
    public static function get_steps() {
        $dev_steps = self::$config_steps;
        $plugin_name = self::get_plugin_display_name();
        $login_callback = 'do_next_step';
        $login_button = __( 'Continue', 'security-ninja' );
        $login_button_class = ' button-secondary';
        $fixes_callback = 'do_next_step';
        $fixes_button = __( 'Continue', 'security-ninja' );
        $fixes_button_class = ' button-secondary';
        $woo_callback = 'do_next_step';
        $woo_button = __( 'Continue', 'security-ninja' );
        $woo_button_class = ' button-secondary';
        $woo_can_skip = false;
        $show_pro_badges = true;
        $steps = array(
            'intro'            => array(
                'id'              => 'intro',
                'title'           => __( 'Thank you for choosing', 'security-ninja' ) . ' ' . esc_attr( $plugin_name ) . ' &hearts;',
                'title_short'     => __( 'Welcome', 'security-ninja' ),
                'icon'            => 'dashboard',
                'view'            => 'get_step_intro',
                'callback'        => 'do_next_step',
                'button_text'     => __( 'Start Wizard', 'security-ninja' ) . ' →',
                'button_class'    => ' button-hero',
                'can_skip'        => false,
                'skip_wizard_url' => admin_url( 'admin.php?page=wf-sn' ),
            ),
            'firewall'         => array(
                'id'          => 'firewall',
                'title'       => __( 'Activate Firewall Protection', 'security-ninja' ),
                'title_short' => __( 'Firewall', 'security-ninja' ),
                'icon'        => 'shield',
                'view'        => 'get_step_firewall',
                'callback'    => 'activate_firewall',
                'button_text' => __( 'Activate', 'security-ninja' ),
                'can_skip'    => true,
            ),
            'events'           => array(
                'id'          => 'events',
                'title'       => __( 'Activate Events Logger', 'security-ninja' ),
                'title_short' => __( 'Events', 'security-ninja' ),
                'icon'        => 'visibility',
                'view'        => 'get_step_events',
                'callback'    => 'activate_events',
                'button_text' => __( 'Activate', 'security-ninja' ),
                'can_skip'    => true,
            ),
            'vulnerabilities'  => array(
                'id'          => 'vulnerabilities',
                'title'       => __( 'Activate Vulnerability Scanner', 'security-ninja' ),
                'title_short' => __( 'Vulnerabilities', 'security-ninja' ),
                'icon'        => 'warning',
                'view'        => 'get_step_vulnerabilities',
                'callback'    => 'activate_vulnerabilities',
                'button_text' => __( 'Activate', 'security-ninja' ),
                'can_skip'    => true,
            ),
            'login_protection' => array(
                'id'           => 'login_protection',
                'title'        => __( 'Login Protection', 'security-ninja' ),
                'title_short'  => __( 'Login', 'security-ninja' ),
                'icon'         => 'lock',
                'view'         => 'get_step_login_protection',
                'callback'     => $login_callback,
                'button_text'  => $login_button,
                'button_class' => $login_button_class,
                'can_skip'     => true,
                'pro_badge'    => $show_pro_badges,
            ),
            'default_fixes'    => array(
                'id'           => 'default_fixes',
                'title'        => __( 'Activate Default Security Measures', 'security-ninja' ),
                'title_short'  => __( 'Fixes', 'security-ninja' ),
                'icon'         => 'admin-plugins',
                'view'         => 'get_step_default_fixes',
                'callback'     => $fixes_callback,
                'button_text'  => $fixes_button,
                'button_class' => $fixes_button_class,
                'can_skip'     => true,
                'pro_badge'    => $show_pro_badges,
            ),
            'woocommerce'      => array(
                'id'           => 'woocommerce',
                'title'        => __( 'WooCommerce Protection', 'security-ninja' ),
                'title_short'  => __( 'WooCommerce', 'security-ninja' ),
                'icon'         => 'cart',
                'view'         => 'get_step_woocommerce',
                'callback'     => $woo_callback,
                'button_text'  => $woo_button,
                'button_class' => $woo_button_class,
                'can_skip'     => $woo_can_skip,
                'pro_badge'    => $show_pro_badges,
            ),
            'security_tests'   => array(
                'id'          => 'security_tests',
                'title'       => __( 'Thank you - All done ', 'security-ninja' ) . ' &hearts;',
                'title_short' => __( 'Done', 'security-ninja' ),
                'icon'        => 'yes-alt',
                'view'        => 'get_step_security_tests',
                'can_skip'    => false,
            ),
        );
        // Iterate through each step and replace with dev config values
        if ( $dev_steps ) {
            // Configurable elements - these are the only ones the dev can update from config.php
            $can_config = array(
                'title',
                'icon',
                'button_text',
                'can_skip'
            );
            foreach ( $dev_steps as $dev_step ) {
                // We can only proceed if an ID exists and matches one of our IDs
                if ( isset( $dev_step['id'] ) ) {
                    $id = $dev_step['id'];
                    if ( isset( $steps[$id] ) ) {
                        foreach ( $can_config as $element ) {
                            if ( isset( $dev_step[$element] ) ) {
                                $steps[$id][$element] = $dev_step[$element];
                            }
                        }
                    }
                }
            }
        }
        return $steps;
    }

    /**
     * Get the content for the intro step.
     *
     * This method returns an array containing the summary and detail content
     * for the intro step of the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_intro() {
        $content = array();
        $content['summary'] = '<p class="secnin-wizard-lead">' . __( 'This wizard sets up standard best security practices for your website.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p><strong>' . __( 'Included in your install:', 'security-ninja' ) . '</strong></p>';
        $content['summary'] .= '<ul class="summarylist">';
        $content['summary'] .= '<li>' . __( 'Security tests to harden your WordPress site', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Vulnerability scanner for plugins and themes', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Core file scanner to detect unexpected changes', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Firewall, Events Logger, and Vulnerability Scanner (activated in this wizard)', 'security-ninja' ) . '</li>';
        $content['summary'] .= '</ul>';
        $show_pro_overview = true;
        if ( $show_pro_overview ) {
            $content['summary'] .= self::get_pro_overview_markup();
        }
        return $content;
    }

    /**
     * Get the content for the default fixes step.
     *
     * This method returns an array containing the summary and detail content
     * for the default fixes step of the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_default_fixes() {
        $content = array();
        $content['summary'] = '<p>' . __( 'One-click fixes hide version info, add security headers, secure cookies, and more — all in a single step.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p>' . __( 'That is included with Pro. Use Continue below to finish your free setup.', 'security-ninja' ) . '</p>';
        return $content;
    }

    /**
     * Get the content for the firewall step.
     *
     * This method returns an array containing the summary and detail content
     * for the firewall step of the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_firewall() {
        $content = array();
        $content['summary'] = '<p>' . __( 'The firewall protects you against hack attempts, blocks known spammers and malicious IPs.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p><strong>' . __( 'Activate turns on:', 'security-ninja' ) . '</strong></p>';
        $content['summary'] .= '<ul class="summarylist">';
        $content['summary'] .= '<li>' . __( 'Firewall protection with global rules enabled', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( '8G firewall rules — filter suspicious queries and common attack patterns', 'security-ninja' ) . '</li>';
        $content['summary'] .= '</ul>';
        return $content;
    }

    /**
     * Get the content for the events logger step.
     *
     * @since  5.289
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_events() {
        $content = array();
        $content['summary'] = '<p>' . __( 'The Events Logger keeps an audit trail of important activity on your site.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p>' . __( 'Activate enables the logger with standard modules. You can turn individual modules on or off later under Events Logger settings.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p><strong>' . __( 'Activate turns on logging for:', 'security-ninja' ) . '</strong></p>';
        $content['summary'] .= '<ul class="summarylist">';
        $content['summary'] .= '<li>' . __( 'Admin logins and failed login attempts', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'User accounts, roles, and profile changes', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Plugin and theme installs and updates', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'WordPress settings changes and Security Ninja actions', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Posts, pages, media, comments, menus, and widgets', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'WooCommerce store activity (when WooCommerce is active)', 'security-ninja' ) . '</li>';
        $content['summary'] .= '</ul>';
        $show_events_pro_note = true;
        if ( $show_events_pro_note ) {
            $content['summary'] .= '<p class="wizard-pro-overview">' . __( 'Email reports and webhooks are available with Pro — configure them later under Events Logger settings.', 'security-ninja' ) . '</p>';
        }
        return $content;
    }

    /**
     * Get the content for the vulnerability scanner step.
     *
     * @since  5.289
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_vulnerabilities() {
        $content = array();
        $content['summary'] = '<p>' . __( 'The vulnerability scanner checks your installed plugins and themes against known security issues.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p><strong>' . __( 'Activate turns on:', 'security-ninja' ) . '</strong></p>';
        $content['summary'] .= '<ul class="summarylist">';
        $content['summary'] .= '<li>' . __( 'Automatic vulnerability scanning for installed plugins and themes', 'security-ninja' ) . '</li>';
        $content['summary'] .= '<li>' . __( 'Admin dashboard notifications when vulnerabilities are found', 'security-ninja' ) . '</li>';
        $content['summary'] .= '</ul>';
        return $content;
    }

    /**
     * Get the content for the login protection step.
     *
     * @since  5.289
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_login_protection() {
        $content = array();
        $content['summary'] = '<p>' . __( 'Failed logins are already logged from the Events step.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p>' . __( 'Pro automatically blocks IPs that keep guessing passwords. Use Continue below to move on.', 'security-ninja' ) . '</p>';
        return $content;
    }

    /**
     * Get the content for the WooCommerce step.
     *
     * This method returns an array containing the summary and detail content
     * for the WooCommerce step of the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_woocommerce() {
        $content = array();
        $woocommerce_active = class_exists( 'WooCommerce' );
        $content['summary'] = '<p>' . __( 'Pro can rate-limit checkout and cart actions and stop coupon guessing attacks on WooCommerce stores.', 'security-ninja' ) . '</p>';
        if ( !$woocommerce_active ) {
            $content['summary'] .= '<p>' . __( 'WooCommerce is not active on your site yet — use Continue below. You can turn on store protection later from Cloud Firewall settings.', 'security-ninja' ) . '</p>';
        } else {
            $content['summary'] .= '<p>' . __( 'Use Continue below to finish your free setup.', 'security-ninja' ) . '</p>';
        }
        return $content;
    }

    /**
     * Get the content for the security tests step.
     *
     * This method returns an array containing the summary and detail content
     * for the security tests step of the wizard.
     *
     * @since  0.0.1
     * @access public static
     * @return array An array containing the summary and detail content.
     */
    public static function get_step_security_tests() {
        $content = array();
        $content['summary'] = '<p class="secnin-wizard-lead">' . __( 'Your security baseline is in place. Here is what to do next.', 'security-ninja' ) . '</p>';
        $content['summary'] .= '<p><strong>' . __( 'Recommended next steps', 'security-ninja' ) . '</strong></p>';
        $content['summary'] .= '<ul class="summarylist wizard-next-steps">';
        $tests_url = admin_url( 'admin.php?page=wf-sn#sn_tests' );
        $content['summary'] .= '<li>' . sprintf(
            '<a href="%1$s">%2$s</a> — %3$s',
            esc_url( $tests_url ),
            esc_html__( 'Run security tests', 'security-ninja' ),
            esc_html__( 'find and fix common WordPress misconfigurations', 'security-ninja' )
        ) . '</li>';
        $vuln_url = admin_url( 'admin.php?page=wf-sn#sn_vuln' );
        $content['summary'] .= '<li>' . sprintf(
            '<a href="%1$s">%2$s</a> — %3$s',
            esc_url( $vuln_url ),
            esc_html__( 'Review vulnerability scan results', 'security-ninja' ),
            esc_html__( 'check plugins and themes for known issues', 'security-ninja' )
        ) . '</li>';
        $core_url = admin_url( 'admin.php?page=wf-sn#sn_core' );
        $content['summary'] .= '<li>' . sprintf(
            '<a href="%1$s">%2$s</a> — %3$s',
            esc_url( $core_url ),
            esc_html__( 'Run the core file scanner', 'security-ninja' ),
            esc_html__( 'spot unexpected changes in WordPress core files', 'security-ninja' )
        ) . '</li>';
        $events_url = admin_url( 'admin.php?page=wf-sn#sn_logger' );
        $content['summary'] .= '<li>' . sprintf(
            '<a href="%1$s">%2$s</a> — %3$s',
            esc_url( $events_url ),
            esc_html__( 'Browse the Events Logger', 'security-ninja' ),
            esc_html__( 'see who logged in and what changed on your site', 'security-ninja' )
        ) . '</li>';
        $content['summary'] .= '</ul>';
        $content['summary'] .= '<p>' . sprintf( 
            /* translators: 1: documentation link HTML, 2: support link HTML */
            __( 'Need help? Read our %1$s or %2$s.', 'security-ninja' ),
            '<a href="https://wpsecurityninja.com/docs/" target="_blank" rel="noopener">' . esc_html__( 'documentation', 'security-ninja' ) . '</a>',
            '<a href="https://wpsecurityninja.com/help/" target="_blank" rel="noopener">' . esc_html__( 'contact support', 'security-ninja' ) . '</a>'
         ) . '</p>';
        $secninlink = admin_url( 'admin.php?page=wf-sn#sn_overview' );
        $content['summary'] .= '<p><a href="' . esc_url( $secninlink ) . '" class="button button-primary button-hero secnin-wizard-finish">' . __( 'Go to Dashboard', 'security-ninja' ) . '</a></p>';
        return $content;
    }

    /**
     * Enqueue CSS and JS scripts for the wizard.
     *
     * This method enqueues the necessary CSS and JS scripts for the wizard
     * page, including the localized parameters.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function enqueue_scripts() {
        global $current_screen;
        $needle = 'page_security-ninja-wizard';
        // Checks if we are on the wizard page, otherwise we leave
        if ( !self::str_ends_with( $current_screen->id, $needle ) ) {
            return;
        }
        wp_register_script(
            'secnin-wizard',
            WF_SN_PLUGIN_URL . 'modules/wizard/assets/js/secnin-wizard.js',
            array('jquery'),
            Wf_Sn::$version,
            true
        );
        $js_vars = array(
            'nonce'         => wp_create_nonce( 'secnin_wizard_nonce' ),
            'sn_plugin_url' => WF_SN_PLUGIN_URL,
            'generic_error' => __( 'Something went wrong. Please try again.', 'security-ninja' ),
            'network_error' => __( 'Could not reach the server. Please try again.', 'security-ninja' ),
            'i18n'          => array(
                'nav_completed' => __( 'Completed step', 'security-ninja' ),
                'nav_current'   => __( 'Current step', 'security-ninja' ),
                'nav_upcoming'  => __( 'Upcoming step', 'security-ninja' ),
            ),
        );
        wp_localize_script( 'secnin-wizard', 'whizzie_params', $js_vars );
        wp_enqueue_script( 'secnin-wizard' );
    }

    /**
     * Activate the firewall and set default settings.
     *
     * This method activates the firewall and sets the default settings
     * for the Security Ninja plugin. It also sends the unblock URL to the
     * current user's email address.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function activate_firewall() {
        // Verify nonce for CSRF protection
        check_ajax_referer( 'secnin_wizard_nonce' );
        // Check user capabilities
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        // Additional security check - ensure we're in admin context
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        // Validate that the firewall class exists
        if ( !class_exists( __NAMESPACE__ . '\\Wf_sn_cf' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Firewall module not available.', 'security-ninja' ),
            ) );
        }
        $default_firewall_options = Wf_sn_cf::get_options();
        $default_firewall_options['active'] = 1;
        $default_firewall_options['global'] = 1;
        $default_firewall_options['filterqueries'] = 1;
        $default_firewall_options['blockadminlogin'] = 0;
        $default_firewall_options['trackvisits'] = 0;
        $default_firewall_options['blocked_countries'] = array();
        $default_firewall_options['usecloud'] = 0;
        $default_firewall_options['globalbannetwork'] = 0;
        // Validate the option key constant exists
        if ( !defined( 'WF_SN_CF_OPTIONS_KEY' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Configuration error.', 'security-ninja' ),
            ) );
        }
        if ( !self::persist_wizard_option( WF_SN_CF_OPTIONS_KEY, $default_firewall_options, array(
            'active' => 1,
        ) ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed to save settings.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'Firewall enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

    /**
     * Activate the Events Logger.
     *
     * @since  5.289
     * @access public static
     * @return void
     */
    public static function activate_events() {
        check_ajax_referer( 'secnin_wizard_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_El' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Events Logger module not available.', 'security-ninja' ),
            ) );
        }
        $options = Wf_Sn_El::get_baseline_options();
        $options['active'] = 1;
        if ( !self::persist_wizard_option( 'wf_sn_el', $options, array(
            'active' => 1,
        ) ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed to save settings.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'Events Logger enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

    /**
     * Activate the vulnerability scanner.
     *
     * @since  5.289
     * @access public static
     * @return void
     */
    public static function activate_vulnerabilities() {
        check_ajax_referer( 'secnin_wizard_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Vu' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Vulnerability scanner not available.', 'security-ninja' ),
            ) );
        }
        $options = Wf_Sn_Vu::get_options();
        $options['enable_vulns'] = 1;
        $options['enable_admin_notification'] = 1;
        if ( !self::persist_wizard_option( 'wf_sn_vu_settings_group', $options, array(
            'enable_vulns' => 1,
        ) ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed to save settings.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'Vulnerability scanner enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

    /**
     * Activate login protection (Pro).
     *
     * @since  5.289
     * @access public static
     * @return void
     */
    public static function activate_login_protection() {
        check_ajax_referer( 'secnin_wizard_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        $login_protection_activated = false;
        if ( !$login_protection_activated ) {
            wp_send_json_error( array(
                'message' => __( 'Login protection requires Security Ninja Pro.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'Login protection enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

    /**
     * Mark the wizard as all done.
     *
     * This method is called when the wizard is completed.
     * It sends a JSON response indicating that the wizard is done.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function all_done() {
        // Verify nonce for CSRF protection
        check_ajax_referer( 'secnin_wizard_nonce' );
        // Check user capabilities
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        // Additional security check - ensure we're in admin context
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        self::mark_wizard_completed();
        $results = array(
            'done'    => 1,
            'message' => __( 'All finished.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
    }

    /**
     * Activate the default fixes.
     *
     * This method activates the default fixes for the Security Ninja plugin.
     * It sets the default options for the fixes and enables automatic
     * background updates for the plugin.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function activate_default_fixes() {
        check_ajax_referer( 'secnin_wizard_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        $fixes_activated = false;
        if ( !$fixes_activated ) {
            wp_send_json_error( array(
                'message' => __( 'Default fixes require Security Ninja Pro.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'Default fixes enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

    /**
     * Activate WooCommerce protection features.
     *
     * This method activates the WooCommerce protection features for the Security Ninja plugin.
     * It enables rate limiting and coupon protection features.
     *
     * @since  0.0.1
     * @access public static
     * @return void
     */
    public static function activate_woocommerce() {
        check_ajax_referer( 'secnin_wizard_nonce' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Insufficient permissions.', 'security-ninja' ),
            ) );
        }
        if ( !is_admin() ) {
            wp_send_json_error( array(
                'message' => __( 'Invalid request context.', 'security-ninja' ),
            ) );
        }
        $woo_protection_activated = false;
        if ( !$woo_protection_activated ) {
            wp_send_json_error( array(
                'message' => __( 'WooCommerce protection requires Security Ninja Pro.', 'security-ninja' ),
            ) );
        }
        $results = array(
            'done'    => 1,
            'message' => __( 'WooCommerce protection enabled.', 'security-ninja' ),
        );
        wp_send_json_success( $results );
        exit;
    }

}

// hook everything up
add_action( 'plugins_loaded', array(__NAMESPACE__ . '\\Wf_Sn_Wiz', 'init') );