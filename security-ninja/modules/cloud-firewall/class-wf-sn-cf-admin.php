<?php

/**
 * Cloud Firewall Wf_Sn_Cf_Admin helpers (loaded on demand).
 *
 * @package WPSecurityNinja\Plugin
 */
namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Cf_Admin
 */
class Wf_Sn_Cf_Admin {
    public static function enqueue_scripts() {
        if ( !Wf_Sn::is_plugin_page() ) {
            return;
        }
        // Use SN-specific handles — themes such as MyListing call wp_deregister_script( 'select2' ).
        wp_register_style(
            'sn-cf-select2',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/select2/css/select2.css',
            array(),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/select2/css/select2.css' )
        );
        wp_register_script(
            'sn-cf-select2',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/select2/js/select2.js',
            array('jquery'),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/select2/js/select2.js' ),
            true
        );
        wp_enqueue_style( 'sn-cf-select2' );
        wp_enqueue_script( 'sn-cf-select2' );
        wp_enqueue_style( 'dashicons' );
        wp_enqueue_style(
            'sn-cf-css',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/css/wf-sn-cf.css',
            array('dashicons', 'sn-cf-select2'),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/css/wf-sn-cf.css' )
        );
        Wf_Sn::enqueue_sn_dialog();
        wp_register_script(
            'sn-cf-js',
            WF_SN_PLUGIN_URL . 'modules/cloud-firewall/js/wf-sn-cf.js',
            array('jquery', 'sn-cf-select2', 'sn-dialog'),
            filemtime( WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/js/wf-sn-cf.js' ),
            true
        );
        $js_vars = array(
            'nonce'         => wp_create_nonce( 'wf_sn_cf' ),
            'sn_plugin_url' => WF_SN_PLUGIN_URL,
            'site_host'     => wp_parse_url( home_url(), PHP_URL_HOST ),
            'strings'       => array(
                'copy_blacklisted'    => __( 'Copy blacklisted IPs', 'security-ninja' ),
                'copy_whitelisted'    => __( 'Copy whitelisted IPs', 'security-ninja' ),
                'copied'              => __( 'Copied to clipboard.', 'security-ninja' ),
                'copy_failed'         => __( 'Could not copy to clipboard.', 'security-ninja' ),
                'confirm_remove_ip'   => __( 'Remove your current IP from the whitelist? You may lock yourself out.', 'security-ninja' ),
                'no_entries'          => __( 'No IP entries match your filters.', 'security-ninja' ),
                'remove'              => __( 'Remove', 'security-ninja' ),
                'copy'                => __( 'Copy', 'security-ninja' ),
                'prev'                => __( 'Prev', 'security-ninja' ),
                'next'                => __( 'Next', 'security-ninja' ),
                'copy_ip'             => __( 'Copy IP', 'security-ninja' ),
                'cancel'              => __( 'Cancel', 'security-ninja' ),
                'list_blacklist'      => __( 'blacklist', 'security-ninja' ),
                'list_whitelist'      => __( 'whitelist', 'security-ninja' ),
                'remove_confirm'      => __( 'Remove %1$s from the %2$s?', 'security-ninja' ),
                'source_label'        => __( 'Source:', 'security-ninja' ),
                'expires_label'       => __( 'Expires:', 'security-ninja' ),
                'last_visit_label'    => __( 'Last visit:', 'security-ninja' ),
                'note_label'          => __( 'Note:', 'security-ninja' ),
                'status_whitelisted'  => __( 'Whitelisted', 'security-ninja' ),
                'status_blacklisted'  => __( 'Blacklisted', 'security-ninja' ),
                'add_rule'            => __( 'Add IP rule', 'security-ninja' ),
                'edit_rule'           => __( 'Edit IP rule', 'security-ninja' ),
                'edit'                => __( 'Edit', 'security-ninja' ),
                'save'                => __( 'Save', 'security-ninja' ),
                'block_all_countries' => __( 'Block all countries?', 'security-ninja' ),
                'add_success'         => __( 'IP rule added.', 'security-ninja' ),
                'edit_success'        => __( 'IP rule updated.', 'security-ninja' ),
                'list_type_blacklist' => __( 'Blacklist', 'security-ninja' ),
                'list_type_whitelist' => __( 'Whitelist', 'security-ninja' ),
            ),
            'waf_strings'   => array(
                'installing'             => __( 'Installing…', 'security-ninja' ),
                'installed'              => __( 'Installed.', 'security-ninja' ),
                'install_failed'         => __( 'Install failed.', 'security-ninja' ),
                'install_request_failed' => __( 'Install request failed.', 'security-ninja' ),
                'verifying'              => __( 'Verifying…', 'security-ninja' ),
                'verified'               => __( 'Verified.', 'security-ninja' ),
                'verify_failed'          => __( 'Verify failed.', 'security-ninja' ),
                'verify_request_failed'  => __( 'Verify request failed.', 'security-ninja' ),
                'disabling'              => __( 'Disabling…', 'security-ninja' ),
                'disabled'               => __( 'Disabled.', 'security-ninja' ),
                'disable_failed'         => __( 'Disable failed.', 'security-ninja' ),
                'disable_request_failed' => __( 'Disable request failed.', 'security-ninja' ),
                'confirm_title'          => __( 'Confirm chaining', 'security-ninja' ),
                'confirm_chain'          => __( 'Enable Early Firewall and chain this existing prepend file after Security Ninja?', 'security-ninja' ),
                'confirm_ok'             => __( 'Enable', 'security-ninja' ),
                'confirm_cancel'         => __( 'Cancel', 'security-ninja' ),
                'unsaved_warning'        => __( 'You have unsaved firewall form changes.', 'security-ninja' ),
            ),
        );
        wp_localize_script( 'sn-cf-js', 'wf_sn_cf', $js_vars );
        wp_enqueue_script( 'sn-cf-js' );
    }

    /**
     * Return firewall options
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  mixed
     */
    public static function sanitize_2fa_required_role_slugs( $raw ) {
        $wp_roles = ( function_exists( 'wp_roles' ) ? wp_roles() : null );
        $valid = ( is_object( $wp_roles ) && isset( $wp_roles->roles ) ? array_keys( $wp_roles->roles ) : array() );
        if ( is_string( $raw ) && '' !== $raw ) {
            $raw = array($raw);
        } elseif ( !is_array( $raw ) ) {
            $raw = array();
        }
        $out = array();
        foreach ( $raw as $slug ) {
            $slug = sanitize_text_field( (string) $slug );
            if ( '' === $slug ) {
                continue;
            }
            if ( empty( $valid ) ) {
                // wp_roles() unavailable (very early); accept nothing so callers can fall back safely.
                continue;
            }
            if ( in_array( $slug, $valid, true ) ) {
                $out[] = $slug;
            }
        }
        return array_values( array_unique( $out ) );
    }

    /**
     * Normalize 2FA required roles: valid slugs only (may be empty for opt-in-only mode).
     *
     * @param mixed $raw             Stored or submitted roles.
     * @param bool  $two_fa_enabled  Whether 2FA is enabled (unused; kept for callers).
     * @return string[]
     */
    public static function sanitize_2fa_methods_list( $raw ) {
        $allowed = array('app', 'email');
        if ( is_string( $raw ) && '' !== $raw ) {
            $raw = array($raw);
        } elseif ( !is_array( $raw ) ) {
            $raw = array();
        }
        $out = array();
        foreach ( $raw as $method ) {
            $method = sanitize_text_field( (string) $method );
            if ( in_array( $method, $allowed, true ) ) {
                $out[] = $method;
            }
        }
        return array_values( array_unique( $out ) );
    }

    /**
     * Normalize allowed 2FA methods (app and/or email); defaults to app when empty on read.
     *
     * @param mixed $raw Stored or submitted methods.
     * @return string[]
     */
    public static function ajax_enable_firewall() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        wf_sn_cf::$options['active'] = 1;
        update_option( WF_SN_CF_OPTIONS_KEY, wf_sn_cf::$options, false );
        if ( class_exists( __NAMESPACE__ . '\\SN_Geolocation' ) ) {
            \WPSecurityNinja\Plugin\SN_Geolocation::update_database();
            // updates the geoip when turning on firewall + via cron afterwards.
        }
        // Add notice about whitelist management
        add_settings_error(
            'wf_sn_cf',
            'firewall_activated',
            __( 'Firewall activated. For security best practices, remember to manually review and manage your IP whitelist.', 'security-ninja' ),
            'info'
        );
        wp_send_json_success( array(
            'message' => __( 'Firewall activated successfully.', 'security-ninja' ),
            'notices' => get_settings_errors( 'wf_sn_cf' ),
        ) );
    }

    /**
     * AJAX: disable firewall.
     *
     * @return void
     */
    public static function ajax_disable_firewall() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        wf_sn_cf::$options = wf_sn_cf::get_options();
        wf_sn_cf::$options['active'] = 0;
        update_option( WF_SN_CF_OPTIONS_KEY, wf_sn_cf::$options, false );
        do_action( 'security_ninja_firewall_settings_saved' );
        wp_send_json_success( array(
            'message' => __( 'Firewall disabled.', 'security-ninja' ),
        ) );
    }

    /**
     * AJAX: install Early Firewall.
     *
     * @return void
     */
    public static function ajax_waf_extended_install() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        wp_send_json_error( array(
            'message' => __( 'Installer not available.', 'security-ninja' ),
        ) );
    }

    /**
     * AJAX: verify Early Firewall.
     *
     * @return void
     */
    public static function ajax_waf_extended_verify() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        wp_send_json_error( array(
            'message' => __( 'Installer not available.', 'security-ninja' ),
        ) );
    }

    /**
     * AJAX: uninstall Early Firewall.
     *
     * @return void
     */
    public static function ajax_waf_extended_uninstall() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        wp_send_json_error( array(
            'message' => __( 'Installer not available.', 'security-ninja' ),
        ) );
    }

    /**
     * Attach panel UI state and send the Early Firewall AJAX result.
     *
     * @param array $result Installer result.
     * @return void
     */
    private static function waf_extended_send_result( $result ) {
        if ( !is_array( $result ) ) {
            $result = array();
        }
        $message = ( isset( $result['message'] ) ? (string) $result['message'] : '' );
        $is_error = empty( $result['success'] );
        $tab_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/extended.php';
        if ( is_readable( $tab_file ) ) {
            require_once $tab_file;
        }
        if ( function_exists( __NAMESPACE__ . '\\wf_sn_cf_early_firewall_panel_ui' ) ) {
            $result['ui'] = wf_sn_cf_early_firewall_panel_ui( $message, $is_error );
        }
        if ( !empty( $result['success'] ) ) {
            wp_send_json_success( $result );
        }
        wp_send_json_error( $result );
    }

    /**
     * Tests if an IP is banned, via AJAX
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  string
     */
    public static function ajax_test_ip() {
        check_ajax_referer( 'wf_sn_cf' );
        wf_sn_cf::require_premium_ip_management_ajax();
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['ip'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing IP.', 'security-ninja' ),
            ) );
        }
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
        if ( !filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_success( __( 'Please enter a valid IP address to test.', 'security-ninja' ) );
        }
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Ip_Management' ) ) {
            $check = Wf_Sn_Cf_Ip_Management::get_block_reasons_for_ip( $ip );
            if ( !empty( $check['whitelisted'] ) && empty( $check['blocked'] ) ) {
                wp_send_json_success( sprintf( 
                    /* translators: %s: IP address */
                    __( '%s is whitelisted and will not be blocked.', 'security-ninja' ),
                    esc_html( $ip )
                 ) );
            }
            if ( !empty( $check['blocked'] ) && !empty( $check['reasons'] ) ) {
                wp_send_json_success( sprintf( 
                    /* translators: 1: IP address, 2: comma-separated block reasons */
                    __( '%1$s is blocked. Reasons: %2$s', 'security-ninja' ),
                    esc_html( $ip ),
                    esc_html( implode( '; ', $check['reasons'] ) )
                 ) );
            }
            wp_send_json_success( sprintf( 
                /* translators: %s: IP address */
                __( '%s is NOT blocked.', 'security-ninja' ),
                esc_html( $ip )
             ) );
        }
        if ( $reason = wf_sn_cf::is_banned_ip( $ip ) ) {
            wp_send_json_success( sprintf( 
                /* translators: 1: IP - 2: The reason, leave as is. */
                __( '%1$s is banned. %2$s', 'security-ninja' ),
                esc_html( $ip ),
                esc_html( $reason )
             ) );
        }
        wp_send_json_success( sprintf( 
            /* translators: %s: IP address */
            __( '%s is NOT banned.', 'security-ninja' ),
            esc_html( $ip )
         ) );
    }

    /**
     * Return domain from full parsed URL
     *
     * https://stackoverflow.com/a/18560043/452515
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $url
     * @return  mixed
     */
    public static function ajax_add_ip_rule() {
        check_ajax_referer( 'wf_sn_cf' );
        wf_sn_cf::require_premium_ip_management_ajax();
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['ip'], $_POST['list_type'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing required fields.', 'security-ninja' ),
            ) );
        }
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
        $list_type = sanitize_key( wp_unslash( $_POST['list_type'] ) );
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Ip_Management' ) ) {
            wp_send_json_error( array(
                'message' => __( 'IP Management is not available.', 'security-ninja' ),
            ) );
        }
        $note = ( isset( $_POST['note'] ) ? Wf_Sn_Cf_Ip_Management::sanitize_note( wp_unslash( $_POST['note'] ) ) : '' );
        $result = Wf_Sn_Cf_Ip_Management::add_manual_rule( $ip, $list_type, $note );
        if ( is_wp_error( $result ) ) {
            wp_send_json_error( array(
                'message' => $result->get_error_message(),
            ) );
        }
        wp_send_json_success( array(
            'message' => __( 'IP rule added.', 'security-ninja' ),
            'data'    => $result,
        ) );
    }

    /**
     * Edit manual blacklist/whitelist rule via AJAX.
     *
     * @return void
     */
    public static function ajax_edit_ip_rule() {
        check_ajax_referer( 'wf_sn_cf' );
        wf_sn_cf::require_premium_ip_management_ajax();
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['old_ip'], $_POST['ip'], $_POST['list_type'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing required fields.', 'security-ninja' ),
            ) );
        }
        $old_ip = sanitize_text_field( wp_unslash( $_POST['old_ip'] ) );
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
        $list_type = sanitize_key( wp_unslash( $_POST['list_type'] ) );
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Ip_Management' ) ) {
            wp_send_json_error( array(
                'message' => __( 'IP Management is not available.', 'security-ninja' ),
            ) );
        }
        $note = ( isset( $_POST['note'] ) ? Wf_Sn_Cf_Ip_Management::sanitize_note( wp_unslash( $_POST['note'] ) ) : '' );
        $result = Wf_Sn_Cf_Ip_Management::edit_manual_rule(
            $old_ip,
            $ip,
            $list_type,
            $note
        );
        if ( is_wp_error( $result ) ) {
            wp_send_json_error( array(
                'message' => $result->get_error_message(),
            ) );
        }
        wp_send_json_success( array(
            'message' => __( 'IP rule updated.', 'security-ninja' ),
            'data'    => $result,
        ) );
    }

    /**
     * Remove manual blacklist/whitelist rule via AJAX.
     *
     * @return void
     */
    public static function ajax_remove_ip_rule() {
        check_ajax_referer( 'wf_sn_cf' );
        wf_sn_cf::require_premium_ip_management_ajax();
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['ip'], $_POST['list_type'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing required fields.', 'security-ninja' ),
            ) );
        }
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
        $list_type = sanitize_key( wp_unslash( $_POST['list_type'] ) );
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Ip_Management' ) ) {
            wp_send_json_error( array(
                'message' => __( 'IP Management is not available.', 'security-ninja' ),
            ) );
        }
        $result = Wf_Sn_Cf_Ip_Management::remove_manual_rule( $ip, $list_type );
        if ( is_wp_error( $result ) ) {
            wp_send_json_error( array(
                'message' => $result->get_error_message(),
            ) );
        }
        wp_send_json_success( array(
            'message' => __( 'IP rule removed.', 'security-ninja' ),
            'data'    => $result,
        ) );
    }

    /**
     * Bulk-add manual blacklist/whitelist rules via AJAX.
     *
     * @return void
     */
    public static function ajax_bulk_add_ip_rules() {
        check_ajax_referer( 'wf_sn_cf' );
        wf_sn_cf::require_premium_ip_management_ajax();
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['ips'], $_POST['list_type'] ) ) {
            wp_send_json_error( array(
                'message' => __( 'Missing required fields.', 'security-ninja' ),
            ) );
        }
        $ips = wp_unslash( $_POST['ips'] );
        $list_type = sanitize_key( wp_unslash( $_POST['list_type'] ) );
        if ( !class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Ip_Management' ) ) {
            wp_send_json_error( array(
                'message' => __( 'IP Management is not available.', 'security-ninja' ),
            ) );
        }
        $note = ( isset( $_POST['note'] ) ? Wf_Sn_Cf_Ip_Management::sanitize_note( wp_unslash( $_POST['note'] ) ) : '' );
        $result = Wf_Sn_Cf_Ip_Management::add_manual_rules_bulk( $ips, $list_type, $note );
        if ( is_wp_error( $result ) ) {
            wp_send_json_error( array(
                'message' => $result->get_error_message(),
            ) );
        }
        $summary = ( isset( $result['summary'] ) ? $result['summary'] : array() );
        unset($result['summary']);
        $added = ( isset( $summary['added'] ) ? (int) $summary['added'] : 0 );
        $invalid = ( isset( $summary['invalid'] ) ? (int) $summary['invalid'] : 0 );
        $skipped = ( isset( $summary['skipped_duplicate'] ) ? (int) $summary['skipped_duplicate'] : 0 );
        $message = sprintf( 
            /* translators: %d: number of IP rules added */
            _n(
                'Added %d IP rule.',
                'Added %d IP rules.',
                $added,
                'security-ninja'
            ),
            $added
         );
        if ( $invalid > 0 ) {
            $message .= ' ' . sprintf( 
                /* translators: %d: number of invalid lines skipped */
                _n(
                    '%d invalid line skipped.',
                    '%d invalid lines skipped.',
                    $invalid,
                    'security-ninja'
                ),
                $invalid
             );
        }
        if ( $skipped > 0 ) {
            $message .= ' ' . sprintf( 
                /* translators: %d: number of duplicate IPs skipped */
                _n(
                    '%d duplicate skipped.',
                    '%d duplicates skipped.',
                    $skipped,
                    'security-ninja'
                ),
                $skipped
             );
        }
        wp_send_json_success( array(
            'message' => trim( $message ),
            'data'    => $result,
        ) );
    }

    /**
     * get_banned_ips.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, June 5th, 2024.
     * @access  public static
     * @return  mixed
     */
    public static function ajax_send_unblock_email() {
        check_ajax_referer( 'wf_sn_cf' );
        if ( !current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array(
                'message' => __( 'Failed.', 'security-ninja' ),
            ) );
        }
        if ( !isset( $_POST['email'] ) ) {
            $error = new \WP_Error('001', 'No email?');
            wp_send_json_error( $error );
        }
        $sanitized_email = sanitize_email( wp_unslash( $_POST['email'] ) );
        if ( false === is_email( $sanitized_email ) ) {
            $error = new \WP_Error('002', 'Not a valid email!');
            wp_send_json_error( $error );
        }
        if ( !array_key_exists( 'unblock_url', wf_sn_cf::$options ) || '' === (string) wf_sn_cf::$options['unblock_url'] ) {
            wf_sn_cf::$options['unblock_url'] = wf_sn_cf::generate_unblock_token();
            update_option( WF_SN_CF_OPTIONS_KEY, wf_sn_cf::$options, false );
        }
        $sendresult = wf_sn_cf::send_secret_access_unblock_url( $sanitized_email );
        if ( $sendresult ) {
            wp_send_json_success( array(
                'message' => __( 'Email sent.', 'security-ninja' ),
            ) );
        } else {
            wp_send_json_error( array(
                'message' => __( 'Email could not be sent.', 'security-ninja' ),
            ) );
        }
        die;
    }

    /**
     * send_secret_access_unblock_url.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, March 16th, 2022.
     * @access  public static
     * @param   mixed   $email
     * @return  boolean
     */
    public static function register_settings() {
        register_setting( WF_SN_CF_OPTIONS_KEY, 'wf_sn_cf', array(__NAMESPACE__ . '\\wf_sn_cf', 'sanitize_settings') );
    }

    /**
     * Normalize country codes.
     *
     * When Utils::get_country_list() is available, keep only those codes.
     * When the list is empty (free build, JSON stripped), keep the sanitized
     * codes so a saved list is not wiped.
     *
     * @param mixed $value Raw codes.
     * @return string[]
     */
    private static function normalize_blocked_country_codes( $value ) {
        $raw = array();
        if ( is_array( $value ) ) {
            $raw = $value;
        } elseif ( is_string( $value ) && '' !== $value ) {
            $raw = array($value);
        }
        $codes = array();
        foreach ( $raw as $code ) {
            $code = strtoupper( sanitize_text_field( (string) $code ) );
            if ( '' === $code ) {
                continue;
            }
            $codes[] = $code;
        }
        $codes = array_values( array_unique( $codes ) );
        $known = \WPSecurityNinja\Plugin\Utils::get_country_list();
        if ( !is_array( $known ) || empty( $known ) ) {
            return $codes;
        }
        $known_codes = array();
        foreach ( array_keys( $known ) as $key ) {
            $known_codes[strtoupper( (string) $key )] = true;
        }
        $filtered = array();
        foreach ( $codes as $code ) {
            if ( isset( $known_codes[$code] ) ) {
                $filtered[] = $code;
            }
        }
        return $filtered;
    }

    /**
     * Sanitize a blocked_countries form value.
     *
     * A jump to every known country is stored only when the saved list is
     * already the full list, or when blocked_countries_confirm_all is 1.
     *
     * @param mixed $value       Submitted codes.
     * @param array $old_options Stored firewall options.
     * @param array $values      Full form submission.
     * @return string[]
     */
    private static function sanitize_blocked_countries_submission( $value, $old_options, $values ) {
        $submitted = self::normalize_blocked_country_codes( $value );
        $previous_raw = array();
        if ( isset( $old_options['blocked_countries'] ) && is_array( $old_options['blocked_countries'] ) ) {
            $previous_raw = $old_options['blocked_countries'];
        }
        $previous = self::normalize_blocked_country_codes( $previous_raw );
        $known = \WPSecurityNinja\Plugin\Utils::get_country_list();
        $known_count = ( is_array( $known ) ? count( $known ) : 0 );
        $is_every = $known_count > 0 && count( $submitted ) === $known_count;
        $was_every = $known_count > 0 && count( $previous ) === $known_count;
        $confirmed = isset( $values['blocked_countries_confirm_all'] ) && '1' === (string) $values['blocked_countries_confirm_all'];
        if ( $is_every && !$was_every && !$confirmed ) {
            add_settings_error(
                'wf_sn_cf',
                'blocked_countries_all',
                __( 'The country block list was not changed. Blocking every country needs Select All and confirmation.', 'security-ninja' ),
                'error'
            );
            return $previous_raw;
        }
        return $submitted;
    }

    /**
     * Log added and removed country codes when the block list changes.
     *
     * @param array $old_options Options before this save.
     * @param array $new_options Options after sanitizing.
     * @return void
     */
    private static function log_blocked_countries_change( $old_options, $new_options ) {
        $old_countries = array();
        if ( isset( $old_options['blocked_countries'] ) ) {
            $old_countries = self::normalize_blocked_country_codes( $old_options['blocked_countries'] );
        }
        $new_countries = array();
        if ( isset( $new_options['blocked_countries'] ) ) {
            $new_countries = self::normalize_blocked_country_codes( $new_options['blocked_countries'] );
        }
        $added = array_values( array_diff( $new_countries, $old_countries ) );
        $removed = array_values( array_diff( $old_countries, $new_countries ) );
        if ( empty( $added ) && empty( $removed ) ) {
            return;
        }
        if ( !method_exists( __NAMESPACE__ . '\\wf_sn_el_modules', 'log_event' ) ) {
            return;
        }
        wf_sn_el_modules::log_event(
            'security_ninja',
            'blocked_countries',
            sprintf( 
                /* translators: 1: number of country codes added, 2: number removed. */
                __( 'Country block list updated. Added %1$d, removed %2$d.', 'security-ninja' ),
                count( $added ),
                count( $removed )
             ),
            array(
                'added'   => $added,
                'removed' => $removed,
            )
        );
    }

    /**
     * Valid visitor IP source modes (stored in wf_sn_cf['ip_source']).
     *
     * @return string[]
     */
    public static function sanitize_settings( $values ) {
        // Handle null or non-array values (WordPress may call this with null)
        if ( !is_array( $values ) ) {
            // Return existing options normalized
            $old_options = get_option( 'wf_sn_cf', array() );
            if ( !is_array( $old_options ) ) {
                $old_options = array();
            }
            // Normalize existing boolean values
            $boolean_keys = array(
                'active',
                'globalbannetwork',
                'global',
                'filterqueries',
                'trackvisits',
                'usecloud',
                'protect_login_form',
                'hide_login_errors',
                'failed_login_email_warning',
                'countryblock_loginonly',
                'whitelist_managewp',
                'whitelist_uptimerobot',
                'whitelist_wprocket',
                'whitelist_uptimia',
                '2fa_enabled',
                '2fa_backup_codes_enabled',
                '404guard_enabled',
                'woo_rate_limiting_enabled',
                'woo_coupon_protection_enabled',
                'change_login_url',
                'blockadminlogin'
            );
            foreach ( $boolean_keys as $key ) {
                if ( isset( $old_options[$key] ) ) {
                    $old_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] );
                }
            }
            return $old_options;
        }
        // Get existing options first (like Events Logger does)
        $old_options = get_option( 'wf_sn_cf', array() );
        if ( !is_array( $old_options ) ) {
            $old_options = array();
        }
        // Start with existing options, then merge with form values
        $new_options = $old_options;
        $defaults = array(
            'active'                        => 0,
            'globalbannetwork'              => 1,
            'global'                        => 1,
            'filterqueries'                 => 1,
            'trackvisits'                   => 0,
            'trackvisits_howlong'           => 7,
            'usecloud'                      => 1,
            'protect_login_form'            => 1,
            'hide_login_errors'             => 1,
            'failed_login_email_warning'    => 0,
            'blocked_countries'             => array(),
            'countryblock_loginonly'        => 0,
            'blacklist'                     => array(),
            'whitelist'                     => array(wf_sn_cf::get_user_ip()),
            'blacklist_notes'               => array(),
            'whitelist_notes'               => array(),
            'whitelist_managewp'            => 1,
            'whitelist_wprocket'            => 0,
            'whitelist_uptimia'             => 0,
            'whitelist_uptimerobot'         => 0,
            'max_login_attempts'            => 5,
            'max_login_attempts_time'       => 5,
            'bruteforce_ban_time'           => 120,
            'login_msg'                     => __( 'Warning: Multiple failed login attempts will get you locked out temporarily.', 'security-ninja' ),
            'login_error_msg'               => __( 'Something went wrong', 'security-ninja' ),
            'message'                       => __( 'You are not allowed to visit this website.', 'security-ninja' ),
            'redirect_url'                  => '',
            'blockadminlogin'               => 0,
            'change_login_url'              => 0,
            'new_login_url'                 => 'my-login',
            'unblock_url'                   => '',
            '2fa_required_roles'            => array(),
            '2fa_methods'                   => array(),
            '2fa_enabled'                   => 0,
            '2fa_enabled_timestamp'         => '',
            '2fa_backup_codes_enabled'      => 0,
            '2fa_grace_period'              => 14,
            '2fa_intro'                     => '',
            '2fa_enter_code'                => '',
            '404guard_enabled'              => 1,
            '404guard_threshold'            => 10,
            '404guard_window'               => 300,
            '404guard_block_time'           => 600,
            'woo_rate_limiting_enabled'     => 0,
            'woo_checkout_rate_limit'       => 3,
            'woo_checkout_window'           => 300,
            'woo_add_to_cart_limit'         => 10,
            'woo_add_to_cart_window'        => 60,
            'woo_order_rate_limit'          => 2,
            'woo_order_window'              => 600,
            'woo_coupon_protection_enabled' => 0,
            'woo_coupon_failed_attempts'    => 5,
            'woo_coupon_window'             => 300,
            'woo_coupon_ban_time'           => 900,
            'satellite_soft_enabled'        => 1,
            'satellite_soft_asns'           => array('14593'),
            'ip_source'                     => 'auto',
            'trusted_proxy_cidrs'           => array(),
        );
        $current_options = wf_sn_cf::get_options();
        $old_2fa_status = $current_options['2fa_enabled'];
        // List of all boolean/flag settings that should be normalized to 0/1
        $boolean_keys = array(
            'active',
            'globalbannetwork',
            'global',
            'filterqueries',
            'trackvisits',
            'usecloud',
            'protect_login_form',
            'hide_login_errors',
            'failed_login_email_warning',
            'countryblock_loginonly',
            'satellite_soft_enabled',
            'whitelist_managewp',
            'whitelist_uptimerobot',
            'whitelist_wprocket',
            'whitelist_uptimia',
            'whitelist_uptimerobot',
            '2fa_enabled',
            '2fa_backup_codes_enabled',
            '404guard_enabled',
            'woo_rate_limiting_enabled',
            'woo_coupon_protection_enabled',
            'change_login_url',
            'blockadminlogin'
        );
        // Handle boolean keys
        // Fields that are always in the form (free features): filterqueries
        // If these are missing from form submission, they're unchecked = 0
        // Premium-only fields might not be in form for free users, so preserve existing
        $always_in_form_keys = array('filterqueries');
        // Free features / always-in-form toggles (failed_login_email_warning moved to Login tab)
        foreach ( $boolean_keys as $key ) {
            if ( isset( $values[$key] ) ) {
                // Value is in form submission - normalize it
                $new_options[$key] = \WPSecurityNinja\Plugin\Utils::normalize_flag( $values[$key] );
            } elseif ( 'active' === $key ) {
                // 'active' is a hidden field - preserve existing value if not in form
                $new_options[$key] = ( isset( $old_options[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] ) : (( isset( $defaults[$key] ) ? $defaults[$key] : 0 )) );
            } elseif ( in_array( $key, $always_in_form_keys, true ) ) {
                // Field is always in form - missing = unchecked = 0
                $new_options[$key] = 0;
            } else {
                // Premium-only field or field that might not be in form - preserve existing
                $new_options[$key] = ( isset( $old_options[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $old_options[$key] ) : (( isset( $defaults[$key] ) ? $defaults[$key] : 0 )) );
            }
        }
        // Process all other form values (non-boolean)
        foreach ( $values as $key => $value ) {
            // Skip boolean keys as they're already handled above
            if ( in_array( $key, $boolean_keys, true ) ) {
                continue;
            }
            if ( array_key_exists( $key, $defaults ) ) {
                switch ( $key ) {
                    case '2fa_required_roles':
                    case '2fa_methods':
                        if ( is_array( $value ) ) {
                            $new_options[$key] = array_map( 'sanitize_text_field', $value );
                        } else {
                            $new_options[$key] = sanitize_text_field( $value );
                        }
                        break;
                    case 'blocked_countries':
                        $new_options['blocked_countries'] = self::sanitize_blocked_countries_submission( $value, $old_options, $values );
                        break;
                    case 'blacklist':
                    case 'whitelist':
                        if ( !is_array( $value ) && is_string( $value ) ) {
                            // Split the string into an array by line breaks
                            $ips = explode( "\n", $value );
                            // Trim whitespace, sanitize each IP address or CIDR, and ensure uniqueness
                            $new_options[$key] = array_unique( array_filter( array_map( function ( $ip ) {
                                $sanitized_ip = sanitize_text_field( trim( $ip ) );
                                if ( filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                                    return $sanitized_ip;
                                }
                                if ( strpos( $sanitized_ip, '/' ) !== false && wf_sn_cf::isValidCIDR( $sanitized_ip ) ) {
                                    return $sanitized_ip;
                                }
                                // Return null if invalid to filter it out
                                return null;
                            }, $ips ), function ( $ip ) {
                                return !is_null( $ip );
                            } ) );
                        } elseif ( is_array( $value ) ) {
                            // If it's already an array, sanitize and validate each entry
                            $new_options[$key] = array_unique( array_filter( array_map( function ( $ip ) {
                                $sanitized_ip = sanitize_text_field( trim( $ip ) );
                                // Validate IP or CIDR using your existing function
                                if ( filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || filter_var( $sanitized_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) || strpos( $sanitized_ip, '/' ) !== false && wf_sn_cf::isValidCIDR( $sanitized_ip ) ) {
                                    return $sanitized_ip;
                                }
                                return null;
                            }, $value ), function ( $ip ) {
                                return !is_null( $ip );
                            } ) );
                        } else {
                            // If the value is neither a string nor an array, set an empty array
                            $new_options[$key] = array();
                        }
                        break;
                    case '2fa_grace_period':
                    case 'max_login_attempts':
                    case 'max_login_attempts_time':
                    case 'bruteforce_ban_time':
                    case 'trackvisits_howlong':
                        // number of days to track visits
                        $new_options[$key] = intval( $value );
                        break;
                    case '404guard_threshold':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 5, maximum 50
                        if ( $new_options[$key] < 5 ) {
                            $new_options[$key] = 5;
                        } elseif ( $new_options[$key] > 50 ) {
                            $new_options[$key] = 50;
                        }
                        break;
                    case '404guard_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 60 seconds (1 minute), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 60 ) {
                            $new_options[$key] = 60;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    case '404guard_block_time':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 86400 seconds (24 hours)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 86400 ) {
                            $new_options[$key] = 86400;
                        }
                        break;
                    // WooCommerce protection options
                    case 'woo_rate_limiting_enabled':
                    case 'woo_coupon_protection_enabled':
                        // These are boolean keys, already handled above - skip
                        break;
                    case 'woo_checkout_rate_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 2, maximum 10
                        if ( $new_options[$key] < 2 ) {
                            $new_options[$key] = 2;
                        } elseif ( $new_options[$key] > 10 ) {
                            $new_options[$key] = 10;
                        }
                        break;
                    case 'woo_checkout_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 180 seconds (3 minutes), maximum 1800 seconds (30 minutes)
                        if ( $new_options[$key] < 180 ) {
                            $new_options[$key] = 180;
                        } elseif ( $new_options[$key] > 1800 ) {
                            $new_options[$key] = 1800;
                        }
                        break;
                    case 'woo_add_to_cart_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 5, maximum 20
                        if ( $new_options[$key] < 5 ) {
                            $new_options[$key] = 5;
                        } elseif ( $new_options[$key] > 20 ) {
                            $new_options[$key] = 20;
                        }
                        break;
                    case 'woo_add_to_cart_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 30 seconds, maximum 300 seconds (5 minutes)
                        if ( $new_options[$key] < 30 ) {
                            $new_options[$key] = 30;
                        } elseif ( $new_options[$key] > 300 ) {
                            $new_options[$key] = 300;
                        }
                        break;
                    case 'woo_order_rate_limit':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 1, maximum 5
                        if ( $new_options[$key] < 1 ) {
                            $new_options[$key] = 1;
                        } elseif ( $new_options[$key] > 5 ) {
                            $new_options[$key] = 5;
                        }
                        break;
                    case 'woo_order_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    // Coupon protection options
                    case 'woo_coupon_failed_attempts':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 3, maximum 15
                        if ( $new_options[$key] < 3 ) {
                            $new_options[$key] = 3;
                        } elseif ( $new_options[$key] > 15 ) {
                            $new_options[$key] = 15;
                        }
                        break;
                    case 'woo_coupon_window':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 180 seconds (3 minutes), maximum 1800 seconds (30 minutes)
                        if ( $new_options[$key] < 180 ) {
                            $new_options[$key] = 180;
                        } elseif ( $new_options[$key] > 1800 ) {
                            $new_options[$key] = 1800;
                        }
                        break;
                    case 'woo_coupon_ban_time':
                        $new_options[$key] = intval( $value );
                        // Sanity check: minimum 300 seconds (5 minutes), maximum 3600 seconds (1 hour)
                        if ( $new_options[$key] < 300 ) {
                            $new_options[$key] = 300;
                        } elseif ( $new_options[$key] > 3600 ) {
                            $new_options[$key] = 3600;
                        }
                        break;
                    case '2fa_intro':
                    case '2fa_enter_code':
                    case '2fa_enabled_timestamp':
                    case 'login_msg':
                    case 'login_error_msg':
                    case 'message':
                    case 'new_login_url':
                        $new_options[$key] = sanitize_text_field( $value );
                        break;
                    case 'redirect_url':
                        $new_options[$key] = esc_url_raw( $value );
                        break;
                    case 'satellite_soft_asns':
                        $raw = ( is_string( $value ) ? $value : '' );
                        $parts = preg_split(
                            '/[\\s,]+/',
                            $raw,
                            -1,
                            PREG_SPLIT_NO_EMPTY
                        );
                        $out = array();
                        foreach ( $parts as $p ) {
                            $p = trim( $p );
                            if ( preg_match( '/^\\d+$/', $p ) ) {
                                $out[] = $p;
                            }
                        }
                        if ( empty( $out ) ) {
                            $out = array('14593');
                        }
                        $new_options['satellite_soft_asns'] = array_unique( $out );
                        break;
                    case 'ip_source':
                        $new_options['ip_source'] = wf_sn_cf::normalize_ip_source( $value );
                        break;
                    case 'trusted_proxy_cidrs':
                        $new_options['trusted_proxy_cidrs'] = wf_sn_cf::sanitize_trusted_proxy_cidrs( $value );
                        break;
                    default:
                        $new_options[$key] = sanitize_text_field( $value );
                        break;
                }
            }
            // Keys not in defaults are ignored (not added to new_options).
        }
        // // Check for user IP whitelisting if the firewall is active
        // $user_ip = wf_sn_cf::get_user_ip();
        // if (isset($new_options['active']) && $new_options['active'] && !in_array($user_ip, $new_options['whitelist'], true)) {
        //  $new_options['whitelist'][] = $user_ip;
        // }
        // Handle 404 Guard status changes
        $old_404guard_status = (int) ($current_options['404guard_enabled'] ?? 0);
        $new_404guard_status = (int) ($new_options['404guard_enabled'] ?? 0);
        $current_twofa_status = (int) ($current_options['2fa_enabled'] ?? 0);
        // If the 2fa_enabled is set to 1 and it used to be 0, set the timestamp '2fa_enabled_timestamp' to the current time
        $old_2fa_status = $current_twofa_status;
        // Check if 2FA was just enabled
        if ( isset( $new_options['2fa_enabled'] ) && (int) $new_options['2fa_enabled'] === 1 && $old_2fa_status === 0 ) {
            $new_options['2fa_enabled_timestamp'] = current_time( 'timestamp' );
            wf_sn_cf::clear_2fa_user_meta_on_first_enable();
        }
        // Ensure a non-empty login URL if the change login URL feature is active
        if ( class_exists( __NAMESPACE__ . '\\SecNin_Rename_WP_Login' ) && isset( $new_options['change_login_url'] ) && $new_options['change_login_url'] && '' === ($new_options['new_login_url'] ?? '') ) {
            $new_options['new_login_url'] = \WPSecurityNinja\Plugin\SecNin_Rename_WP_Login::$default_login_url;
        }
        // Merge sanitized values with defaults to ensure all settings are complete and valid
        // Use $new_options which already has existing values preserved for missing keys
        $merged = array_merge( $defaults, $new_options );
        $two_fa_on = !empty( $merged['2fa_enabled'] );
        $merged['2fa_required_roles'] = wf_sn_cf::normalize_2fa_required_roles( $merged['2fa_required_roles'] ?? array(), $two_fa_on );
        $merged['2fa_methods'] = wf_sn_cf::normalize_2fa_methods( $merged['2fa_methods'] ?? array() );
        self::log_blocked_countries_change( $old_options, $merged );
        return $merged;
    }

    /**
     * add new tab
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   mixed   $tabs
     * @return  mixed
     */
    public static function sn_tabs( $tabs ) {
        $core_tab = array(
            'id'       => 'sn_cf',
            'class'    => '',
            'label'    => 'Firewall',
            'callback' => array(__NAMESPACE__ . '\\wf_sn_cf', 'do_page'),
        );
        $done = 0;
        $tabs_count = count( $tabs );
        for ($i = 0; $i < $tabs_count; $i++) {
            if ( 'sn_cf' === $tabs[$i]['id'] ) {
                $tabs[$i] = $core_tab;
                $done = 1;
                break;
            }
        }
        if ( !$done ) {
            $tabs[] = $core_tab;
        }
        $login_tab_class = 'profeature';
        $login_tab = array(
            'id'       => 'sn_login',
            'class'    => $login_tab_class,
            'label'    => esc_html__( 'Login', 'security-ninja' ),
            'callback' => array(__NAMESPACE__ . '\\wf_sn_cf', 'do_login_page'),
        );
        $inserted = false;
        foreach ( $tabs as $idx => $tab ) {
            if ( isset( $tab['id'] ) && $tab['id'] === 'sn_cf' ) {
                array_splice(
                    $tabs,
                    $idx + 1,
                    0,
                    array($login_tab)
                );
                $inserted = true;
                break;
            }
        }
        if ( !$inserted ) {
            $tabs[] = $login_tab;
        }
        return $tabs;
    }

    /**
     * Renders the Login top-level tab (login protection settings or upgrade notice).
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, March 10th, 2025.
     * @access  public static
     * @return  void
     */
    public static function do_login_page() {
        if ( is_null( wf_sn_cf::$options ) ) {
            wf_sn_cf::$options = wf_sn_cf::get_options();
        }
        if ( get_transient( 'secnin_2fa_optin_only_notice' ) ) {
            delete_transient( 'secnin_2fa_optin_only_notice' );
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Two-factor authentication is enabled but no roles are required. Users can opt in from their profile; nobody will be forced to set up 2FA.', 'security-ninja' ) . '</p></div>';
        }
        if ( get_transient( 'secnin_2fa_methods_empty_notice' ) ) {
            delete_transient( 'secnin_2fa_methods_empty_notice' );
            echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'At least one 2FA method must be selected. Your previous method settings were kept.', 'security-ninja' ) . '</p></div>';
        }
        ?>
		<div class="sncard settings-card">
			<h2><span class="dashicons dashicons-lock"></span> <?php 
        esc_html_e( 'Login', 'security-ninja' );
        ?></h2>
			<p><?php 
        esc_html_e( 'Protect your login page from brute force attacks, enable 2FA, and customize your login URL.', 'security-ninja' );
        ?></p>
		<?php 
        $show_login_upsell = true;
        if ( $show_login_upsell ) {
            ?>
			<div class="sncard infobox">
				<div class="inner">
					<h3>Upgrade to Pro for Login Protection</h3>
					<p>Upgrade to Security Ninja Pro to unlock powerful login protection features:</p>
					<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
						<li>Advanced login form protection with brute force detection</li>
						<li>Auto-ban rules for failed login attempts</li>
						<li>Block "admin" username login attempts</li>
						<li>Hide login errors to prevent username enumeration</li>
						<li>Email warnings for failed login attempts</li>
						<li>Change login URL to hide wp-login.php</li>
						<li>Two-Factor Authentication (2FA) for enhanced security</li>
					</ul>
					<p style="margin-top: 15px;">
						<a href="<?php 
            echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
            ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
            esc_html_e( 'Upgrade to Pro', 'security-ninja' );
            ?></a>
					</p>
				</div>
			</div>
			<?php 
        }
        echo '</div>';
    }

    /**
     * Handles saving of login protection settings (admin_post handler).
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, March 10th, 2025.
     * @access  public static
     * @return  void
     */
    public static function save_login_settings() {
        if ( !isset( $_POST['sn_login_nonce'] ) || !wp_verify_nonce( sanitize_key( wp_unslash( $_POST['sn_login_nonce'] ) ), 'sn_save_login_settings' ) ) {
            wp_die( 'Security check failed.' );
        }
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions.' );
        }
        $values = ( isset( $_POST['wf_sn_cf'] ) && is_array( $_POST['wf_sn_cf'] ) ? wp_unslash( $_POST['wf_sn_cf'] ) : array() );
        $existing = get_option( 'wf_sn_cf', array() );
        if ( !is_array( $existing ) ) {
            $existing = array();
        }
        $boolean_keys = array(
            'protect_login_form',
            'hide_login_errors',
            'failed_login_email_warning',
            'change_login_url',
            'blockadminlogin',
            '2fa_enabled',
            '2fa_backup_codes_enabled'
        );
        foreach ( $boolean_keys as $key ) {
            $existing[$key] = ( isset( $values[$key] ) ? \WPSecurityNinja\Plugin\Utils::normalize_flag( $values[$key] ) : 0 );
        }
        $int_keys = array(
            'max_login_attempts'      => array(1, 100),
            'max_login_attempts_time' => array(1, 60),
            'bruteforce_ban_time'     => array(2, 5256000),
            '2fa_grace_period'        => array(0, 90),
        );
        foreach ( $int_keys as $key => $bounds ) {
            if ( isset( $values[$key] ) ) {
                $v = intval( $values[$key] );
                $existing[$key] = max( $bounds[0], min( $bounds[1], $v ) );
            }
        }
        $text_keys = array(
            'login_msg',
            'login_error_msg',
            'new_login_url',
            '2fa_intro',
            '2fa_enter_code'
        );
        foreach ( $text_keys as $key ) {
            if ( array_key_exists( $key, $values ) ) {
                $existing[$key] = sanitize_text_field( $values[$key] );
            }
        }
        if ( !empty( $values['2fa_required_roles_present'] ) ) {
            if ( isset( $values['2fa_required_roles'] ) && is_array( $values['2fa_required_roles'] ) ) {
                $existing['2fa_required_roles'] = array_map( 'sanitize_text_field', $values['2fa_required_roles'] );
            } else {
                $existing['2fa_required_roles'] = array();
            }
        }
        if ( !empty( $values['2fa_methods_present'] ) ) {
            $methods = self::sanitize_2fa_methods_list( $values['2fa_methods'] ?? array() );
            if ( empty( $methods ) ) {
                set_transient( 'secnin_2fa_methods_empty_notice', 1, MINUTE_IN_SECONDS );
            } else {
                $existing['2fa_methods'] = $methods;
            }
        } elseif ( isset( $values['2fa_methods'] ) ) {
            $existing['2fa_methods'] = wf_sn_cf::normalize_2fa_methods( $values['2fa_methods'] );
        }
        $current_options = wf_sn_cf::get_options();
        $old_2fa = (int) (( isset( $current_options['2fa_enabled'] ) ? $current_options['2fa_enabled'] : 0 ));
        if ( isset( $existing['2fa_enabled'] ) && (int) $existing['2fa_enabled'] === 1 && $old_2fa === 0 ) {
            $existing['2fa_enabled_timestamp'] = (string) current_time( 'timestamp' );
            wf_sn_cf::clear_2fa_user_meta_on_first_enable();
        }
        if ( !empty( $existing['change_login_url'] ) && '' === ($existing['new_login_url'] ?? '') ) {
            $existing['new_login_url'] = ( class_exists( __NAMESPACE__ . '\\SecNin_Rename_WP_Login' ) ? \WPSecurityNinja\Plugin\SecNin_Rename_WP_Login::$default_login_url : 'my-login' );
        }
        if ( isset( $existing['new_login_url'] ) && $existing['new_login_url'] !== '' ) {
            $existing['new_login_url'] = preg_replace( '/[^a-zA-Z0-9_-]/', '', $existing['new_login_url'] );
            if ( $existing['new_login_url'] === '' ) {
                $existing['new_login_url'] = 'my-login';
            }
        }
        if ( isset( $current_options['unblock_url'] ) && $current_options['unblock_url'] !== '' ) {
            $existing['unblock_url'] = $current_options['unblock_url'];
        }
        $two_fa_on = !empty( $existing['2fa_enabled'] );
        $existing['2fa_required_roles'] = wf_sn_cf::normalize_2fa_required_roles( $existing['2fa_required_roles'] ?? array(), $two_fa_on );
        $existing['2fa_methods'] = wf_sn_cf::normalize_2fa_methods( $existing['2fa_methods'] ?? array() );
        if ( $two_fa_on && empty( $existing['2fa_required_roles'] ) ) {
            set_transient( 'secnin_2fa_optin_only_notice', 1, MINUTE_IN_SECONDS );
        }
        update_option( 'wf_sn_cf', $existing, false );
        do_action( 'security_ninja_firewall_settings_saved' );
        wf_sn_cf::$options = null;
        wp_safe_redirect( admin_url( 'admin.php?page=wf-sn&settings-updated=1#sn_login' ) );
        exit;
    }

    /**
     * add custom message to overlay
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function do_page() {
        global $wpdb;
        $ips = get_option( 'wf_sn_cf_ips' );
        if ( !is_array( $ips ) ) {
            $ips = array();
        }
        $cloud_total = ( array_key_exists( 'total', $ips ) ? max( 0, (int) $ips['total'] ) : Wf_sn_cf_Utils::count_cloud_list_addresses( $ips ) );
        $banned_ips = wf_sn_cf::get_banned_ips();
        $banned_ips_count = ( is_array( $banned_ips ) ? count( $banned_ips ) : 0 );
        $ips['total'] = $cloud_total + $banned_ips_count;
        ?>
		<div class="sncard settings-card">
			<h2><span class="dashicons dashicons-shield-alt"></span> <?php 
        esc_html_e( 'Firewall', 'security-ninja' );
        ?></h2>
			<p>Protect your website from malicious traffic and attacks</p>

			<div id="snfwtop">
				<div class="col left">
					<?php 
        $blocked_count = get_option( 'wf_sn_cf_blocked_count' );
        if ( $blocked_count ) {
            ?>
						<div class="snfw-blocked-count">Total Blocked Visits <div class="val"><?php 
            echo number_format_i18n( $blocked_count );
            ?></div>
						</div>
						<?php 
        }
        if ( 1 === wf_sn_cf::is_active() ) {
            echo '<input type="button" value="' . __( 'Disable Firewall', 'security-ninja' ) . '" id="sn-disable-firewall" class="button snbutton" />';
        } else {
            echo '<input type="button" value="' . __( 'Enable Firewall', 'security-ninja' ) . '" id="sn-enable-firewall-overlay" class="button button-primary button-hero sn-cta wf-sn-button"/>';
        }
        ?>

				</div>
				<div class="col right">
				<?php 
        if ( 1 === wf_sn_cf::is_active() ) {
            echo '<h3>' . esc_html__( 'Secret Access URL', 'security-ninja' ) . '</h3>';
            ?>
						<input type="text" id="sn-unblock-url" value="<?php 
            echo esc_url( wf_sn_cf::get_unblock_url() );
            ?>" disabled>
						<?php 
            echo '<p class="description">' . esc_html__( 'Do not share this URL! Use it only to access your website if your IP gets banned.', 'security-ninja' ) . '</p>';
        } else {
            echo '<h3>' . esc_html__( 'Firewall is not active', 'security-ninja' ) . '</h3>';
            echo '<p>' . esc_html__( 'Activating the firewall enables protection against outside threats trying to access your website.', 'security-ninja' ) . '</p>';
        }
        ?>
				</div>
			</div>


			<?php 
        global $secnin_fs;
        if ( 1 === wf_sn_cf::is_active() ) {
            echo '</div>';
            echo '<div class="sncard settings-card">';
            echo '<form action="options.php" id="sn-firewall-settings-form" method="post">';
            settings_fields( 'wf_sn_cf' );
            ?>
		<div class="wf-sn-tab-content">
			<div class="nav-tab-wrapper" id="wf-sn-cf-subtabs">
				<a href="#sn_cf_settings" class="nav-tab nav-tab-active">Settings</a>
				<?php 
            $can_use_premium = false;
            $pro_class = ( $can_use_premium ? '' : ' profeature' );
            ?>
				<a href="#sn_cf_visitors" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">Visitor Logging</a>
				<a href="#sn_cf_ip" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">IP Management</a>
				<a href="#sn_cf_404guard" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>">404 Guard</a>
				<a href="#sn_cf_woocommerce" class="nav-tab<?php 
            echo esc_attr( $pro_class );
            ?>"><?php 
            esc_html_e( 'Store', 'security-ninja' );
            ?></a>
			</div>

			<div id="sn_cf_settings" class="wf-sn-subtab">
				<?php 
            // Include settings content from separate file
            $settings_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/tabs/settings.php';
            if ( file_exists( $settings_file ) ) {
                require_once $settings_file;
                wf_sn_cf_render_settings_content( wf_sn_cf::$options, $ips );
            }
            ?>
			</div>

			<div id="sn_cf_visitors" class="wf-sn-subtab">
				<?php 
            $sn_cf_show_visitor_upgrade = true;
            if ( $sn_cf_show_visitor_upgrade ) {
                ?>
					<table class="form-table">
						<tbody>
							<tr>
								<td colspan="2">
									<div class="sncard infobox">
										<div class="inner">
											<h3>Upgrade to Pro for Visitor Logging</h3>
											<p>The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock visitor logging features:</p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li>Track all visitors and page requests</li>
												<li>Visitor logging with geolocation data</li>
												<li>Detailed visitor analytics and insights</li>
												<li>Customizable log retention periods</li>
											</ul>
											<p style="margin-top: 15px;">
												<a href="<?php 
                echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
                ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Upgrade to Pro', 'security-ninja' );
                ?></a>
											</p>
										</div>
									</div>
								</td>
							</tr>
						</tbody>
					</table>
					<?php 
            }
            ?>
			</div>

			<div id="sn_cf_ip" class="wf-sn-subtab">
				<?php 
            $sn_cf_show_ip_upgrade = true;
            if ( $sn_cf_show_ip_upgrade ) {
                ?>
					<table class="form-table">
						<tbody>
							<tr>
								<td colspan="2">
									<div class="sncard infobox">
										<div class="inner">
											<h3>Upgrade to Pro for IP Management</h3>
											<p>The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock advanced IP management features:</p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li>Manual IP blacklist and whitelist management</li>
												<li>Automatic whitelisting for WP Rocket, Uptimia, UptimeRobot, and ManageWP</li>
												<li>View and manage locally banned IPs</li>
												<li>Test IP addresses to check ban status</li>
												<li>Clear banned IP lists with one click</li>
											</ul>
											<p style="margin-top: 15px;">
												<a href="<?php 
                echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
                ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Upgrade to Pro', 'security-ninja' );
                ?></a>
											</p>
										</div>
									</div>
								</td>
							</tr>
						</tbody>
					</table>
					<?php 
            }
            ?>
			</div>

			<div id="sn_cf_404guard" class="wf-sn-subtab">
				<?php 
            $sn_cf_show_404guard_upgrade = true;
            if ( $sn_cf_show_404guard_upgrade ) {
                ?>
					<table class="form-table">
						<tbody>
							<tr>
								<td colspan="2">
									<div class="sncard infobox">
										<div class="inner">
											<h3>Upgrade to Pro for 404 Guard</h3>
											<p>The free version provides basic firewall protection. Upgrade to Security Ninja Pro to unlock 404 Guard features:</p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li>Block IPs that generate excessive 404 errors</li>
												<li>Prevent bots from scanning your site for vulnerabilities</li>
												<li>Configurable threshold and time window settings</li>
												<li>Automatic whitelisting of search engines and crawlers</li>
												<li>Temporary blocks that automatically expire</li>
												<li>Comprehensive logging of all blocked IPs</li>
											</ul>
											<p style="margin-top: 15px;">
												<a href="<?php 
                echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
                ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Upgrade to Pro', 'security-ninja' );
                ?></a>
											</p>
										</div>
									</div>
								</td>
							</tr>
						</tbody>
					</table>
					<?php 
            }
            ?>
			</div>

			<div id="sn_cf_woocommerce" class="wf-sn-subtab">
				<?php 
            $sn_cf_show_woocommerce_upgrade = true;
            if ( $sn_cf_show_woocommerce_upgrade ) {
                ?>
					<table class="form-table">
						<tbody>
							<tr>
								<td colspan="2">
									<div class="sncard infobox">
										<div class="inner">
											<h3><?php 
                esc_html_e( 'Upgrade to Pro for Store Protection', 'security-ninja' );
                ?></h3>
											<p><?php 
                esc_html_e( 'Upgrade to Security Ninja Pro to unlock store protection for WooCommerce and SureCart:', 'security-ninja' );
                ?></p>
											<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
												<li><?php 
                esc_html_e( 'Rate limiting for checkout, cart, and order placement', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Coupon / promotion code brute force protection with temporary bans', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Automatic blocking of suspicious IPs', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Comprehensive logging of all security events', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Safe for legitimate customers with conservative default settings', 'security-ninja' );
                ?></li>
												<li><?php 
                esc_html_e( 'Configurable thresholds for different store sizes', 'security-ninja' );
                ?></li>
											</ul>
											<p style="margin-top: 15px;">
												<a href="<?php 
                echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
                ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Upgrade to Pro', 'security-ninja' );
                ?></a>
											</p>
										</div>
									</div>
								</td>
							</tr>
						</tbody>
					</table>
					<?php 
            }
            ?>
			</div>
		</div>


		<p class="submit"><br><input type="submit" value="<?php 
            echo esc_html__( 'Save Changes', 'security-ninja' );
            ?>" class="input-button button-primary" name="Submit" /></p>
		</form>
		</div>
				<?php 
        } else {
            $sn_cf_show_inactive_upgrade = true;
            if ( $sn_cf_show_inactive_upgrade ) {
                ?>
				<div class="sncard infobox">
					<div class="inner">
						<h3>Upgrade to Pro for Advanced Firewall Features</h3>
						<p>The free version provides basic firewall protection with 8G rules. Upgrade to Security Ninja Pro to unlock powerful advanced features:</p>
						<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
							<li>Control how banned IPs are handled - block completely or only from login</li>
							<li>Cloud Firewall with 600+ million known bad IPs, automatically updated</li>
							<li>Participate in global IP threat network and share threat intelligence</li>
							<li>Block entire countries from accessing your website</li>
							<li>Customize messages shown to blocked visitors</li>
							<li>Redirect blocked visitors to any URL using 301 redirects</li>
						</ul>
						<p style="margin-top: 15px;">
							<a href="<?php 
                echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'firewall_upgrade', '/upgrade/' ) );
                ?>" class="button button-primary button-small" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Upgrade to Pro', 'security-ninja' );
                ?></a>
						</p>
					</div>
				</div>
					<?php 
            }
            ?>
		</div>
				<?php 
        }
        // Only show modal if firewall is not active
        if ( 1 !== wf_sn_cf::is_active() ) {
            ?>
	<div id="sn-firewall-modal" class="sn-modal">
		<div class="sn-modal-content">
			<h2><?php 
            esc_html_e( 'Enable Firewall', 'security-ninja' );
            ?></h2>
			<p><?php 
            esc_html_e( 'To ensure you can regain access to your website if you get blocked, please enter your email address. You will be sent a secret access URL to help you regain access.', 'security-ninja' );
            ?></p>

			<div class="sn-input-container">
				<input
					type="email"
					id="sn-firewall-email"
					autocomplete="off"
					placeholder="<?php 
            esc_attr_e( 'Enter your email', 'security-ninja' );
            ?>"
					value="<?php 
            echo esc_attr( wp_get_current_user()->user_email );
            ?>"
					required
					data-1p-ignore
					data-lpignore="true">
				<div class="sn-buttons">
					<a href="#" id="sn-modal-continue" class="button button-large button-primary sn-cta">
						<?php 
            esc_html_e( 'Send email', 'security-ninja' );
            ?>
					</a>
					<a href="#" id="sn-modal-skip" class="button button-large button-secondary">
						<?php 
            esc_html_e( 'Activate, but no email', 'security-ninja' );
            ?>
					</a>
				</div>
			</div>


			<div id="sn-unblock-message"></div>
			<div id="sn-firewall-status"></div>
		</div>
	</div>
				<?php 
        }
        ?>


		<?php 
    }

    /**
     * Whether a ban should only apply on login-related URLs (frontend allowed).
     *
     * Country bans: login-only when countryblock_loginonly is ON.
     * IP/cloud bans: login-only when global is OFF.
     *
     * @author  Lars Koudal
     * @since   5.289
     * @param   string $ban_reason Ban reason from is_banned_ip().
     * @return  bool True when non-login requests should be allowed.
     */
}
