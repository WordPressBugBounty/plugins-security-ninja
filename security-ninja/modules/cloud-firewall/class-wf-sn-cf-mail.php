<?php

/**
 * Cloud Firewall mail helpers (secret access + failed-login warning).
 *
 * Free-shipping. Loaded on demand from wf_sn_cf wrappers.
 *
 * @package WPSecurityNinja\Plugin
 */
namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Cf_Mail
 */
class Wf_Sn_Cf_Mail {
    public static function send_secret_access_unblock_url( $email ) {
        if ( !$email ) {
            return false;
        }
        $sanitized_email = sanitize_email( $email );
        if ( false === is_email( $sanitized_email ) ) {
            $error = new \WP_Error('002', 'Not a valid email!');
            wp_send_json_error( $error );
        }
        $subject = __( 'Security Ninja Firewall secret access link', 'security-ninja' );
        $body = '<p>' . esc_html__( 'Thank you for installing.', 'security-ninja' ) . '</p>';
        $body .= '<p>' . esc_html__( 'Please keep this email for your records.', 'security-ninja' ) . '</p>';
        $body .= '<p>' . esc_html__( 'In the unlikely situation that your IP gets banned, you will need the secret access link.', 'security-ninja' ) . '</p>';
        $body .= '<p><strong>' . sprintf( esc_html__( 'Your secret access link is %s', 'security-ninja' ), wf_sn_cf::get_unblock_url() ) . '</strong></p>';
        $body .= '<p>' . esc_html__( 'Copy-paste this URL to your browser to whitelist your IP, allowing you to log back in.', 'security-ninja' ) . '</p>';
        $body .= '<p>' . esc_html__( 'Please keep it safe and do not share it with others. Use it only if you get blocked by the firewall.', 'security-ninja' ) . '</p>';
        $show_docs_link = true;
        if ( $show_docs_link ) {
            $sal_email_link = Utils::generate_sn_web_link( 'email_secret_access', '/docs/firewall-protection/secret-access-link/', array(
                'utm_medium' => 'email',
            ) );
            $body .= '<p><a href="' . $sal_email_link . '" target="_blank" rel="noopener">Documentation for Secret Access Link</a></p>';
        }
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $emailintrotext = 'Save your secret access link for ' . wf_sn_cf::url_to_domain( site_url() );
        $dashboardlink = admin_url( '?page=wf-sn' );
        $dashboardlinkanchor = 'Settings';
        $body .= '<p><a href="' . $dashboardlink . '" target="_blank" rel="noopener">' . $dashboardlinkanchor . '</a></p>';
        $my_replacements = array(
            '%%emailintrotext%%'      => $emailintrotext,
            '%%websitedomain%%'       => site_url(),
            '%%dashboardlink%%'       => $dashboardlink,
            '%%dashboardlinkanchor%%' => $dashboardlinkanchor,
            '%%secninlogourl%%'       => WF_SN_PLUGIN_URL . 'images/security-ninja-logo.png',
            '%%emailtitle%%'          => $subject,
            '%%sentfromtext%%'        => 'This email was sent from ' . wf_sn_cf::url_to_domain( site_url() ),
            '%%emailcontent%%'        => nl2br( $body ),
        );
        $template_path = WF_SN_PLUGIN_DIR . 'includes/email-default.php';
        // Use secure file reading with validation
        $html = Wf_Sn_Security_Utils::secure_file_get_contents( $template_path, array(
            'check_readable'     => true,
            'check_size'         => true,
            'max_size'           => 1024 * 1024,
            'check_type'         => true,
            'allowed_extensions' => array('php'),
            'check_mime'         => false,
            'check_path'         => true,
            'allowed_dirs'       => array(WF_SN_PLUGIN_DIR),
        ) );
        if ( $html === false ) {
            // Handle error - template not found
            $html = '<p>Email template not found.</p>';
        }
        foreach ( $my_replacements as $needle => $replacement ) {
            $html = str_replace( $needle, $replacement, $html );
        }
        $sendresult = wp_mail(
            $sanitized_email,
            $subject,
            $html,
            $headers
        );
        wf_sn_el_modules::log_event( 'security_ninja', 'install_wizard', 'Sent unblock URL to email ' . $sanitized_email );
        return $sendresult;
    }

    /**
     * Send failed login warning email to administrator
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 14th, 2025.
     * @access  public static
     * @param   string $username   Username that was attempted
     * @param   string $ip         IP address of the attempt
     * @param   string $user_agent User agent string
     * @return  bool True on success, false on failure
     */
    public static function send_failed_login_warning_email( $username, $ip, $user_agent ) {
        // Check if setting is enabled
        if ( empty( wf_sn_cf::$options['failed_login_email_warning'] ) ) {
            return false;
        }
        // Validate username
        if ( empty( $username ) ) {
            return false;
        }
        // Check rate limiting - prevent multiple emails for same username within 15 minutes
        $rate_limit_key = 'wf_sn_failed_login_email_' . md5( $username );
        $last_email_time = get_transient( $rate_limit_key );
        if ( $last_email_time && time() - $last_email_time < 900 ) {
            // Email was sent recently, skip
            return false;
        }
        // Get user by username
        $user = get_user_by( 'login', $username );
        // Check if user exists and is administrator
        if ( !$user || !in_array( 'administrator', (array) $user->roles, true ) ) {
            return false;
        }
        // Get user email
        $user_email = $user->user_email;
        if ( !is_email( $user_email ) ) {
            return false;
        }
        // Build email subject
        $subject = __( 'Was that you trying to log in?', 'security-ninja' );
        // Build email body
        $body = '<p>' . sprintf( 
            /* translators: 1: Username */
            __( 'Someone just tried to log in to your account with username: %s', 'security-ninja' ),
            esc_html( $username )
         ) . '</p>';
        $body .= '<p><strong>' . __( 'Details:', 'security-ninja' ) . '</strong></p>';
        $body .= '<ul>';
        $body .= '<li>' . sprintf( 
            /* translators: 1: IP address */
            __( 'IP Address: %s', 'security-ninja' ),
            esc_html( $ip )
         ) . '</li>';
        if ( !empty( $user_agent ) ) {
            $body .= '<li>' . sprintf( 
                /* translators: 1: User agent */
                __( 'User Agent: %s', 'security-ninja' ),
                esc_html( $user_agent )
             ) . '</li>';
        }
        $body .= '<li>' . sprintf( 
            /* translators: 1: Timestamp */
            __( 'Time: %s', 'security-ninja' ),
            date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) )
         ) . '</li>';
        $body .= '</ul>';
        $body .= '<p>' . __( 'If this was you, you can ignore this email. If this was not you, we recommend:', 'security-ninja' ) . '</p>';
        $body .= '<ul>';
        $body .= '<li>' . __( 'Change your password immediately', 'security-ninja' ) . '</li>';
        $body .= '<li>' . __( 'Review your account security settings', 'security-ninja' ) . '</li>';
        $body .= '<li>' . __( 'Enable two-factor authentication if available', 'security-ninja' ) . '</li>';
        $body .= '</ul>';
        $dashboardlink = admin_url( '?page=wf-sn' );
        $dashboardlinkanchor = __( 'Security Settings', 'security-ninja' );
        $body .= '<p><a href="' . esc_url( $dashboardlink ) . '" target="_blank" rel="noopener">' . esc_html( $dashboardlinkanchor ) . '</a></p>';
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $emailintrotext = sprintf( 
            /* translators: 1: Site domain */
            __( 'Failed login attempt for %s', 'security-ninja' ),
            wf_sn_cf::url_to_domain( site_url() )
         );
        $my_replacements = array(
            '%%emailintrotext%%'      => $emailintrotext,
            '%%websitedomain%%'       => site_url(),
            '%%dashboardlink%%'       => $dashboardlink,
            '%%dashboardlinkanchor%%' => $dashboardlinkanchor,
            '%%secninlogourl%%'       => WF_SN_PLUGIN_URL . 'images/security-ninja-logo.png',
            '%%emailtitle%%'          => $subject,
            '%%sentfromtext%%'        => 'This email was sent from ' . wf_sn_cf::url_to_domain( site_url() ),
            '%%emailcontent%%'        => nl2br( $body ),
        );
        $template_path = WF_SN_PLUGIN_DIR . 'includes/email-default.php';
        // Use secure file reading with validation
        $html = Wf_Sn_Security_Utils::secure_file_get_contents( $template_path, array(
            'check_readable'     => true,
            'check_size'         => true,
            'max_size'           => 1024 * 1024,
            'check_type'         => true,
            'allowed_extensions' => array('php'),
            'check_mime'         => false,
            'check_path'         => true,
            'allowed_dirs'       => array(WF_SN_PLUGIN_DIR),
        ) );
        if ( $html === false ) {
            // Handle error - template not found
            $html = '<p>Email template not found.</p>';
        }
        foreach ( $my_replacements as $needle => $replacement ) {
            $html = str_replace( $needle, $replacement, $html );
        }
        $sendresult = wp_mail(
            $user_email,
            $subject,
            $html,
            $headers
        );
        // Log the email sending event
        if ( $sendresult ) {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'failed_login_email_sent',
                sprintf( 
                    /* translators: 1: Username, 2: Email address */
                    __( 'Failed login warning email sent to %1$s (%2$s)', 'security-ninja' ),
                    esc_html( $username ),
                    esc_html( $user_email )
                 ),
                array(
                    'username'   => $username,
                    'email'      => $user_email,
                    'ip'         => $ip,
                    'user_agent' => $user_agent,
                )
            );
            // Set rate limiting transient
            set_transient( $rate_limit_key, time(), 900 );
        } else {
            wf_sn_el_modules::log_event(
                'security_ninja',
                'failed_login_email_failed',
                sprintf( 
                    /* translators: 1: Username, 2: Email address */
                    __( 'Failed to send failed login warning email to %1$s (%2$s)', 'security-ninja' ),
                    esc_html( $username ),
                    esc_html( $user_email )
                 ),
                array(
                    'username' => $username,
                    'email'    => $user_email,
                    'ip'       => $ip,
                )
            );
        }
        return $sendresult;
    }

}
