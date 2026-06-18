<?php

namespace WPSecurityNinja\Plugin;

use Wf_Sn;
if ( !defined( 'ABSPATH' ) ) {
    die;
}
class Utils {
    /**
     * Filters out any Freemius admin notices
     *
     * @author Lars Koudal
     * @author Unknown
     * @since v0.0.1
     * @version v1.0.0 Wednesday, January 13th, 2021.
     * @version v1.0.1 Thursday, July 10th, 2025.
     * @access public static
     * @param mixed $show
     * @param mixed $msg
     * @return mixed
     */
    public static function do_filter_show_admin_notice( $show, $msg ) {
        return $show;
    }

    /**
     * Do admin notices
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 12th, 2021.
     * @version v1.0.1  Tuesday, March 22nd, 2022.
     * @access  public static
     * @return  void
     */
    public static function do_admin_notices() {
        $is_sn_admin_page = \WPSecurityNinja\Plugin\Wf_Sn::is_plugin_page();
        $current_screen = get_current_screen();
        if ( !$is_sn_admin_page ) {
            return;
        }
        $wf_sn_vu_vulns_notice = get_option( 'wf_sn_vu_vulns_notice', false );
        if ( isset( $wf_sn_vu_vulns_notice ) && $wf_sn_vu_vulns_notice && '' !== $wf_sn_vu_vulns_notice ) {
            $current_screen = get_current_screen();
            // Lets not show on the wizard page
            if ( strpos( $current_screen->id, 'page_security-ninja-wizard' ) === false ) {
                ?>
				<div class="notice notice-info is-dismissible secnin-notice">
					<h3><?php 
                esc_html_e( 'Security Ninja - Vulnerability list updated!', 'security-ninja' );
                ?></h3>
					<p><?php 
                echo esc_html( $wf_sn_vu_vulns_notice );
                ?></p>
				</div>
				<?php 
                delete_option( 'wf_sn_vu_vulns_notice' );
            }
        }
        $review = get_option( 'wf_sn_review_notice' );
        $time = time();
        $load = false;
        if ( !$review ) {
            $review = array(
                'time'      => $time,
                'dismissed' => false,
            );
            $load = true;
        } elseif ( isset( $review['dismissed'] ) && !$review['dismissed'] && (isset( $review['time'] ) && $review['time'] <= $time) ) {
            $load = true;
        }
        // Hvis vi skal vise den igen
        if ( isset( $review['time'] ) ) {
            if ( $time > $review['time'] ) {
                // Vi kan godt vise den igen
                $load = true;
            }
        }
        if ( !$load ) {
            return;
        }
        // Update the review option now.
        update_option( 'wf_sn_review_notice', $review, false );
        $current_user = wp_get_current_user();
        $fname = '';
        if ( !empty( $current_user->user_firstname ) ) {
            $fname = $current_user->user_firstname;
        }
        if ( function_exists( '\\WPSecurityNinja\\Plugin\\secnin_fs' ) ) {
            if ( secnin_fs()->is_registered() ) {
                $get_user = secnin_fs()->get_user();
                $fname = $get_user->first;
            }
        }
        // We have a candidate! Output a review message.
        $timeused = __( 'a while', 'security-ninja' );
        $options = \WPSecurityNinja\Plugin\Wf_Sn::$options;
        if ( isset( $options['first_install'] ) && is_numeric( $options['first_install'] ) ) {
            $first_install = intval( $options['first_install'] );
            $timeused = human_time_diff( $first_install, time() );
        }
        $current_screen = get_current_screen();
        // Lets not show on the wizard page
        if ( false !== strpos( $current_screen->id, 'page_security-ninja-wizard' ) ) {
            return;
        }
        ?>
		<div class="notice notice-info is-dismissible wfsn-review-notice">
			<p>Hey <?php 
        echo esc_html( $fname );
        ?>, I noticed you have been using Security Ninja for
				<?php 
        echo esc_html( $timeused );
        ?> - that's awesome!</p>
			<p>Could you please do us a BIG favor and give it a 5-star rating on WordPress to help us spread the word?</p>
			<p>Thank you :-)</p>
			<p><strong>Lars Koudal,</br>wpsecurityninja.com</strong></p>
			<p>
			<ul>
				<li><a href="https://wordpress.org/support/plugin/security-ninja/reviews/?filter=5#new-post" class="wfsn-dismiss-review-notice wfsn-reviewlink button-primary" target="_blank" rel="noopener">Ok, you deserve
						it</a></li>
				<li><span class="dashicons dashicons-calendar"></span><a href="#" class="wfsn-dismiss-review-notice" target="_blank" rel="noopener">Nope, maybe later</a></li>
				<li><span class="dashicons dashicons-smiley"></span><a href="#" class="wfsn-dismiss-review-notice" target="_blank" rel="noopener">I already did</a></li>
			</ul>
			<p><small>This notice is shown every 30 days.</small></p>
		</div>
		<?php 
    }

    /**
     * signup_to_newsletter.
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, September 1st, 2021.
     * @version v1.0.1  Thursday, March 3rd, 2022.
     * @access  public static
     * @return  void
     */
    public static function signup_to_newsletter() {
        // Only show on SN pages
        $is_sn_admin_page = \WPSecurityNinja\Plugin\Wf_Sn::is_plugin_page();
        if ( !$is_sn_admin_page ) {
            return;
        }
        $current_screen = get_current_screen();
        // Lets not show on the wizard page
        if ( false !== strpos( $current_screen->id, 'page_security-ninja-wizard' ) ) {
            return;
        }
        // Check if been dismissed already
        $review = get_option( 'wf_sn_review_notice' );
        if ( $review && isset( $review['dismissed'] ) && $review['dismissed'] ) {
            return;
        }
        $current_user = wp_get_current_user();
        $admin_name = $current_user->user_firstname;
        if ( $current_user->user_lastname ) {
            $admin_name .= ' ' . $current_user->user_lastname;
        }
        if ( \PAnD::is_admin_notice_active( 'wfs-newsletter-30' ) ) {
            ?>
			<div data-dismissible="wfs-newsletter-30" class="secnin-notice sncard is-dismissible snnotice">
				<h3>Get WordPress Security Updates & Exclusive Deals</h3>
				<h4>Join 10,000+ WordPress admins getting critical security alerts, pro tips, and special offers directly in their inbox from wpsecurityninja.com</h4>
				<form class="ml-block-form" action="https://assets.mailerlite.com/jsonp/16490/forms/106309154087372203/subscribe" data-code="" method="post" target="_blank">
					<table>
						<tbody>
							<tr>
								<td>
									<input type="text" class="regular-text" data-inputmask="" name="fields[name]" placeholder="Your name" autocomplete="name" style="width:15em;" value="<?php 
            echo esc_html( $current_user->display_name );
            ?>" required="required">
								</td>
								<td>
									<input aria-label="email" aria-required="true" data-inputmask="" type="email" class="regular-text required email" data-inputmask="" name="fields[email]" placeholder="Your email" autocomplete="email" style="width:15em;" value="<?php 
            echo esc_html( $current_user->user_email );
            ?>" required="required">
								</td>
								<td>
									<button type="submit" class="button button-primary button-small">Subscribe</button>
								</td>
							</tr>
					</table>
					<input type="hidden" name="fields[signupsource]" value="Security Ninja Plugin <?php 
            echo esc_attr( self::get_plugin_version() );
            ?>">
					<input type="hidden" name="ml-submit" value="1">
					<input type="hidden" name="anticsrf" value="true">
				</form>


				<p>You can unsubscribe anytime. For more details, review our <a href="<?php 
            echo esc_url( self::generate_sn_web_link( 'newsletter_signup', '/privacy-policy/' ) );
            ?>" target="_blank" rel="noopener">Privacy Policy</a>.</p>
				<p><small>Signup form is shown every 30 days.</small> - <a href="javascript:;" class="dismiss-this">Click here to dismiss</a></p>
			</div>
			<?php 
        }
    }

    /**
     * Add last login column
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, August 1st, 2023.
     * @access  public static
     * @param   mixed $columns
     * @return  mixed
     */
    public static function add_user_last_login_column( $columns ) {
        $columns['secnin_last_login'] = __( 'Last Login', 'security-ninja' );
        return $columns;
    }

    /**
     * return_last_login_column.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, August 1st, 2023.
     * @access  public static
     * @param   mixed $output
     * @param   mixed $column_id
     * @param   mixed $user_id
     * @return  mixed
     */
    public static function return_last_login_column( $output, $column_id, $user_id ) {
        if ( 'secnin_last_login' !== $column_id ) {
            return $output;
        }
        $current_time = current_time( 'timestamp' );
        $last_login = get_user_meta( $user_id, 'sn_last_login', true );
        if ( $last_login ) {
            $last_login_timestamp = strtotime( $last_login );
            if ( $last_login_timestamp <= $current_time ) {
                $human_time = human_time_diff( $last_login_timestamp, $current_time ) . ' ago';
                $friendly_date = date_i18n( get_option( 'date_format' ) . ' - ' . get_option( 'time_format' ), $last_login_timestamp );
                return $human_time . '<br><small>' . $friendly_date . '</small>';
            }
        } else {
            $session_tokens = get_user_meta( $user_id, 'session_tokens', true );
            if ( $session_tokens && is_array( $session_tokens ) ) {
                foreach ( $session_tokens as $stok ) {
                    if ( isset( $stok['login'] ) && is_numeric( $stok['login'] ) && $stok['login'] <= $current_time ) {
                        $human_time = human_time_diff( $stok['login'], $current_time ) . ' ago';
                        $friendly_date = date_i18n( get_option( 'date_format' ) . ' - ' . get_option( 'time_format' ), $stok['login'] );
                        return $human_time . '<br><small>' . $friendly_date . '</small>';
                    }
                }
            }
        }
        return __( 'No recorded login', 'security-ninja' );
    }

    /**
     * Checks for and migrates old license system to Freemius automatically.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.1  Thursday, September 21st, 2023.
     * @access  public static
     * @return  void
     */
    public static function secnin_fs_license_key_migration() {
        $has_api_connectivity = false;
        if ( secnin_fs()->has_api_connectivity() ) {
            $has_api_connectivity = true;
        }
        $is_registered = false;
        if ( secnin_fs()->is_registered() ) {
            $is_registered = true;
        }
        if ( false === $has_api_connectivity || $is_registered ) {
            // No connectivity OR the user already opted-in to Freemius.
            return;
        }
        if ( 'pending' !== get_option( 'secnin_fs_migrated2fs', 'pending' ) ) {
            return;
        }
        // Check if license_key.txt exists in the plugin directory and use it to activate the license
        $license_file = WF_SN_PLUGIN_DIR . 'license_key.txt';
        $license_key = '';
        if ( file_exists( $license_file ) ) {
            $file_contents = file( $license_file, FILE_IGNORE_NEW_LINES );
            if ( false !== $file_contents ) {
                $license_key = trim( $file_contents[0] );
                if ( empty( $license_key ) || strlen( $license_key ) !== 32 || strpos( $license_key, 'sk_' ) !== 0 ) {
                    $license_key = '';
                }
            }
        }
        try {
            $next_page = secnin_fs()->activate_migrated_license( $license_key );
        } catch ( \Exception $e ) {
            update_option( 'secnin_fs_migrated2fs', 'unexpected_error', false );
            return;
        }
    }

    /**
     * Handles incoming requests from MainWP Master.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, December 6th, 2023.
     * @access  public static
     * @param   mixed $information
     * @param   mixed $data        Default: array()
     * @return  mixed
     */
    public static function do_filter_mainwp_site_sync_others_data( $information, $data = array() ) {
        if ( isset( $data['SecNin_get_details'] ) && $data['SecNin_get_details'] ) {
            try {
                global $wpdb;
                $information['SecNin_get_details'] = array(
                    'plan' => 'Free',
                    'ver'  => self::get_plugin_version(),
                );
                // Check vulnerabilities
                if ( class_exists( __NAMESPACE__ . '\\wf_sn_vu' ) ) {
                    try {
                        $vulns = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vuln_count();
                        $vulndetails = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vulnerabilities();
                    } catch ( \Exception $e ) {
                        $vulns = 0;
                        $vulndetails = array();
                    }
                    $information['SecNin_get_details']['vulns'] = $vulns;
                    $information['SecNin_get_details']['vulndetails'] = $vulndetails;
                }
                // Get test scores
                $information['SecNin_get_details']['tests'] = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
                $information['SecNin_get_details']['test_results'] = \WPSecurityNinja\Plugin\Wf_Sn::get_test_results();
                // Core Scanner (free) – sync results for all sites.
                $wf_sn_cs_results = get_option( 'wf_sn_cs_results' );
                $information['SecNin_get_details']['cs_results'] = $wf_sn_cs_results;
                if ( is_array( $wf_sn_cs_results ) && !empty( $wf_sn_cs_results['last_run'] ) && class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_Cs' ) ) {
                    $information['SecNin_get_details']['cs_meta'] = \WPSecurityNinja\Plugin\Wf_Sn_Cs::build_meta_strings( $wf_sn_cs_results );
                }
            } catch ( \Exception $e ) {
                $information['SecNin_get_details'] = array(
                    'error' => $e->getMessage(),
                );
            }
        }
        return $information;
    }

    /**
     * Integrating with MainWP
     *
     * @author  Lars Koudal
     * @since   v5.139
     * @version v1.0.0  Thursday, March 24th, 2022.
     * @version v1.0.1  Saturday, April 2nd, 2022.
     * @access  public static
     * @param   mixed $info      – Information
     *                           to return.
     * @param   mixed $post_data – Post data array
     *                           from MainWP.
     * @return  mixed
     */
    public static function do_filter_mainwp_child_extra_execution( $info, $post_data ) {
        if ( isset( $post_data['action'] ) ) {
            switch ( $post_data['action'] ) {
                // *** Run all tests
                case 'run_all_tests':
                    do_action( 'secnin_run_tests_event' );
                    $info['secnin_run_all_tests'] = array(
                        'ran'     => true,
                        'modules' => array('tests', 'core'),
                    );
                    break;
                // *** Update settings (patch from MainWP Dashboard).
                case 'update_settings':
                    break;
                // ***  Update white label settings
                case 'update_white_label':
                    break;
                case 'manage_ip':
                    break;
                default:
                    break;
            }
        }
        return $info;
    }

    /**
     * Apply allowlisted Security Ninja settings from MainWP (changed keys only).
     *
     * @param array $post_data Request payload from MainWP.
     * @return array
     */
    public static function handle_mainwp_update_settings_request( $post_data ) {
        $response = array(
            'success' => false,
            'applied' => array(),
            'skipped' => array(),
            'errors'  => array(),
            'message' => '',
            'options' => array(),
        );
        $patch = array();
        if ( isset( $post_data['settings_patch'] ) && is_array( $post_data['settings_patch'] ) ) {
            $patch = $post_data['settings_patch'];
        }
        if ( empty( $patch ) ) {
            $response['message'] = __( 'No settings changes to apply.', 'security-ninja' );
            $response['success'] = true;
            return $response;
        }
        $allow = self::get_mainwp_settings_allowlist();
        $map = self::get_mainwp_settings_option_map();
        foreach ( $patch as $module => $keys ) {
            $module = sanitize_key( $module );
            if ( !is_array( $keys ) || !isset( $map[$module] ) ) {
                $response['skipped'][] = $module;
                continue;
            }
            $option_key = $map[$module];
            $existing = get_option( $option_key, array() );
            if ( !is_array( $existing ) ) {
                $existing = array();
            }
            $module_allow = ( isset( $allow[$module] ) ? $allow[$module] : array() );
            foreach ( $keys as $key => $raw_value ) {
                $key = sanitize_key( $key );
                if ( !isset( $module_allow[$key] ) ) {
                    $response['skipped'][] = $module . '.' . $key;
                    continue;
                }
                $type = $module_allow[$key];
                $value = self::sanitize_mainwp_setting_value(
                    $type,
                    $raw_value,
                    $module,
                    $key
                );
                if ( 'firewall' === $module && in_array( $key, array('unblock_url', 'unblock_url_hash'), true ) ) {
                    $response['skipped'][] = $module . '.' . $key;
                    continue;
                }
                $existing[$key] = $value;
                $response['applied'][] = $module . '.' . $key;
            }
            if ( 'firewall' === $module && class_exists( __NAMESPACE__ . '\\wf_sn_cf' ) ) {
                $opts = \WPSecurityNinja\Plugin\wf_sn_cf::get_options();
                if ( isset( $opts['unblock_url'] ) ) {
                    $existing['unblock_url'] = $opts['unblock_url'];
                }
            }
            update_option( $option_key, $existing, false );
        }
        if ( class_exists( __NAMESPACE__ . '\\wf_sn' ) && method_exists( __NAMESPACE__ . '\\wf_sn', 'return_global_options__premium_only' ) ) {
            $response['options'] = \WPSecurityNinja\Plugin\wf_sn::return_global_options__premium_only();
        }
        $applied_count = count( $response['applied'] );
        $response['success'] = $applied_count > 0;
        if ( $applied_count > 0 ) {
            $response['message'] = sprintf( 
                /* translators: %d: number of settings */
                _n(
                    '%d setting updated.',
                    '%d settings updated.',
                    $applied_count,
                    'security-ninja'
                ),
                $applied_count
             );
            $applied_keys = $response['applied'];
            \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                'security_ninja',
                'mainwp_settings_change',
                sprintf( 
                    /* translators: %d: number of settings changed */
                    _n(
                        'MainWP updated %d setting.',
                        'MainWP updated %d settings.',
                        $applied_count,
                        'security-ninja'
                    ),
                    $applied_count
                 ),
                array(
                    'source'        => 'mainwp',
                    'changed_count' => $applied_count,
                    'applied_keys'  => $applied_keys,
                )
            );
        } else {
            $response['message'] = __( 'No settings were updated.', 'security-ninja' );
        }
        return $response;
    }

    /**
     * Allowlist: module => key => type (bool|text|email|url|int).
     *
     * @return array<string, array<string, string>>
     */
    public static function get_mainwp_settings_allowlist() {
        $bools = array();
        foreach ( array(
            'active',
            'trackvisits',
            'globalbannetwork',
            'global',
            'usecloud',
            'protect_login_form',
            'hide_login_errors',
            'blockadminlogin',
            'change_login_url',
            '2fa_enabled',
            '2fa_backup_codes_enabled',
            '404guard_enabled',
            'whitelist_managewp',
            'filterqueries',
            'countryblock_loginonly',
            'failed_login_email_warning',
            'whitelist_wprocket',
            'whitelist_uptimia',
            'whitelist_uptimerobot',
            'woo_rate_limiting_enabled',
            'woo_coupon_protection_enabled',
            'satellite_soft_enabled'
        ) as $k ) {
            $bools[$k] = 'bool';
        }
        $firewall = $bools;
        $firewall['trackvisits_howlong'] = 'int';
        $firewall['max_login_attempts'] = 'int';
        $firewall['max_login_attempts_time'] = 'int';
        $firewall['bruteforce_ban_time'] = 'int';
        $firewall['login_msg'] = 'text';
        $firewall['login_error_msg'] = 'text';
        $firewall['message'] = 'text';
        $firewall['redirect_url'] = 'url';
        $firewall['new_login_url'] = 'text';
        $firewall['404guard_threshold'] = 'int';
        $firewall['404guard_window'] = 'int';
        $firewall['404guard_block_time'] = 'int';
        $vulns = array(
            'enable_vulns'              => 'bool',
            'enable_admin_notification' => 'bool',
            'enable_outdated'           => 'bool',
            'enable_email_notice'       => 'bool',
            'email_notice_recipient'    => 'email',
            'ignored_plugin_slugs'      => 'text',
        );
        $eventslogger = array(
            'active'                       => 'bool',
            'email_reports'                => 'text',
            'webhook_active'               => 'bool',
            'webhook_firewall_events'      => 'bool',
            'webhook_user_logins'          => 'bool',
            'webhook_updates'              => 'bool',
            'notify_new_admin'             => 'bool',
            'retention'                    => 'text',
            'email_to'                     => 'email',
            'webhook_url'                  => 'url',
            'new_admin_notification_email' => 'email',
        );
        $scheduledscanner = array(
            'main_setting'  => 'text',
            'scan_schedule' => 'text',
            'email_report'  => 'int',
            'email_to'      => 'email',
        );
        $whitelabel = array(
            'wl_active'         => 'bool',
            'wl_newname'        => 'text',
            'wl_newdesc'        => 'text',
            'wl_newauthor'      => 'text',
            'wl_newurl'         => 'url',
            'wl_newiconurl'     => 'url',
            'wl_newmenuiconurl' => 'url',
        );
        $fixes = array(
            'hide_wp'                      => 'bool',
            'hide_wlw'                     => 'bool',
            'hide_php_ver'                 => 'bool',
            'hide_server'                  => 'bool',
            'disable_editors'              => 'bool',
            'disable_wp_debug'             => 'bool',
            'enable_xcto'                  => 'bool',
            'enable_xfo'                   => 'bool',
            'enable_xxp'                   => 'bool',
            'enable_sts'                   => 'bool',
            'enable_rp'                    => 'bool',
            'enable_fp'                    => 'bool',
            'enable_csp'                   => 'bool',
            'disable_wp_sitemaps'          => 'bool',
            'disable_username_enumeration' => 'bool',
            'hide_wp_debug'                => 'bool',
            'application_passwords'        => 'bool',
            'remove_unwanted_files'        => 'bool',
            'secure_cookies'               => 'bool',
            'disable_xmlrpc'               => 'bool',
            'sechead_xcto'                 => 'text',
            'sechead_xfo'                  => 'text',
            'sechead_sts'                  => 'text',
            'sechead_rp'                   => 'text',
            'sechead_fp'                   => 'text',
            'sechead_csp'                  => 'text',
        );
        return array(
            'firewall'         => $firewall,
            'vulns'            => $vulns,
            'eventslogger'     => $eventslogger,
            'scheduledscanner' => $scheduledscanner,
            'whitelabel'       => $whitelabel,
            'fixes'            => $fixes,
            'malware_scanner'  => array(),
        );
    }

    /**
     * Map synced module slug to WordPress option name.
     *
     * @return array<string, string>
     */
    public static function get_mainwp_settings_option_map() {
        $fixes_key = ( defined( 'WF_SN_FIXES_OPTIONS_KEY' ) ? WF_SN_FIXES_OPTIONS_KEY : 'wf_sn_fixes' );
        $ss_key = ( defined( 'WF_SN_SS_OPTIONS_KEY' ) ? WF_SN_SS_OPTIONS_KEY : 'wf_sn_ss' );
        return array(
            'firewall'         => 'wf_sn_cf',
            'vulns'            => 'wf_sn_vu_settings_group',
            'eventslogger'     => 'wf_sn_el',
            'scheduledscanner' => $ss_key,
            'whitelabel'       => 'wf_sn_wl',
            'fixes'            => $fixes_key,
            'malware_scanner'  => 'wf_sn_ms_whitelist',
        );
    }

    /**
     * Sanitize one setting value for MainWP remote apply.
     *
     * @param string $type   Value type.
     * @param mixed  $value  Raw value.
     * @param string $module Module slug.
     * @param string $key    Setting key.
     * @return mixed
     */
    public static function sanitize_mainwp_setting_value(
        $type,
        $value,
        $module,
        $key
    ) {
        switch ( $type ) {
            case 'bool':
                return self::normalize_flag( $value );
            case 'int':
                return max( 0, (int) $value );
            case 'email':
                return sanitize_email( (string) $value );
            case 'url':
                return esc_url_raw( (string) $value );
            default:
                return sanitize_text_field( (string) $value );
        }
    }

    /**
     * Build a stable lookup key for MainWP event sync rows.
     *
     * @param array $row Event row.
     * @return string
     */
    public static function mainwp_event_sync_key( $row ) {
        if ( !is_array( $row ) ) {
            return '';
        }
        $parts = array(
            ( isset( $row['timestamp'] ) ? (string) $row['timestamp'] : '' ),
            ( isset( $row['ip'] ) ? (string) $row['ip'] : '' ),
            ( isset( $row['module'] ) ? (string) $row['module'] : '' ),
            ( isset( $row['action'] ) ? (string) $row['action'] : '' ),
            ( isset( $row['user_agent'] ) ? (string) $row['user_agent'] : '' ),
            ( isset( $row['user_id'] ) ? (string) $row['user_id'] : '' ),
            ( isset( $row['description'] ) ? (string) $row['description'] : '' )
        );
        return implode( '|', $parts );
    }

    /**
     * Create custom select element
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, January 13th, 2021.
     * @version v1.0.1  Thursday, April 11th, 2024.
     * @access  public static
     * @param   mixed   $options
     * @param   boolean $selected   Default: false
     * @param   boolean $output     Default: true
     * @return  void
     */
    public static function create_select_options( $options, $selected = null, $output = true ) {
        $out = '';
        $is_selected_array = is_array( $selected );
        foreach ( $options as $option ) {
            $value = ( isset( $option['val'] ) ? $option['val'] : '' );
            $label = ( isset( $option['label'] ) ? $option['label'] : '' );
            $is_selected = false;
            if ( $is_selected_array && is_array( $selected ) ) {
                $is_selected = in_array( $value, $selected, true );
            } elseif ( null !== $selected ) {
                $is_selected = ( is_numeric( $value ) && is_numeric( $selected ) ? $value == $selected : $value === $selected );
                // Strict comparison for other types
            }
            $value = esc_attr( $value );
            $label = esc_html( $label );
            $selected_attr = ( $is_selected ? ' selected="selected"' : '' );
            $out .= sprintf(
                '<option value="%1$s"%2$s>%3$s</option>',
                $value,
                $selected_attr,
                $label
            );
        }
        $allowed_html = array(
            'option' => array(
                'value'    => array(),
                'selected' => array(),
            ),
        );
        if ( $output ) {
            echo wp_kses( $out, $allowed_html );
        } else {
            return wp_kses( $out, $allowed_html );
        }
    }

    /**
     * Helper function to generate tagged links
     *
     * @param  string $placement [description]
     * @param  string $page      [description]
     * @param  array  $params    [description]
     * @return string            Full URL with utm_ parameters added
     */
    public static function generate_sn_web_link( $placement = '', $page = '/', $params = array() ) {
        $base_url = 'https://wpsecurityninja.com';
        if ( '/' !== $page ) {
            $page = '/' . trim( $page, '/' ) . '/';
        }
        $utm_source = 'security_ninja_free';
        $parts = array_merge( array(
            'utm_source'   => esc_attr( $utm_source ),
            'utm_medium'   => 'plugin',
            'utm_content'  => esc_attr( $placement ),
            'utm_campaign' => esc_attr( 'security_ninja_v' . self::get_plugin_version() ),
        ), $params );
        $out = $base_url . $page . '?' . http_build_query( $parts, '', '&amp;' );
        return $out;
    }

    /**
     * add_freemius_extra_permission.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Saturday, March 5th, 2022.
     * @access  public static
     * @param   mixed $permissions
     * @return  mixed
     */
    public static function add_freemius_extra_permission( $permissions ) {
        $permissions['newsletter'] = array(
            'id'         => 'security_ninja_newsletter',
            'icon-class' => 'dashicons dashicons-email-alt2',
            'label'      => 'Newsletter',
            'desc'       => 'You are added to our newsletter. Unsubscribe anytime.',
            'priority'   => 18,
        );
        return $permissions;
    }

    /**
     * Add markup for UI overlay.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Thursday, January 14th, 2021.
     * @access  public static
     * @return  void
     */
    public static function admin_footer() {
        if ( \WPSecurityNinja\Plugin\Wf_Sn::is_plugin_page() ) {
            $current_screen = ( function_exists( 'get_current_screen' ) ? get_current_screen() : null );
            if ( $current_screen && false !== strpos( $current_screen->id, 'page_security-ninja-wizard' ) ) {
                return;
            }
            echo '<div id="sn_overlay"><div class="sn-overlay-wrapper">';
            echo '<div class="inner">';
            // Outer
            echo '<div class="wf-sn-overlay-outer">';
            echo '<div class="wf-sn-overlay-content">';
            echo '<div id="sn-site-scan" style="display: none;">';
            echo '</div>';
            echo '<p><a id="abort-scan" href="#" class="button button-secondary">Cancel</a></p>';
            echo '</div>';
            // wf-sn-overlay-content
            echo '</div></div></div></div>';
        }
    }

    /**
     * Returns icon in SVG format
     * Thanks Yoast for code.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Thursday, January 14th, 2021.
     * @access  public static
     * @param   boolean $base64 Return SVG in base64 or not
     * @param   string  $color  Default: '82878c'
     * @return  mixed
     */
    public static function get_icon_svg( $base64 = true, $color = '82878c' ) {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500">
																													<g fill="#' . $color . '">
																													<path d="M171.117 262.277c14.583-.142 25.832 20.664 25.921 35.25.094 15.265-11.418 37.682-26.678 37.227-14.687-.438-23.797-22.605-23.494-37.296.295-14.24 10.095-35.044 24.25-35.181zM322.387 263.03c14.584-.142 25.832 20.664 25.922 35.25.093 15.265-11.419 37.681-26.679 37.227-14.686-.438-23.797-22.606-23.493-37.296.294-14.24 10.094-35.044 24.25-35.182z"/>
																													<path d="M331.348 26.203c0-.107 98.038-7.914 98.038-7.914s-9.219 91.716-10.104 96.592c1.277-3.3 22.717-46.002 22.818-46.002.105 0 53.047 69.799 53.047 69.799l-46.63 42.993c26.6 30.762 41.632 67.951 41.724 107.653.239 103.748-110.253 191.827-245.68 191.091-130.352-.706-239.977-86.977-240.475-188.91-.5-102.38 105.089-191.741 239.663-192.095 38.677-.1 74.34 6.068 105.82 17.154-3.241-16.067-18.22-90.265-18.22-90.36zm-85.421 157.959c-74.098-1.337-161.3 41.627-161.054 105.87.247 63.88 87.825 103.981 160.683 104.125 78.85.154 164.156-41.58 163.722-106.614-.428-64.436-86.566-101.996-163.351-103.381z"/>
																													</g>
																													</svg>';
        if ( $base64 ) {
            return 'data:image/svg+xml;base64,' . base64_encode( $svg );
        }
        return $svg;
    }

    /**
     * Renders the output for the whitelabel page
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Saturday, March 5th, 2022.
     * @access  public static
     * @return  void
     */
    public static function render_whitelabel_page() {
        ?>
		<div class="sncard settings-card">
				<h2><span class="dashicons dashicons-admin-appearance"></span> <?php 
        esc_html_e( 'White label', 'security-ninja' );
        ?></h2>
			<p>Customize the plugin branding for your agency or clients.</p>
			<div class="sncard infobox">
				<div class="inner">
					<h3>Upgrade to Pro for White Label</h3>
					<p>Present a fully customized security solution to your clients. Upgrade to Security Ninja Pro (25+ site license) to unlock White Label:</p>
					<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
						<li>Hide Security Ninja branding and use your own logo</li>
						<li>Customize the plugin name and add your company URL</li>
						<li>Increase brand visibility with every scan and notification</li>
						<li>Provide a seamless, branded experience for client loyalty</li>
					</ul>
					<p style="margin-top: 15px;">
						<a href="<?php 
        echo esc_url( self::generate_sn_web_link( 'upgrade_tab_whitelabel', '/pricing/' ) );
        ?>" class="button button-primary button-small" target="_blank" rel="noopener">Upgrade to Pro</a>
					</p>
				</div>
			</div>
		</div>
		<?php 
    }

    /**
     * Safely strips HTML and PHP tags from a string, handling null values.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, December 7th, 2021.
     * @access  public static
     * @param   string|null $str The string to strip tags from.
     * @param   string|null $allowable_tags Optional. Tags to allow.
     * @return  string The string with tags stripped.
     */
    public static function safe_strip_tags( $str, $allowable_tags = null ) {
        if ( null === $str ) {
            return '';
        }
        return strip_tags( $str, $allowable_tags );
    }

    public static function extra_modern_checkout_parameters( $parameters ) {
        // You can modify existing parameters in the $parameters array or add new ones.
        $parameters['show_refund_badge'] = true;
        $parameters['show_reviews'] = true;
        $parameters['billing_cycle_selector'] = 'dropdown';
        return $parameters;
    }

    /**
     * Custom Freemius opt-in (connect) message.
     *
     * Keeps the Skip option (enable_anonymous) but gives users a clear,
     * security-focused reason to opt in, which lifts the opt-in rate without
     * forcing the connection.
     *
     * @since   v5.290
     * @access  public static
     * @param   string $message         Default opt-in message (replaced).
     * @param   string $user_first_name Current user's first name.
     * @param   string $product_title   Plugin title.
     * @param   string $user_login      Current user's login.
     * @param   string $site_link       HTML link to the current site.
     * @param   string $freemius_link   HTML link to Freemius.
     * @return  string
     */
    public static function freemius_connect_message(
        $message,
        $user_first_name,
        $product_title,
        $user_login,
        $site_link,
        $freemius_link
    ) {
        if ( empty( $user_first_name ) ) {
            $greeting = esc_html__( 'Hi there!', 'security-ninja' );
        } else {
            /* translators: %s: current user's first name. */
            $greeting = sprintf( esc_html__( 'Hi %s!', 'security-ninja' ), esc_html( $user_first_name ) );
        }
        return sprintf( 
            /* translators: 1: greeting, 2: plugin title (bold). */
            esc_html__( '%1$s Opt in to keep %2$s working at its best — get critical security alerts, fresh vulnerability data, and important update notices, plus non-sensitive diagnostics that help us fix issues faster. We never collect sensitive data, never share your email, and you can opt out anytime. Not ready? Just click Skip.', 'security-ninja' ),
            $greeting,
            '<strong>' . esc_html( $product_title ) . '</strong>'
         );
    }

    /**
     * Creates database tables for a specific site.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, December 7th, 2021.
     * @access  private static
     * @param   string $charset Database charset.
     * @return  bool Always returns true to indicate completion.
     */
    public static function create_tables_for_site( $charset ) {
        global $wpdb;
        // Create main tests table
        $table_name = $wpdb->prefix . 'wf_sn_tests';
        $sql = "CREATE TABLE {$table_name} (\n\t\t\t\tid bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n\t\t\t\ttestid varchar(30) NOT NULL,\n\t\t\t\ttimestamp datetime NOT NULL,\n\t\t\t\ttitle text,\n\t\t\t\tstatus tinyint(4) NOT NULL,\n\t\t\t\tscore tinyint(4) NOT NULL,\n\t\t\t\truntime float DEFAULT NULL,\n\t\t\t\tmsg text,\n\t\t\t\tdetails text,\n\t\t\t\tPRIMARY KEY  (testid),\n\t\t\t\tKEY id (id)\n\t\t\t) {$charset};";
        dbDelta( $sql );
        // EVENT LOGS
        $table_name = $wpdb->prefix . 'wf_sn_el';
        $sql = "CREATE TABLE {$table_name} (\n\t\t\t\tid bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n\t\t\t\ttimestamp datetime NOT NULL,\n\t\t\t\tip varchar(39) NOT NULL,\n\t\t\t\tuser_agent varchar(255) NOT NULL,\n\t\t\t\tuser_id int(10) unsigned NOT NULL,\n\t\t\t\tmodule varchar(32) NOT NULL,\n\t\t\t\taction varchar(64) NOT NULL,\n\t\t\t\tdescription text NOT NULL,\n\t\t\t\traw_data blob NOT NULL,\n\t\t\t\tPRIMARY KEY  (id)\n\t\t\t) {$charset};";
        dbDelta( $sql );
        // AI Advisor reports (when module is loaded)
        if ( class_exists( '\\WPSecurityNinja\\Plugin\\AiAdvisor\\Wf_Sn_Ai_Advisor_Reports' ) ) {
            \WPSecurityNinja\Plugin\AiAdvisor\Wf_Sn_Ai_Advisor_Reports::ensure_table();
        }
        // Firewall - local list of blocked IPs (free feature)
        $table_name = $wpdb->prefix . 'wf_sn_cf_bl_ips';
        $sql = "CREATE TABLE {$table_name} (\n\t\t\t\ttid datetime NOT NULL DEFAULT NOW(),\n\t\t\t\tip varchar(46) NOT NULL,\n\t\t\t\treason varchar(255) NOT NULL,\n\t\t\t\tPRIMARY KEY  (ip),\n\t\t\t\tKEY tid (tid)\n\t\t\t) {$charset};";
        dbDelta( $sql );
        // Set up default settings for Event logger (free feature)
        if ( class_exists( '\\WPSecurityNinja\\Plugin\\Wf_Sn_El' ) ) {
            Wf_Sn_El::default_settings( false );
        }
        return true;
    }

    /**
     * Safely trims whitespace from the beginning of a string, handling null values.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, December 7th, 2021.
     * @access  public static
     * @param   string|null $str The string to trim.
     * @param   string $character_mask Optional. Characters to trim.
     * @return  string The trimmed string.
     */
    public static function safe_ltrim( $str, $character_mask = " \t\n\r\x00\v" ) {
        if ( null === $str ) {
            return '';
        }
        return ltrim( $str, $character_mask );
    }

    /**
     * Safely trims whitespace from both ends of a string, handling null values.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, December 7th, 2021.
     * @access  public static
     * @param   string|null $str The string to trim.
     * @param   string $character_mask Optional. Characters to trim.
     * @return  string The trimmed string.
     */
    public static function safe_trim( $str, $character_mask = " \t\n\r\x00\v" ) {
        if ( null === $str ) {
            return '';
        }
        return trim( $str, $character_mask );
    }

    /**
     * Start timer for performance measurement
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 12th, 2021.
     * @access  public static
     * @param   string $watchname Timer identifier
     * @return  void
     */
    public static function timerstart( $watchname ) {
        set_transient( 'security_ninja_' . esc_attr( $watchname ), microtime( true ), 60 * 60 * 1 );
    }

    /**
     * End timer and return elapsed time
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 12th, 2021.
     * @access  public static
     * @param   string   $watchname Timer identifier
     * @param   integer  $digits    Number of decimal places (default: 5)
     * @return  float    Elapsed time in seconds
     */
    public static function timerstop( $watchname, $digits = 5 ) {
        $return = round( microtime( true ) - get_transient( 'security_ninja_' . esc_attr( $watchname ) ), $digits );
        delete_transient( 'security_ninja_' . esc_attr( $watchname ) );
        return $return;
    }

    /**
     * Shows the topbar, logo and version
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0    Monday, March 11th, 2024.
     * @access  public static
     * @global
     * @return  void
     */
    public static function show_topbar() {
        $icon_url = WF_SN_PLUGIN_URL . 'images/sn-logo.svg';
        $menu_title = 'Security Ninja';
        $topbar = '<div id="sntopbar">';
        $topbar .= '<div class="plugname">';
        if ( !empty( $icon_url ) ) {
            $topbar .= '<img src="' . esc_url( $icon_url ) . '" height="28" alt="' . esc_attr( $menu_title ) . '" class="logoleft">';
        }
        $topbar .= '<div class="name">' . esc_html( $menu_title ) . ' <span>v.' . esc_html( self::get_plugin_version() ) . '</span></div></div>';
        $menu_links = '<a href="https://wordpress.org/support/plugin/security-ninja/" target="_blank" rel="noopener noreferrer" class="extlink">Support Forum</a>';
        $is_registered = false;
        if ( secnin_fs()->is_registered() ) {
            $is_registered = true;
        }
        $is_tracking_allowed = false;
        if ( secnin_fs()->is_tracking_allowed() ) {
            $is_tracking_allowed = true;
        }
        if ( $is_registered && $is_tracking_allowed ) {
            $menu_links .= '<a href="#" class="productlift-sidebar=caa739c4-554e-4526-9720-a600a6702a8e whatsnew">Updates 🚀</a>';
        }
        $topbar .= '<div class="links">' . $menu_links . '</div>';
        $topbar .= '</div>';
        echo wp_kses_post( $topbar );
    }

    /**
     * Creates a toggle switch HTML element
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, January 12th, 2021.
     * @access  public static
     * @param   string $name    The name/id of the toggle switch
     * @param   array  $options Options for the toggle switch
     * @param   bool   $output  Whether to output or return the HTML
     * @return  string|void     HTML string if $output is false, void otherwise
     */
    public static function create_toggle_switch( $name, $options = array(), $output = true ) {
        $default_options = array(
            'value'       => 1,
            'saved_value' => 0,
            'option_key'  => '',
        );
        $options = wp_parse_args( $options, $default_options );
        $value = (int) $options['value'];
        $saved_value = ( isset( $options['saved_value'] ) ? (int) $options['saved_value'] : 0 );
        $checked = ( $value === $saved_value ? ' checked' : '' );
        // When unchecked, checkboxes are omitted from POST. A hidden input with value 0
        // ensures the field is always submitted so "off" persists (e.g. 2FA disable).
        $html = '';
        if ( '' !== (string) $options['option_key'] ) {
            $html .= sprintf( '<input type="hidden" name="%1$s" value="0">', esc_attr( $options['option_key'] ) );
        }
        $html .= sprintf(
            '<input type="checkbox" id="%1$s" value="%2$s" class="switch" name="%3$s"%4$s>',
            esc_attr( $name ),
            esc_attr( $options['value'] ),
            esc_attr( $options['option_key'] ),
            $checked
        );
        if ( $output ) {
            echo wp_kses( $html, array(
                'div'   => array(
                    'class' => array(),
                ),
                'input' => array(
                    'type'    => array(),
                    'id'      => array(),
                    'value'   => array(),
                    'name'    => array(),
                    'class'   => array(),
                    'checked' => array(),
                ),
                'label' => array(
                    'for'   => array(),
                    'class' => array(),
                ),
                'span'  => array(
                    'class' => array(),
                ),
            ) );
        } else {
            return $html;
        }
    }

    /**
     * Returns the ISO country-code => country-name map.
     *
     * The data is stored as a JSON data file (rather than an executable PHP
     * array) so security scanners do not mistake a large static list for
     * obfuscated/concealed code. The result is cached for the request.
     *
     * @author  Lars Koudal
     * @since   v5.290
     * @access  public static
     * @return  array  Associative array of country code => country name (empty on failure).
     */
    public static function get_country_list() {
        static $country_list = null;
        if ( null !== $country_list ) {
            return $country_list;
        }
        $country_list = array();
        $path = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/geoip-countrylist.json';
        if ( is_readable( $path ) ) {
            $contents = file_get_contents( $path );
            if ( false !== $contents && '' !== $contents ) {
                $decoded = json_decode( $contents, true );
                if ( is_array( $decoded ) ) {
                    $country_list = $decoded;
                }
            }
        }
        return $country_list;
    }

    /**
     * Fetch plugin version from plugin PHP header
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, January 13th, 2021.
     * @access  public static
     * @return  string Plugin version
     */
    public static function get_plugin_version() {
        $plugin_data = get_file_data( WF_SN_BASE_FILE, array(
            'version' => 'Version',
        ), 'plugin' );
        return $plugin_data['version'];
    }

    /**
     * Fetch plugin name from plugin PHP header
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, January 13th, 2021.
     * @access  public static
     * @return  string Plugin name
     */
    public static function get_plugin_name() {
        $plugin_data = get_file_data( WF_SN_BASE_FILE, array(
            'name' => 'Plugin Name',
        ), 'plugin' );
        return $plugin_data['name'];
    }

    /**
     * Converts a status integer to a button.
     *
     * This method takes a status code as an integer and returns a string representing a button with a class indicating the status.
     * The status codes are mapped to the following buttons:
     * - 0: Fail (class "sn-error")
     * - 10: OK (class "sn-success")
     * - Any other value: Warning (class "sn-warning")
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Tuesday, December 7th, 2021.
     * @access  public static
     * @param   int $statuscode The status code to convert.
     * @return  string The HTML string representing the button.
     */
    public static function status( $statuscode ) {
        switch ( $statuscode ) {
            case 0:
                $string = '<span class="sn-error">' . __( 'Fail', 'security-ninja' ) . '</span>';
                break;
            case 10:
                $string = '<span class="sn-success">' . __( 'OK', 'security-ninja' ) . '</span>';
                break;
            default:
                $string = '<span class="sn-warning">' . __( 'Warning', 'security-ninja' ) . '</span>';
                break;
        }
        return $string;
    }

    /**
     * Normalize a boolean-like value to integer 0 or 1
     *
     * Converts various boolean representations (true, false, 'true', '1', 1, 0, etc.)
     * to a consistent integer format (0 or 1) for storage and comparison.
     *
     * @author  Lars Koudal
     * @since   v1.0.0
     * @version v1.0.0  Monday, January 20th, 2025.
     * @access  public static
     * @param   mixed   $value  The value to normalize (can be boolean, string, integer, etc.)
     * @return  int     Returns 1 if value is truthy, 0 otherwise
     */
    public static function normalize_flag( $value ) {
        // Handle explicit true/false
        if ( $value === true ) {
            return 1;
        }
        if ( $value === false ) {
            return 0;
        }
        // Handle string representations
        if ( is_string( $value ) ) {
            $value = strtolower( trim( $value ) );
            if ( $value === 'true' || $value === '1' || $value === 'yes' || $value === 'on' ) {
                return 1;
            }
            return 0;
        }
        // Handle numeric values
        if ( is_numeric( $value ) ) {
            return ( (int) $value ? 1 : 0 );
        }
        // For any other type, use truthiness check
        return ( $value ? 1 : 0 );
    }

}
