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
            echo esc_attr( \WPSecurityNinja\Plugin\Wf_Sn::get_plugin_version() );
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
        $current_time = time();
        $gmt_offset_seconds = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
        $current_time_with_offset = $current_time + $gmt_offset_seconds;
        $last_login = get_user_meta( $user_id, 'sn_last_login', true );
        if ( $last_login ) {
            $last_login_timestamp = strtotime( $last_login );
            if ( $last_login_timestamp <= $current_time ) {
                $human_time = human_time_diff( $last_login_timestamp, $current_time_with_offset ) . ' ago';
                $friendly_date = date_i18n( get_option( 'date_format' ) . ' - ' . get_option( 'time_format' ), $last_login_timestamp );
                return $human_time . '<br><small>' . $friendly_date . '</small>';
            }
        } else {
            $session_tokens = get_user_meta( $user_id, 'session_tokens', true );
            if ( $session_tokens && is_array( $session_tokens ) ) {
                foreach ( $session_tokens as $stok ) {
                    if ( isset( $stok['login'] ) && is_numeric( $stok['login'] ) && $stok['login'] <= $current_time ) {
                        $human_time = human_time_diff( $stok['login'], $current_time_with_offset ) . ' ago';
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
        if ( false === secnin_fs()->has_api_connectivity() || secnin_fs()->is_registered() ) {
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
        if ( secnin_fs()->can_use_premium_code() ) {
            update_option( 'secnin_fs_migrated2fs', 'done', false );
            // Delete the license file if it exists
            if ( file_exists( $license_file ) ) {
                wp_delete_file( $license_file );
            }
            // Display admin notice for successful activation
            add_action( 'admin_notices', function () {
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'License automatically activated!', 'security-ninja' ) . '</p></div>';
            } );
            if ( is_array( $next_page ) && isset( $next_page['success'] ) && 1 === $next_page['success'] && isset( $next_page['next_page'] ) ) {
                $next_page_url = wp_validate_redirect( $next_page['next_page'], admin_url() );
                wp_safe_redirect( $next_page_url );
                exit;
            }
        } else {
            update_option( 'secnin_fs_migrated2fs', 'failed', false );
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
                    'ver'  => \WPSecurityNinja\Plugin\wf_sn::get_plugin_version(),
                );
                // Check vulnerabilities
                if ( class_exists( __NAMESPACE__ . '\\wf_sn_vu' ) ) {
                    $vulns = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vuln_count();
                    $vulndetails = \WPSecurityNinja\Plugin\Wf_Sn_Vu::return_vulnerabilities();
                    $information['SecNin_get_details']['vulns'] = $vulns;
                    $information['SecNin_get_details']['vulndetails'] = $vulndetails;
                }
                // Get test scores
                $information['SecNin_get_details']['tests'] = \WPSecurityNinja\Plugin\Wf_Sn::return_test_scores();
                $information['SecNin_get_details']['test_results'] = \WPSecurityNinja\Plugin\Wf_Sn::get_test_results();
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
                    wp_schedule_single_event( time(), 'secnin_run_tests_event' );
                    break;
                // *** Start malware scan
                case 'run_malware_scan':
                    break;
                // *** Update settings
                case 'update_settings':
                    // @todo - sanitity checks and then update values
                    break;
                // *** Update vulnerabilities
                case 'update_vulnerabilities':
                    \WPSecurityNinja\Plugin\Wf_Sn_Vu::update_vuln_list();
                    break;
                // ***  Update white label settings
                case 'update_white_label':
                    break;
                default:
                    break;
            }
        }
        return $info;
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
            'utm_campaign' => esc_attr( 'security_ninja_v' . \WPSecurityNinja\Plugin\Wf_Sn::get_plugin_version() ),
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
        $permissions['wpsnapi'] = array(
            'id'         => 'security_ninja_api',
            'icon-class' => 'dashicons dashicons-sos',
            'label'      => __( 'Security Ninja API', 'security-ninja' ),
            'desc'       => __( 'Sending and getting data from Security Ninja API servers.', 'security-ninja' ),
            'priority'   => 17,
        );
        $permissions['newsletter'] = array(
            'id'         => 'security_ninja_newsletter',
            'icon-class' => 'dashicons dashicons-email-alt2',
            'label'      => __( 'Newsletter', 'security-ninja' ),
            'desc'       => __( 'You are added to our newsletter. Unsubscribe anytime.', 'security-ninja' ),
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
            echo '<div id="sn_overlay"><div class="sn-overlay-wrapper">';
            echo '<div class="inner">';
            // Outer
            echo '<div class="wf-sn-overlay-outer">';
            echo '<div class="wf-sn-overlay-content">';
            echo '<div id="sn-site-scan" style="display: none;">';
            echo '</div>';
            // do_action( 'sn_overlay_content' ); // @todo - remove this
            echo '<p><a id="abort-scan" href="#" class="button button-secondary">Cancel</a></p>';
            // do_action('sn_overlay_content_after'); @todo - remove this.
            echo '</div>';
            // wf-sn-overlay-content
            echo '</div></div></div></div>';
            echo '<div id="test-details-dialog" style="display: none;" title="Test details"><p>Please wait.</p></div>';
            echo '<div id="sn_tests_descriptions" style="display: none;">';
            include_once WF_SN_PLUGIN_DIR . 'sn-tests-description.php';
            echo '</div>';
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
		<div class="submit-test-container">
			<div class="fomcont">
				<h3>Unlock Agency-Level Branding</h3>
				<img src="<?php 
        echo esc_url( WF_SN_PLUGIN_URL . 'images/whitelabel.jpg' );
        ?>" alt="Whitelabel your security work." class="tabimage">



				<p>
					White label is the ultimate branding tool for agencies and professionals. Present a fully customized security solution to your clients, boosting your brand recognition and client loyalty. Hide WP Security Ninja branding, customize the plugin name, add your company URL, and even use your own logo.
				</p>
				<ul>
					<li><strong>Increase Brand Visibility:</strong> Showcase your brand with every security scan and notification.</li>
					<li><strong>Enhanced Client Loyalty:</strong> Provide a seamless, branded experience that keeps clients coming back.</li>
				</ul>
				<p>
					<em>This feature is available for Pro users with 25+ site licenses.</em>
				</p>





				<p class="fomlink"><a target="_blank" href="<?php 
        echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_whitelabel', '/' ) );
        ?>" class="button button-primary" rel="noopener"><?php 
        esc_html_e( 'Learn more', 'security-ninja' );
        ?></a></p>

			</div>
		</div>
<?php 
    }

}
