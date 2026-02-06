<?php
/**
 * Cloud Firewall Settings
 * 
 * This file contains the settings form content for the Cloud Firewall module.
 * Extracted from cloud-firewall.php to reduce file size and improve maintainability.
 */

namespace WPSecurityNinja\Plugin;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Ensure we have access to the main class
if (!class_exists('Wf_sn_cf')) {
    return;
}

/**
 * Render the settings form content
 * 
 * @param array $options Current options
 * @param array $ips IP information
 */
function wf_sn_cf_render_settings_content($options, $ips = array()) {
    ?>

<table class="form-table">
					<tbody>
						<tr>
							<td colspan="2">
								<h2><?php esc_html_e('Firewall Settings', 'security-ninja'); ?></h2>
							</td>
						</tr>
						<?php

						// Free feature: 8G Firewall Rules
						echo '<tr valign="top"><th scope="row"><label for="wf_sn_cf_filterqueries"><h3>' . esc_html__('Block Suspicious Page Requests', 'security-ninja') . '</h3>';
						echo '<p class="description">' . __('Block suspicious page requests and malicious query strings using the proven 8G Firewall rules.', 'security-ninja') . '</p>';
						echo '<p class="description">' . __('Based on the excellent 8G Firewall by Jeff Starr from Perishable Press. This protection filters out dangerous requests including SQL injections, XSS attacks, and other malicious patterns.', 'security-ninja') . '</p></label></th>';
						echo '</th><td class="sn-cf-options">';

						\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
							WF_SN_CF_OPTIONS_KEY . '_filterqueries',
							array(
								'saved_value' => $options['filterqueries'],
								'option_key'  => WF_SN_CF_OPTIONS_KEY . '[filterqueries]',
							)
						);

						echo '</td></tr>';

						// Pro features - show unified marketing info box for free users
						if (!secnin_fs()->can_use_premium_code()):
						?>

						<tr>
							<td colspan="2">
								<div class="sncard infobox">
									<div class="inner">
										<h3><?php esc_html_e('Upgrade to Pro for Advanced Firewall Features', 'security-ninja'); ?></h3>
										<p><?php esc_html_e('The free version provides basic firewall protection with 8G rules. Upgrade to Security Ninja Pro to unlock powerful advanced features:', 'security-ninja'); ?></p>
										<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
											<li><?php esc_html_e('Control how banned IPs are handled - block completely or only from login', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Cloud Firewall with 600+ million known bad IPs, automatically updated', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Participate in global IP threat network and share threat intelligence', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Block entire countries from accessing your website', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Customize messages shown to blocked visitors', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Redirect blocked visitors to any URL using 301 redirects', 'security-ninja'); ?></li>
										</ul>
										<p style="margin-top: 15px;">
											<a href="<?php echo esc_url(secnin_fs()->get_upgrade_url()); ?>" class="button button-primary"><?php esc_html_e('Upgrade to Pro', 'security-ninja'); ?></a>
										</p>
									</div>
								</div>
							</td>
						</tr>

						<?php
						else:
						// Premium users see full functionality
						$options = \WPSecurityNinja\Plugin\wf_sn_cf::get_options();
						?>

						<tr>
							<td colspan="2"><hr></td>
						</tr>

						<tr valign="top">
							<th scope="row">
								<label for="wf_sn_cf_global">
									<h3><?php esc_html_e('Prevent Banned IPs from Accessing the Site', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('If set to ON cloud and local firewall will prevent banned IPs from accessing the site all together.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('If set to OFF they will not be able to log in, but will be able to view the site.', 'security-ninja'); ?></p>
								</label>
							</th>
							<td class="sn-cf-options">
								<?php
								\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_global',
									array(
										'saved_value' => $options['global'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[global]',
									)
								);
								?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row">
								<label for="wf_sn_cf_usecloud">
									<h3><?php esc_html_e('Cloud Firewall', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('The list of 600+ million IPs can sometimes block traffic that should not be blocked. Use this to turn off this feature.', 'security-ninja'); ?></p>
									<?php
									if (1 === wf_sn_cf::is_active()) {
										if (isset($ips['timestamp'])) {
									?>
											<p>
												<?php
												printf(
													esc_html__('%s bad IPs blocked from logging in.', 'security-ninja'),
													'<strong>' . number_format_i18n($ips['total']) . '</strong>'
												);
												?>
											</p>
											<p><small>
													<?php
													printf(
														esc_html__('List last updated %1$s (%2$s)', 'security-ninja'),
														date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $ips['timestamp']),
														human_time_diff($ips['timestamp'], current_time('timestamp')) . ' ' . __('ago', 'security-ninja')
													);
													?>
												</small></p>
									<?php
										}
									}
									?>
								</label>
							</th>
							<td class="sn-cf-options">
								<?php
								\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_usecloud',
									array(
										'saved_value' => $options['usecloud'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[usecloud]',
									)
								);
								?>
							</td>
						</tr>

						<tr valign="top">
							<th scope="row">
								<label for="wf_sn_cf_globalbannetwork">
									<h3><?php esc_html_e('Block IP Network', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('Participate in the global bad IP network. Submit hack attempts to central database.', 'security-ninja'); ?></p>
								</label>
							</th>
							<td class="sn-cf-options globalbannetwork">
								<?php
								\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_globalbannetwork',
									array(
										'saved_value' => $options['globalbannetwork'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[globalbannetwork]',
									)
								);
								?>
							</td>
						</tr>

						<tr>
							<td colspan="2"><hr></td>
						</tr>

						<?php
						echo '<tr valign="top"><th scope="row"><h3>' . __('Block visits from these countries', 'security-ninja') . '</h3>';
						?>
						<p class="description"><?php esc_html_e('Choose the countries you want to block.', 'security-ninja'); ?></p>
						<p class="description">
							<?php esc_html_e('Be careful not to block USA if you depend on traffic from Google as Google crawls your website from USA.', 'security-ninja'); ?>
						</p>
						<?php
						echo '</th><td></td></tr>';

						echo '<tr><td class="fullwidth" colspan="2">';

						$countrylist_uri = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-sn-geoip-countrylist.php';
						require_once $countrylist_uri;
						?>
						<select name="wf_sn_cf[blocked_countries][]" id="wf_sn_cf_blocked_countries" multiple="multiple" style="width:100%;" class="">
							<?php
							$blocked_countries = \WPSecurityNinja\Plugin\wf_sn_cf::get_blocked_countries();
							if ($geoip_countrylist) {
								foreach ($geoip_countrylist as $key => $gc) {
									$selected = in_array($key, $blocked_countries, true) ? ' selected="selected" ' : '';
							?>
									<option value="<?php echo $key; ?>" <?php echo $selected; ?>><?php echo $gc . ' (' . $key . ')'; ?></option>
							<?php
								}
							}
							?>
						</select>
						<button id="select_all_countries" class="button button-secondary button-small alignright"><?php esc_html_e('Select All', 'security-ninja'); ?></button>
						<button id="select_no_countries" class="button button-secondary button-small alignright"><?php esc_html_e('Select None', 'security-ninja'); ?></button>
						</td>
						</tr>
						<tr valign="top">
							<th scope="row">
								<label for="wf_sn_cf_countryblock_loginonly">
								<h3><?php esc_html_e('Only block these countries from login functionality', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('For example, if you block a particular country, users from that country will not be able to log in, but will be able to view the site.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('For more login protection, check out the tab "Login Protection".', 'security-ninja'); ?></p>
								</label>
							</th>
							<td class="sn-cf-options">
								<?php
								\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_countryblock_loginonly',
									array(
										'saved_value' => $options['countryblock_loginonly'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[countryblock_loginonly]',
									)
								);
								?>
							</td>
						</tr>

						<?php
						echo '<tr valign="top">
					<th scope="row"><label for="wf_sn_cf_message"><h3>' . __('Message for blocked IPs', 'security-ninja') . '</h3>';
						echo '<p class="description">' . __('Message shown to blocked visitors when they try to access the site or log in.', 'security-ninja') . '</p>';
						echo '</label></th></tr>';

						echo '<tr><td class="fullwidth" colspan="2"><textarea id="wf_sn_cf_message" name="' . WF_SN_CF_OPTIONS_KEY . '[message]" rows="3" cols="50">' . esc_textarea($options['message']) . '</textarea></td></tr>';
						?>
						<tr>
							<td colspan="2"><?php esc_html_e('Or you can redirect blocked visitors', 'security-ninja'); ?>:</td>
						</tr>
						<?php
						echo '<tr valign="top"><th scope="row"><label for="wf-cf-redirect-url"><h3>' . __('Redirect blocked visitors', 'security-ninja') . '</h3>';
						echo '<p class="description">' . __('301 redirect blocked visitors to any URL. Leave empty to show message instead.', 'security-ninja') . '</p>';
						echo '</label></th><td></td></tr>';
						echo '<tr><td class="fullwidth" colspan="2">';
						echo '<input type="text" placeholder="https://" class="regular-text" value="' . esc_attr($options['redirect_url']) . '" id="wf-cf-redirect-url" name="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '[redirect_url]">';
						echo '</td></tr>';
						?>
						<?php
						endif; // End premium check
						?>
					</tbody>
				</table>
    <?php
} 