<?php
/**
 * Cloud Firewall Login Protection
 * 
 * This file contains the login protection form content for the Cloud Firewall module.
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
 * Render the login protection form content
 * 
 * @param array $options Current options
 */
function wf_sn_cf_render_login_protection_content($options) {
    ?>

<table class="form-table">
					<tbody>
						<tr valign="top">
							<th colspan="2">
								<h3><?php esc_html_e('Login Form Protection', 'security-ninja'); ?></h3>
							</th>
						</tr>
						<?php if (secnin_fs()->can_use_premium_code()): ?>
						<?php
						echo '<tr valign="top"><th scope="row"><label for="wf_sn_cf_protect_login_form"><h3>' . esc_html__('Protect the login form', 'security-ninja') . '</h3>';
						echo '<p class="description">' . __('Protect the login form for repeated login attempts.', 'security-ninja') . '</p>';

						echo '</label></th><td class="sn-cf-options">';

						\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
							WF_SN_CF_OPTIONS_KEY . '_protect_login_form',
							array(
								'saved_value' => $options['protect_login_form'],
								'option_key'  => WF_SN_CF_OPTIONS_KEY . '[protect_login_form]',
							)
						);


						echo '</td></tr>';

						echo '<tr valign="top">';
						echo '<th scope="row"><label class="" for="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_login_msg"><h3>' . esc_html__('Login notice', 'security-ninja') . '</h3>';
						echo '<p class="description">' . esc_html__('Warn people what happens if they fail to login too many times.', 'security-ninja') . '</p>';

						echo '</label></th><td></td></tr>';
						echo '<tr><td colspan="2" class="fullwidth">
				<textarea rows="3" name="' . WF_SN_CF_OPTIONS_KEY . '[login_msg]" id="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_login_msg">' . $options['login_msg'] . '</textarea>';
						echo '</td>';
						echo '</tr>';

						for ($i = 2; $i <= 10; $i++) {
							$max_login_attempts[] = array(
								'val'   => $i,
								'label' => $i,
							);
						}
						for ($i = 2; $i <= 15; $i++) {
							$max_login_attempts_time_s[] = array(
								'val'   => $i,
								'label' => $i,
							);
						}


						// Bruteforce Timeout Options
						$bruteforce_timeouts = array(
							array(
								'val'   => 2,
								'label' => __('2 minutes', 'security-ninja'),
							),
							array(
								'val'   => 10,
								'label' => __('10 minutes', 'security-ninja'),
							),
							array(
								'val'   => 20,
								'label' => __('20 minutes', 'security-ninja'),
							),
							array(
								'val'   => 30,
								'label' => __('30 minutes', 'security-ninja'),
							),
							array(
								'val'   => 60,
								'label' => __('1 hour', 'security-ninja'),
							),
							array(
								'val'   => 120,
								'label' => __('2 hours', 'security-ninja'),
							),
							array(
								'val'   => 1440,
								'label' => __('1 day', 'security-ninja'),
							),
							array(
								'val'   => 2880,
								'label' => __('2 days', 'security-ninja'),
							),
							array(
								'val'   => 10080,
								'label' => __('7 days', 'security-ninja'),
							),
							array(
								'val'   => 43200,
								'label' => __('1 month', 'security-ninja'),
							),
							array(
								'val'   => 525600,
								'label' => __('1 year', 'security-ninja'),
							),
							array(
								'val'   => 5256000,
								'label' => __('forever', 'security-ninja'),
							)
						);


						echo '<tr valign="top">';
						echo '<th scope="row"><label for="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_max_login_attempts" class=""><h3>' . __('Auto-ban rules for failed login and lost password attempts', 'security-ninja') . '</h3>';

						echo '<p class="description">' . esc_html__('Users who continuously make failed login or lost password attempts will get banned. Five failed attempts in five minutes is a good threshold.', 'security-ninja') . '</p>';

						echo '</label></th><td></td></tr>';

						echo '<tr><td class="fullwidth" colspan="2">
						<div class="loginattemptsrow">
						<div>
			<select name="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '[max_login_attempts]" id="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_max_login_attempts">';

						Utils::create_select_options($max_login_attempts, $options['max_login_attempts']);
						echo '</select> failed login/lost password attempts in ';
						echo '</div>';
						echo '<div>';
						echo '<select name="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '[max_login_attempts_time]" id="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_max_login_attempts_time">';
						Utils::create_select_options($max_login_attempts_time_s, $options['max_login_attempts_time']);
						echo '</select> minutes get the IP banned for ';
						echo '</div>';
						echo '<div>';
						echo '<select name="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '[bruteforce_ban_time]" id="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_bruteforce_ban_time">';
						Utils::create_select_options($bruteforce_timeouts, $options['bruteforce_ban_time']);
						echo '</select>';
						echo '</div>';
						echo '</div>';
						echo '</td></tr>';

						echo '<tr valign="top">
			<th scope="row"><label for="wf_sn_cf_blockadminlogin" class=""><h3>' . __('Block "admin" login', 'security-ninja') . '</h3>';
						echo '<p class="description">' . esc_html__('Immediately block anyone trying to log in with the classic username "admin". These are most likely automated attempts to test for weak passwords.', 'security-ninja') . '</p>';

						echo '<p class="description">' . esc_html__('Warning: You should not turn this on if you have a user with username "admin".', 'security-ninja') . '</p>';
						echo '</label></th>
			<td class="sn-cf-options">';

						\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
							WF_SN_CF_OPTIONS_KEY . '_blockadminlogin',
							array(
								'saved_value' => $options['blockadminlogin'],
								'option_key'  => WF_SN_CF_OPTIONS_KEY . '[blockadminlogin]',
							)
						);



						echo '</td></tr>';

						echo '<tr valign="top"><th scope="row"><label for="wf_sn_cf_hide_login_errors" class=""><h3>' . __('Hide login errors', 'security-ninja') . '</h3>';
						echo '<p class="description">' . esc_html__('This makes it harder for automated scripts to see if the account they attempt to log into even exists.', 'security-ninja') . '</p>';

						echo '</label></th><td class="sn-cf-options">';

						\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
							WF_SN_CF_OPTIONS_KEY . '_hide_login_errors',
							array(
								'saved_value' => $options['hide_login_errors'],
								'option_key'  => WF_SN_CF_OPTIONS_KEY . '[hide_login_errors]',
							)
						);


						echo '</td></tr>';

						echo '<tr valign="top"><th scope="row"><label for="wf_sn_cf_failed_login_email_warning"><h3>' . esc_html__('Failed login warnings', 'security-ninja') . '</h3>';
						echo '<p class="description">' . esc_html__('Send email notifications to administrators when someone attempts to log in with their username and fails.', 'security-ninja') . '</p>';

						echo '</label></th><td class="sn-cf-options">';

						\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
							WF_SN_CF_OPTIONS_KEY . '_failed_login_email_warning',
							array(
								'saved_value' => $options['failed_login_email_warning'],
								'option_key'  => WF_SN_CF_OPTIONS_KEY . '[failed_login_email_warning]',
							)
						);


						echo '</td></tr>';

						echo '<tr valign="top">';
						echo '<th scope="row"><label for="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_login_error_msg" class=""><h3>' . esc_html__('Login notice', 'security-ninja'), '</h3>';
						echo '<p class="description">' . esc_html__('Error message to show on failed logins. Default: "Something went wrong".', 'security-ninja') . '</p>';

						echo '</label></th><td></td></tr>';
						echo '<td colspan="2" class="fullwidth">
				<textarea rows="3" name="' . WF_SN_CF_OPTIONS_KEY . '[login_error_msg]" id="' . esc_attr(WF_SN_CF_OPTIONS_KEY) . '_login_error_msg" placeholder="">' . $options['login_error_msg'] . '</textarea>';
						echo '</td>';
						echo '</tr>';


						?>

						<tr valign="top">
							<th scope="row">
							<label for="wf_sn_cf_change_login_url">
									<h3><?php esc_html_e('Change login URL', 'security-ninja'); ?></h3>
									<p><?php esc_html_e('Many automated hacking scripts look for the default wp-login.php file and the default /wp-admin URL to try to bruteforce their way in to your website. Change the default login URL to prevent this from happening.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('Warning: You will not be able to log in without the new URL, please remember to write down this information.', 'security-ninja'); ?></p>
								</label></th>
							<td class="sn-cf-options">

								<?php
								\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_change_login_url',
									array(
										'saved_value' => $options['change_login_url'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[change_login_url]',
									)
								);
								?>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_new_login_url'; ?>" class="">
									<h3><?php esc_html_e('New login slug', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('Only alphanumeric characters, underscore (_) and dash (-) are allowed.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<?php
								$default_login_placeholder = 'my-login';
								if (class_exists(__NAMESPACE__ . '\\SecNin_Rename_WP_Login')) {
									$default_login_placeholder = \WPSecurityNinja\Plugin\SecNin_Rename_WP_Login::$default_login_url;
								}
								?>
								<input type="text" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_new_login_url'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[new_login_url]'; ?>" value="<?php echo $options['new_login_url']; ?>" placeholder="<?php echo esc_attr($default_login_placeholder); ?>" class="regular-text">
								<p><?php esc_html_e('Preview', 'security-ninja'); ?>: <code><?php echo esc_url(trailingslashit(site_url($options['new_login_url']))); ?></code></p>
							</td>
						</tr>
					</tbody>
				</table>
				
				<hr>

				
				<h3><?php esc_html_e('2FA - Two Factor Authentication', 'security-ninja'); ?></h3>
				<table class="form-table">
					<tbody>
						<tr valign="top">
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_enabled'; ?>">
									<h3><?php esc_html_e('Enable 2FA', 'security-ninja'); ?></h3>
									<p class="description"><strong><?php esc_html_e('Warning', 'security-ninja'); ?>:</strong> <?php esc_html_e('Enabling this feature will mandate the setup and use of 2FA for login by the selected user roles.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('When you enable this, the website will ask you next time you log in to set up 2FA.', 'security-ninja'); ?></p>

								</label></th>
							<td class="sn-cf-options"><?php \WPSecurityNinja\Plugin\Utils::create_toggle_switch(
									WF_SN_CF_OPTIONS_KEY . '_2fa_enabled',
									array(
										'saved_value' => $options['2fa_enabled'],
										'option_key'  => WF_SN_CF_OPTIONS_KEY . '[2fa_enabled]',
									)
								);
?>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_grace_period'; ?>" class="">
									<h3><?php esc_html_e('Grace Period', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('How many days to allow users to skip setting up 2FA.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('Note: If you change the number of days after enabling 2FA, the last day will be recalculated.', 'security-ninja'); ?></p>
									<p class="description"><?php esc_html_e('Set the value to 0 to enforce 2FA straight away.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<input type="number" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_grace_period'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_grace_period]'; ?>" value="<?php echo $options['2fa_grace_period']; ?>" class="regular-text" data-1p-ignore>

								<input type="hidden" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_enabled_timestamp'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_enabled_timestamp]'; ?>">
								<?php

								if ($options['2fa_grace_period'] < 1) {
									echo '<p class="description">' . esc_html__('Setting this to 0 will require all users to set up 2FA immediately.', 'security-ninja') . '</p>';
								}
								if ($options['2fa_enabled']) {

									if (isset($options['2fa_enabled_timestamp']) && '' !== $options['2fa_enabled_timestamp']) {
										$enabled_timestamp = $options['2fa_enabled_timestamp'];
										// use the value in $options['2fa_grace_period'] as a day value to calulate the cutoff time. You can use the $enabled_timestamp as the starting point when the 2FA was last enabled
										$cutoff_time = strtotime('+' . $options['2fa_grace_period'] . ' days', $enabled_timestamp);

										$current_time = current_time('timestamp');
										if ($current_time < $cutoff_time) {
											$formatted_cutoff_time = date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $cutoff_time);
											$time_diff = human_time_diff($current_time, $cutoff_time);
											echo '<p class="description">' . sprintf(esc_html__('The grace period will end on %s, which is in about %s.', 'security-ninja'), $formatted_cutoff_time, $time_diff) . '</p>';
										} else {
											echo '<p class="description">' . esc_html__('The grace period has ended. Two-factor authentication is now enforced for all selected users.', 'security-ninja') . '</p>';
										}
									}
								}
								?>
							</td>
						</tr>

						<tr>
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_required_roles'; ?>" class="">
									<h3><?php esc_html_e('Required Roles', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('Only the selected roles will be required to use 2FA when logging in.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<ul class="sn-2fa-required-roles">
									<?php
									$editable_roles = get_editable_roles();
									$selected_roles = isset($options['2fa_required_roles']) ? (array) $options['2fa_required_roles'] : array();

									foreach ($editable_roles as $role => $details) {
										$name = translate_user_role($details['name']);
										$checked = in_array($role, $selected_roles) ? 'checked' : '';
									?>
										<li>
											<label>
												<input type="checkbox" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_required_roles'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_required_roles][]'; ?>" value="<?php echo esc_attr($role); ?>" <?php echo $checked; ?>>
												<?php echo esc_html($name); ?>
											</label>
										</li>
									<?php
									}
									?>
								</ul>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_methods'; ?>" class="">
									<h3><?php esc_html_e('2FA Methods', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('Allowed login methods.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<?php
								$selected_method = 'app';
								if (isset($options['2fa_methods'])) {
									if (is_array($options['2fa_methods']) && !empty($options['2fa_methods'])) {
										$selected_method = $options['2fa_methods'][0];
									} elseif (!is_array($options['2fa_methods'])) {
										$selected_method = $options['2fa_methods'];
									}
								}
								?>
								<input type="radio" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_methods_app'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_methods]'; ?>" value="app" <?php checked($selected_method, 'app'); ?>>
								<label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_methods_app'; ?>"><?php esc_html_e('Application', 'security-ninja'); ?></label>
								<p class="description"><?php esc_html_e('Use a 2FA application like Google Authenticator or Authy to generate a code.', 'security-ninja'); ?></p>
							</td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<input type="radio" id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_methods_email'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_methods]'; ?>" value="email" <?php checked($selected_method, 'email'); ?>>
								<label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_methods_email'; ?>"><?php esc_html_e('Email', 'security-ninja'); ?></label>
								<p class="description"><?php esc_html_e('Send a code to the user\'s email address.', 'security-ninja'); ?></p>
							</td>
						</tr>


						<tr valign="top">
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_intro'; ?>" class="">
									<h3><?php esc_html_e('2FA Introduction', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('This text will be displayed to users when they are prompted to set up two-factor authentication.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">

								<textarea id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_intro'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_intro]'; ?>" rows="3"><?php echo $options['2fa_intro']; ?></textarea>
							</td>
						</tr>


						<tr valign="top">
							<th scope="row"><label for="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_enter_code'; ?>" class="">
									<h3><?php esc_html_e('2FA Enter Code', 'security-ninja'); ?></h3>
									<p class="description"><?php esc_html_e('Shown next to the input field where the user enters their code.', 'security-ninja'); ?></p>
								</label></th>
							<td></td>
						</tr>
						<tr>
							<td colspan="2" class="fullwidth">
								<textarea id="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '_2fa_enter_code'; ?>" name="<?php echo esc_attr(WF_SN_CF_OPTIONS_KEY) . '[2fa_enter_code]'; ?>" rows="3"><?php echo $options['2fa_enter_code']; ?></textarea>
							</td>
						</tr>

					</tbody>
				</table>
				<?php else: ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td colspan="2">
								<div class="sncard infobox">
									<div class="inner">
										<h3><?php esc_html_e('Upgrade to Pro for Advanced Login Protection', 'security-ninja'); ?></h3>
										<p><?php esc_html_e('The free version provides basic login and failed login event logging. Upgrade to Security Ninja Pro to unlock powerful login protection features:', 'security-ninja'); ?></p>
										<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
											<li><?php esc_html_e('Advanced login form protection with brute force detection', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Auto-ban rules for failed login attempts', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Block "admin" username login attempts', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Hide login errors to prevent username enumeration', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Email warnings for failed login attempts', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Change login URL to hide wp-login.php', 'security-ninja'); ?></li>
											<li><?php esc_html_e('Two-Factor Authentication (2FA) for enhanced security', 'security-ninja'); ?></li>
										</ul>
										<p style="margin-top: 15px;">
											<a href="<?php echo esc_url(secnin_fs()->get_upgrade_url()); ?>" class="button button-primary"><?php esc_html_e('Upgrade to Pro', 'security-ninja'); ?></a>
										</p>
									</div>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
				<?php endif; ?>

<?php
} 