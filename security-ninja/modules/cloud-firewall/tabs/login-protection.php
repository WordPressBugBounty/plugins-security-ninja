<?php

/**
 * Cloud Firewall Login Protection
 *
 * This file contains the login protection form content for the Cloud Firewall module.
 */
namespace WPSecurityNinja\Plugin;

// Prevent direct access
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
if ( !class_exists( 'Wf_sn_cf' ) ) {
    return;
}
/**
 * Render the login protection form content
 *
 * @param array $options Current options
 */
function wf_sn_cf_render_login_protection_content(  $options  ) {
    ?>

<table class="form-table">
					<tbody>
						<?php 
    ?>
				<table class="form-table">
					<tbody>
						<tr>
							<td colspan="2">
								<div class="sncard infobox">
									<div class="inner">
										<h3>Upgrade to Pro for Advanced Login Protection</h3>
										<p>The free version provides basic login and failed login event logging. Upgrade to Security Ninja Pro to unlock powerful login protection features:</p>
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
    echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'upgrade_tab_login_protection', '/pricing/' ) );
    ?>" class="button button-primary button-small" target="_blank" rel="noopener">Upgrade to Pro</a>
										</p>
									</div>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
				<?php 
    ?>

	<?php 
}
