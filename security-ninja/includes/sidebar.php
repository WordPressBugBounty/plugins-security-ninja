<?php

namespace WPSecurityNinja\Plugin;

// this is an include only WP file
if ( !defined( 'ABSPATH' ) ) {
    die;
}
global $secnin_fs;
?>
<div class="secnin_content_cell" id="sidebar-container">

	<div class="sidebarsection feature">
		<h3><span class="dashicons dashicons-info-outline"></span> <?php 
esc_html_e( 'Learn more', 'security-ninja' );
?></h3>
		<ul class="linklist">
			<li><a href="<?php 
echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/security-tests/' ) );
?>" target="_blank" rel="noopener"><?php 
esc_html_e( 'About the tests', 'security-ninja' );
?></a></li>
			<li><a href="<?php 
echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/why-is-insignificant-small-site-attacked-by-hackers/' ) );
?>" target="_blank" rel="noopener"><?php 
esc_html_e( 'Even small sites are attacked by hackers', 'security-ninja' );
?></a></li>
			<li><a href="<?php 
echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/wordpress-beginner-mistakes/' ) );
?>" target="_blank" rel="noopener"><?php 
esc_html_e( 'New to WordPress? avoid these beginner mistakes', 'security-ninja' );
?></a></li>
			<li><a href="<?php 
echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/signs-wordpress-site-is-hacked/' ) );
?>" target="_blank" rel="noopener"><?php 
esc_html_e( 'Signs that your site has been hacked', 'security-ninja' );
?></a></li>

		</ul>
	</div><!-- .sidebarsection -->


	<?php 
if ( function_exists( 'secnin_fs' ) ) {
    $display_promotion = true;
    if ( $display_promotion ) {
        ?>
			<div class="snupgradebox sidebarsection feature">
				<h3><span class="dashicons dashicons-star-filled"></span> Security Ninja Pro <span class="dashicons dashicons-star-filled"></span></h3>
				<ul class="checkmarks">
					<li><strong><?php 
        esc_html_e( 'Install Wizard', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'get protected in minutes.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Firewall Protection', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Protect your website from suspicious visitors.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Spam Protection', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'The firewall blocks known spammers.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Login Protection', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Stop repeated failed logins.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Rename Login', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Change the default WordPress login URL.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( '2FA', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Add two factor authentication to your WordPress login.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Country Blocking', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Block entire countries.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Core Scanner', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Detect infected WordPress core files.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Plugin Validation', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Check plugins have not been modified with malware.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Malware Scanner', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Find and remove suspicious files.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Auto Fixer', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Fix many security issues with a few clicks.', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Events Logger', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Audit log - Know who did what on your website', 'security-ninja' );
        ?></li>
					<li><strong><?php 
        esc_html_e( 'Scheduled Scanner', 'security-ninja' );
        ?></strong> - <?php 
        esc_html_e( 'Scan your website for security issues at a specific time.', 'security-ninja' );
        ?></li>
				</ul>
				<p><strong><?php 
        esc_html_e( 'Try the Pro version free for 30 days!', 'security-ninja' );
        ?></strong></p>
				<a href="<?php 
        echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/pricing/' ) );
        ?>" class="button button-primary trial-button" target="_blank" rel="noopener"><?php 
        echo 'Get started';
        ?></a>
				<div class="wrap-collabsible">
					<input id="collapsible-payment-details" class="toggle" type="checkbox">
					<label for="collapsible-payment-details" class="lbl-toggle">Click to see details</label>
					<div class="collapsible-content">
						<div class="content-inner">

							<ul class="salenotices">
								<li><?php 
        esc_html_e( 'We ask for your payment information to reduce fraud and provide a seamless subscription experience.', 'security-ninja' );
        ?></li>
								<li><?php 
        esc_html_e( 'CANCEL ANYTIME before the trial ends to avoid being charged.', 'security-ninja' );
        ?></li>
								<li><?php 
        esc_html_e( 'We will send you an email reminder BEFORE your trial ends.', 'security-ninja' );
        ?></li>
								<li><?php 
        esc_html_e( 'We accept Visa, Mastercard, American Express and PayPal.', 'security-ninja' );
        ?></li>
								<li><?php 
        esc_html_e( 'Upgrade, downgrade or cancel any time.', 'security-ninja' );
        ?></li>
								<li><?php 
        esc_html_e( 'Bulk discounts for more websites.', 'security-ninja' );
        ?></li>
							</ul>
							<p><a href="<?php 
        echo esc_url( Utils::generate_sn_web_link( 'sidebar_link', '/pricing/' ) );
        ?>" target="_blank" class="button button-primary" rel="noopener"><?php 
        esc_html_e( 'Read more about the Pro version', 'security-ninja' );
        ?></a></p>

						</div>
					</div>
				</div>
			</div><!-- .snupgradebox -->
	<?php 
    }
}
?>
	<div class="sidebarsection feature">
		<h3><span class="dashicons dashicons-info-outline"></span> <?php 
esc_html_e( 'Plugin help', 'security-ninja' );
?></h3>
		<ul class="linklist">
			<?php 
global $secnin_fs;
?>
			<li><a href="<?php 
echo esc_url( 'https://wordpress.org/support/plugin/security-ninja/' );
?>" target="_blank" rel="noopener"><?php 
esc_html_e( 'Support Forum', 'security-ninja' );
?></a></li>
			<?php 
if ( secnin_fs()->is_not_paying() ) {
    ?>
				<li><a href="<?php 
    echo esc_url( secnin_fs()->connect_again() );
    ?>"><?php 
    esc_html_e( 'Activate License', 'security-ninja' );
    ?></a></li>

			<?php 
}
?>
		</ul>
	</div><!-- .sidebarsection -->
	<?php 
$show_pro_ad = false;
if ( secnin_fs()->is_not_paying() && $show_pro_ad ) {
    ?>
		<div class="sidebarsection feature upgradepro">
			<h3>Effortless Security for Your Site!</h3>
			<ul>
				<li><strong>Easy Setup:</strong> Install in minutes, no technical skills required.</li>
				<li><strong>Automatic Protection:</strong> Real-time firewall and automated scans.</li>
				<li><strong>Spam &amp; Bot Blocking:</strong> Keeps your site clean and visitors safe.</li>
				<li><strong>Secure Logins:</strong> Protect your login page from attacks.</li>
			</ul>
			<p>
				<em>Upgrade to Pro and get effortless security today!</em>
			</p>

			<p style="margin-top: 10px;text-align: center;">
				<a href="https://wpsecurityninja.com/pricing/?utm_source=overview-tab&amp;utm_medium=plugin&amp;utm_content=explore-pro&amp;utm_campaign=security_ninja_v5.235" class="" target="_blank">Get started now!</a><br><small>30-days money back guarantee</small>
			</p>
		</div>
	<?php 
}
?>
</div><!-- #sidebar-container --><?php 