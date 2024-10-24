<?php
/*
 * Security Ninja
 * Test descriptions and help
 * (c) 2011 - 2024 WP Security Ninja
 */
?>
<div class="sn_test_details" id="application_passwords">
	<div class="test_name">
		<?php esc_html_e( 'Checks if Application Passwords feature is enabled.', 'security-ninja' ); ?>
	</div>
	<div class="test_description">
		<p><?php esc_html_e( 'A new feature introduced in WordPress 5.6', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Allows you to give external systems access to control your website via generated passwords.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'No known exploits are known, but if you do not need this feature there is no need to leave it on.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'You can disable this feature by adding this single line of code to your functions.php:', 'security-ninja' ); ?></p>
		<p><code>add_filter(&#39;wp_is_application_passwords_available&#39;, &#39;__return_false&#39;);</code>
		</p>
	</div>
</div>



<div class="sn_test_details" id="dangerous_files">
	<div class="test_name">
		<?php esc_html_e( 'Searches for unwanted files in your root folder.', 'security-ninja' ); ?>

	</div>
	<div class="test_description">
		<p><?php esc_html_e( 'This test looks for typical files that are sometimes left in your website root folder. These files can contain sensitive information or error details.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'You should remove any non-used files from your website root folder', 'security-ninja' ); ?></p>
	</div>
</div>



<div class="sn_test_details" id="strict_transport_security">
	<div class="test_name">
		<?php esc_html_e( 'Check if server response headers contain Strict-Transport-Security', 'security-ninja' ); ?>
	</div>
	<div class="test_description">
		<p><?php esc_html_e( 'Instructs your webserver to only use HTTPS and not allow HTTP insecure connections.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'It is important you verify your website has a SSL certificate and it is working correctly before implementing this.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Setting up is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
		<pre>header('Strict-Transport-Security: max-age=31536000;');</pre>

		<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
<pre>#BEGIN - Forces only HTTPS
	&lt;IfModule mod_headers.c&gt;
	Header set Strict-Transport-Security "max-age=31536000;"
	&lt;/IfModule&gt;
#END - Forces only HTTPS</pre>
		<p><?php esc_html_e( 'You can add "includeSubDomains" if you want this to include any subdomains you might have.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
		<pre>add_header Strict-Transport-Security "max-age=31536000;";</pre>

		<p>Further reading and test: <a href="https://hstspreload.org" target="_blank" rel="noopener">https://hstspreload.org</a></p>
	</div>
</div>



<div class="sn_test_details" id="content_security_policy">
	<div class="test_name"><?php esc_html_e( 'Check if server response headers contain Content-Security-Policy', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'This limits any browser visiting your website to only load content from approved sources.', 'security-ninja' ); ?></p>

		<p><strong>Warning: <?php esc_html_e( 'If you embed scripts from external websites, Google Analytics or other sources this could break your website functionality. Read and test before implementing.', 'security-ninja' ); ?></strong></p>
		<p><?php esc_html_e( 'Since each website is different, we can only give a general suggestion and strongly advise to remove the fix again if something on your website stops working.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'This example forces a browser to only load JavaScript .js files from your own website. Warning: Inline code will stop working. Add this to your .htaccess file', 'security-ninja' ); ?></p>
<pre>#BEGIN - Only allow browsers to load .js files from this website
	# Use Content-Security-Policy-Report-Only to test settings before using Content-Security-Policy.
	# Once you have fixed any problems, you can change to
	# Header set Content-Security-Policy: ...
	
	&lt;IfModule mod_headers.c&gt;
	Header set Content-Security-Policy-Report-Only: "script-src 'self'"
	&lt;/IfModule&gt;
#END - Only allow browsers to load .js files from this website</pre>

			<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
			<pre>add_header X-Frame-Options SAMEORIGIN;</pre>

			<p>Scott Helme is a security researcher and has written a really indepth walkthrough of Content Security Policy.<a href="https://scotthelme.co.uk/content-security-policy-an-introduction/" target="_blank" rel="noopener">Content Security Policy - An Introduction</a>.</p>
		</div>
	</div>






	<div class="sn_test_details" id="x_frame_options">
		<div class="test_name"><?php esc_html_e( 'Check if server response headers contain X-Frame-Options', 'security-ninja' ); ?></div>
		<div class="test_description"><p><?php esc_html_e( 'The X-Frame-Options response header indicates if a page is allowed to render a page in an iframe, frame or object. Avoid clickjacking attacks simply by not allowing your content to be embedded on other websites.', 'security-ninja' ); ?></p>

			<p><strong><?php esc_html_e( 'Warning: The fix is easy, but some sites have problems with the theme customizer preview when this code is enabled.', 'security-ninja' ); ?></strong></p>

			<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
			<pre>header('X-Frame-Options: SAMEORIGIN');</pre>

			<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
<pre>#BEGIN - Prevent page-framing and click-jacking
	&lt;IfModule mod_headers.c&gt;
	Header always append X-Frame-Options SAMEORIGIN
	&lt;/IfModule&gt;
#END - Prevent page-framing and click-jacking</pre>
			<p>

				<p><?php esc_html_e( 'You can use the following values: DENY, SAMEORIGIN or ALLOW-FROM', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'WARNING: If you use iframes on your website you need to be careful configuring this.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header X-Frame-Options "SAMEORIGIN";</pre>

				<p><?php
				// translators: %s is a link to GeekFlare article about X-Frame-Options
				printf(
					esc_html__( 'Read more about %s.', 'security-ninja' ),
					'<a href="https://geekflare.com/http-header-implementation/#X-Frame-Options" target="_blank" rel="noopener">' . esc_html__( 'the different options on GeekFlare', 'security-ninja' ) . '</a>'
				);
				?></p>
			</div>
		</div>



		<div class="sn_test_details" id="x_content_type_options">
			<div class="test_name"><?php esc_html_e( 'Check if server response headers contain X-Content-Type-Options', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( 'Setting this will force a browser to only load external resources if the content-type matches what is expected. This prevents malicious hidden code in unexpected files', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
				<pre>header('X-Content-Type-Options: nosniff');</pre>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
<pre>#BEGIN - Prevent code in unexpected files
	&lt;IfModule mod_headers.c&gt;
	Header set X-Content-Type-Options nosniff
	&lt;/IfModule&gt;
#END - Prevent code in unexpected files</pre>
				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header X-Content-Type-Options nosniff;</pre>
			</div>
		</div>


		<div class="sn_test_details" id="feature_policy">
			<div class="test_name"><?php esc_html_e( 'Check if server response headers contain Permissions-Policy', 'security-ninja' ); ?></div>
			<div class="test_description">
				<p><?php esc_html_e( 'This is a way to instruct a browser which features it can use on a website.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'With this you can explitly prevent access to the camera, microphone, geolocation and many other features.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'For a full and updated list check out the link.', 'security-ninja' ); ?> <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy" target="_blank" rel="noopener">Mozilla.org - Permissions Policy</a></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
<pre>header("Permissions-Policy: accelerometer 'none' ; ambient-light-sensor 'none' ; autoplay 'none' ; camera 'none' ; encrypted-media 'none' ; fullscreen 'none' ; geolocation 'none' ; gyroscope 'none' ; magnetometer 'none' ; microphone 'none' ; midi 'none' ; payment 'none' ; speaker 'none' ; sync-xhr 'none' ; usb 'none' ; notifications 'none' ; vibrate 'none' ; push 'none' ; vr 'none' ");</pre>

				<p><?php esc_html_e( 'NOTE: This example disables everything, so if you have website that uses some of the features please check the link to Mozilla on more details on how to finetune.', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>

<pre>
	#BEGIN - Set Permissions-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Permissions-Policy "accelerometer 'none' ; ambient-light-sensor 'none' ; autoplay 'none' ; camera 'none' ; encrypted-media 'none' ; fullscreen 'none' ; geolocation 'none' ; gyroscope 'none' ; magnetometer 'none' ; microphone 'none' ; midi 'none' ; payment 'none' ; speaker 'none' ; sync-xhr 'none' ; usb 'none' ; notifications 'none' ; vibrate 'none' ; push 'none' ; vr 'none' "
	&lt;/IfModule&gt;
	#END - Set Permissions-Policy
</pre>
				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
<pre>add_header Permissions-Policy "accelerometer 'none'; autoplay 'none'; camera 'none'; encrypted-media 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; sync-xhr 'none'; usb 'none';";</pre>

			</div>
		</div>





		<div class="sn_test_details" id="referrer_policy">
			<div class="test_name"><?php esc_html_e( 'Check if server response headers contain Referrer-Policy', 'security-ninja' ); ?></div>
			<div class="test_description">
				<p><?php esc_html_e( 'Referrer-Policy is a way to control when the "referrer" header information is allowed.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'This means which websites can see where visitors are referred from.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'The recommended setting "same-origin" allows you to still track data internally on your website, but no other website will know that a visitor came from a link on your website.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>

				<pre>header('Referrer-Policy: same-origin');</pre>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>

<pre>
	#BEGIN - Set Referrer-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Referrer-Policy "same-origin"
	&lt;/IfModule&gt;
	#END - Set Referrer-Policy
</pre>

				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header Referrer-Policy same-origin;</pre>

			</div>
		</div>


		<div class="sn_test_details" id="rest_api_links">
			<div class="test_name"><?php esc_html_e( 'Check if the REST API links are shown in code', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( 'WordPress comes with a powerful REST API system that allows access to different data in a structured format. We recommend you disable these links showing in the header.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
<pre>
remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
remove_action('wp_head', 'rest_output_link_wp_head');
remove_action('template_redirect', 'rest_output_link_header', 11, 0);</pre>
			</div>
		</div>


		<div class="sn_test_details" id="ver_check">
			<div class="test_name"><?php esc_html_e( 'Check if WordPress core is up to date', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( 'Keeping the WordPress core up to date is one of the most important aspects of site security. If vulnerabilities are discovered in WordPress and a new version is released to address the issue, the information required to exploit the vulnerability is definitely in the public domain. This makes old versions more open to attacks, and is one of the primary reasons you should always keep WordPress up to date.', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'Thanks to automatic updates, upgrading is now very simple. Navigate to the "Dashboard - Updates" page and click the "Update Now" button.', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'Important: Always create a backup of your files and database before performing any upgrades!', 'security-ninja' ); ?></p>
			</div>
		</div>



		<div class="sn_test_details" id="core_updates_check">
			<div class="test_name"><?php esc_html_e( 'Check if automatic core updates are enabled', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( "Unless you're running a highly customized WordPress site wich requires rigorous testing of all updates we recommend having automatic minor core updates enabled. These are usually security fixes that don't alter WP in any significant way and should be applied as soon as WP releases them.", 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'Updates can be disabled via constants in wp-config.php or by a plugin. For details please see', 'security-ninja' ); ?> <a href="http://codex.wordpress.org/Configuring_Automatic_Background_Updates" target="_blank" rel="noopener"><?php esc_html_e( 'WP Codex', 'security-ninja' ); ?></a>.</p>
			</div>
		</div>



		<div class="sn_test_details" id="plugins_ver_check">
			<div class="test_name"><?php esc_html_e( 'Check if plugins are up to date', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( "As with the WordPress core, keeping plugins up to date is one of the most important and easiest ways to keep your site secure. Since most plugins are free and therefore their code is available to anyone, having the latest version will ensure you're not prone to attacks based on known vulnerabilities.", 'security-ninja' ); ?></p>
				<p>
				<?php
					printf(
						wp_kses(
							__( 'If you downloaded a plugin from the official WP repository you can easily check if there are any updates available, and update it by opening <a target="_blank" href="%s">Dashboard - Updates</a>. If you bought the plugin from somewhere else check the item\'s support on instructions how to upgrade manually. <b>Remember</b> - always backup your files and database before upgrading!', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
								'b' => array(),
							)
						),
						esc_url( admin_url( 'update-core.php' ) )
					);
					?>
				</p>
			</div>
		</div>



		<div class="sn_test_details" id="deactivated_plugins">
			<div class="test_name"><?php esc_html_e( 'Check if there are any deactivated plugins', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( 'If you are not using a plugin remove it from the WP plugins folder. It is that simple. There is no reason to keep it there and in case the code is malicious or it has some vulnerabilities it can still be exploited by a hacker regardless of the fact the plugin is not active.', 'security-ninja' ); ?></p>
				<p>
				<?php
					printf(
						wp_kses(
							__( 'Open <a target="_blank" href="%s">plugins</a> and simply delete all plugins that are not active. Or login via FTP and move them to some folder that\'s not /wp-content/plugins/.', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
							)
						),
						esc_url( admin_url( 'plugins.php?plugin_status=inactive' ) )
					);
					?>
				</p>
			</div>
		</div>



		<div class="sn_test_details" id="themes_ver_check">
			<div class="test_name"><?php esc_html_e( 'Check if themes are up to date', 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( "As with the WordPress core, keeping the themes up to date is one of the most important and easiest ways to keep your site secure. Since most themes are free and therefore their code is available to anyone having the latest version will ensure you're not prone to attacks based on known vulnerabilities. Also, having the latest version will ensure your theme is compatible with the latest version of WordPress.", 'security-ninja' ); ?></p>
				<p>
				<?php
						printf(
							wp_kses(
								__( 'If you downloaded a theme from the official WP repository you can easily check if there are any updates available, and upgrade it by opening <a target="_blank" href="%s">Appearance - Themes</a>. If you bought the theme from a theme shop check their support and upgrade manually. <b>Remember</b> - always backup your files and database before upgrading!', 'security-ninja' ),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
									'b' => array(),
								)
							),
							esc_url( 'themes.php' )
						);
						?>
				</p>
			</div>
		</div>



		<div class="sn_test_details" id="deactivated_themes">
			<div class="test_name"><?php esc_html_e( 'Check if there are any unnecessary themes installed', 'security-ninja' ); ?></div>
			<div class="test_description">
					<p><?php esc_html_e( "If you're not using a theme remove it from the WP themes folder. There's no reason to keep it there and in case the code is malicious or it has some vulnerabilities it can still be exploited by a hacker regardless of the fact the theme is not active.", 'security-ninja' ); ?></p>
					<p><em><?php esc_html_e( 'Note: To accommodate the WP Health Test, the test filters out the latest default WP theme you have installed.', 'security-ninja' ); ?></em></p>
					<p>
					<?php
							printf(
								wp_kses(
									__( 'Open <a target="_blank" href="%s">Appearance - Themes</a> and use the list above to delete the themes you do not need.', 'security-ninja' ),
									array(
										'a' => array(
											'href'   => array(),
											'target' => array(),
										),
									)
								),
								esc_url( 'themes.php' )
							);
							?>
					</p>
			</div>
			</div>



		<div class="sn_test_details" id="wp_header_meta">
			<div class="test_name"><?php esc_html_e( "Check if full WP version info is revealed in page's meta data", 'security-ninja' ); ?></div>
			<div class="test_description"><p><?php esc_html_e( "You should be proud that your site is powered by WordPress and there's no need to hide that information. However disclosing the full WP version info in the default location (page header meta) is not wise. People with bad intentions can easily use Google to find site's that use a specific version of WordPress and target them with (0-day) exploits.", 'security-ninja' ); ?></p>
				<p><?php esc_html_e( "Place the following code in your theme's functions.php file in order to remove the header meta version info:", 'security-ninja' ); ?></p>
				<pre>function remove_version() {
					return '';
				}
			add_filter('the_generator', 'remove_version');</pre>
		</div>
	</div>


	<div class="sn_test_details" id="php_headers">
		<div class="test_name"><?php esc_html_e( 'Check if server response headers contain detailed PHP version info', 'security-ninja' ); ?></div>
		<div class="test_description"><p><?php esc_html_e( 'As with the WordPress version it is not wise to disclose the exact PHP version you are using because it makes the job of attacking your site much easier.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( 'This issue is not directly WP related but it definitely affects your site.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( 'You will most probably have to ask your hosting company to configure the HTTP server not to show PHP version info but you can also try adding these directives to the .htacces file:', 'security-ninja' ); ?></p>
<pre>#BEGIN - Hide PHP version in header
	&lt;IfModule mod_headers.c&gt;
	Header unset X-Powered-By
	Header unset Server
	&lt;/IfModule&gt;
#END - Hide PHP version in header</pre>
		</div>
	</div>

	<div class="sn_test_details" id="user_exists">
		<div class="test_name"><?php esc_html_e( 'Check if user with username "admin" exists', 'security-ninja' ); ?></div>
		<div class="test_description"><p><?php esc_html_e( 'If someone tries to guess your username and password or tries a brute-force attack they will most probably start with username "admin". This is the default username used by too many sites and should be removed.', 'security-ninja' ); ?></p>
			<p>
			<?php
					printf(
						wp_kses(
							__( 'Create a new user and assign him the "administrator" role. Try not to use usernames like: "root", "god", "null" or similar ones. Once you have the new user created delete the "admin" one and assign all post/pages he may have created to the new user.', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
							)
						),
						esc_url( 'user-new.php' )
					);
					?>
			</p>
		</div>
	</div>

	<div class="sn_test_details" id="check_failed_login_info">
		<div class="test_name"><?php esc_html_e( 'Check for display of unnecessary information on failed login attempts', 'security-ninja' ); ?></div>
		<div class="test_description"><p><?php esc_html_e( 'By default on failed login attempts WordPress will tell you whether username or password is wrong. An attacker can use that to find out which usernames are active on your system and then use brute-force methods to hack the password.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( "The solution to this problem is simple. Whether user enters a wrong username or wrong password we always tell him 'wrong username or password' so that he does not know which of the two is wrong. Open your theme's functions.php file and copy/paste the following code:", 'security-ninja' ); ?></p>
			<pre>function wrong_login() {
				return 'Wrong username or password.';
			}
		add_filter('login_errors', 'wrong_login');</pre>
	</div>
</div>

<div class="sn_test_details" id="salt_keys_check">
	<div class="test_name"><?php esc_html_e( 'Check if all security keys and salts have proper values', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( "Security keys are used to ensure better encryption of information stored in the user's cookies and hashed passwords. They make your site harder to hack and access harder to crack by adding random elements to the password. You don't have to remember these keys. In fact once you set them you'll never see them again. Therefore there's no excuse for not setting them properly.", 'security-ninja' ); ?></p>
		<p>
		<?php
				$translation = __( 'Security keys (there are eight) are defined in wp-config.php as constants on lines #49-56. They should be as unique and as long as possible. WordPress made a great script which helps you generate those strings. Please use it! After the script generates strings those 8 lines of code should look something like this:', 'security-ninja' );

				printf(
					wp_kses_post(
						'%s <a target="_blank" href="%s" rel="noopener">' . esc_html__( 'Get new security keys', 'security-ninja' ) . '</a>',
						array(
							'a' => array(
								'href'   => array(),
								'target' => array(),
								'rel'    => array(),
							),
						)
					),
					esc_html( $translation ),
					esc_url( 'https://api.wordpress.org/secret-key/1.1/salt/' )
				);
				?>
		</p>
		<pre>define('AUTH_KEY',         '}D4@p&lt;0VFKb*pdhM8c&lt;bb:qB%Fr8:- dc}U(,[K?hobrzsn*:r?,e^/eHsm6nHls');
			define('SECURE_AUTH_KEY',  'M2wEPuf7.%FWW1xvy]ar&amp;vy3gj,:1Go&gt;qs7d_N)nX}O[-(+AaDsiPbvAOdLG~dt}');
			define('LOGGED_IN_KEY',    'iA#+3)Xhf0E*oyN1A4#:0wVp|d&lt;F-rQQ Sf_HNMk,rVj,F,GdKF|b-:xBEM,y(,f');
			define('NONCE_KEY',        'ctGmyOSSfm1-WR/V:J6[;Zh|?a$slsWs_9BIKcM[}uh~+C|R}ylW4cU%D tIOG=d');
			define('AUTH_SALT',        '|@tYo .T&amp;-{wMmP&gt;ggj4p{,HKs!&gt;vsUXz/aPDlZ=1.D54m+#1xyt+%w)3r&amp;j]r?:');
			define('SECURE_AUTH_SALT', '`^mxb~AvK*Agn+h&gt;U!0GL2*2|R+HHyY%h1b%Aoo,Jy|M{}TP`mSTt&lt;fcm=O9`=bA');
			define('LOGGED_IN_SALT',   'Ow||n$:: HWM5%H7k+MW7{!Z[Z|G-UJZ6Pp8;Id^&lt;lK-&amp;W+}Q?wHw!xlp2g(1% w');
			define('NONCE_SALT',       'IoLWhDF-d&lt;&gt;`u}R4oEe5kXf+)&lt;.}Ib?BPE&lt;C9R=NQivhZ|8k^b@LhkpuqojnzdVI');
		</pre>

		<p><b><?php esc_html_e( 'Warning', 'security-ninja' ); ?></b>: <?php esc_html_e( 'Do NOT use the keys above. They are just an example, publicly available and therefore not safe. Generate your own ones.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="salt_keys_age_check">
	<div class="test_name"><?php esc_html_e( 'Check if security keys and salts have been updated in the last 3 months', 'security-ninja' ); ?></div>
	<div class="test_description">
			<p><?php esc_html_e( "It's recommended to change the security keys and salts once in a while. The process will invalidate all existing cookies. This does mean that all users will have to login again. It's a minor inconvenience that will ensure nobody can login with an old or stolen cookie.", 'security-ninja' ); ?></p>
			<p>
			<?php
					printf(
						wp_kses(
							__( 'To edit the keys open wp-config.php, <a target="_blank" href="%s" rel="noopener">generate new keys</a> and copy/paste them to overwrite the old ones.', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
									'rel'    => array(),
								),
							)
						),
						esc_url( 'https://api.wordpress.org/secret-key/1.1/salt/' )
					);
					?>
			</p>
	</div>
</div>


<div class="sn_test_details" id="db_password_check">
	<div class="test_name"><?php esc_html_e( 'Test the strength of WordPress database password', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'There is no such thing as an "unimportant password"! The same goes for WordPress database password. Although most servers are configured so that the database cannot be accessed from other hosts (or from outside of the local network) that does not mean your database passsword should be "12345".', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Choose a proper password, at least 12 characters long with a combination of letters, numbers and special characters.', 'security-ninja' ); ?></p>
		<h3><?php esc_html_e( 'To change the database password', 'security-ninja' ); ?></h3>
		<p><?php esc_html_e( '1. Open cPanel, Plesk or any other hosting control panel you have. Find the option to change the database password and make the new password strong enough. If you cannot find that option or you are uncomfortable changing it contact your hosting provider. After the password is changed open wp-config.php and change the password', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( '2. After the password is changed open wp-config.php and change the password', 'security-ninja' ); ?></p>
<pre>/** MySQL database password */
define('DB_PASSWORD', 'YOUR_NEW_DB_PASSWORD_GOES_HERE');
</pre>
<p><strong><?php esc_html_e( 'IMPORTANT: While you are changing the password your website will be offline.', 'security-ninja' ); ?></strong></p>
<p><?php esc_html_e( 'Random password suggestions - Feel free to use or make your own. Remember to change the database password BOTH places.', 'security-ninja' ); ?></p>
<ul>
<?php
for ( $i = 0; $i < 3; $i++ ) {

	echo '<li>' . esc_html( wp_generate_password( 24, true, false ) ) . '</li>';
}

?>
</ul>
</div>
</div>

<div class="sn_test_details" id="db_table_prefix_check">
	<div class="test_name"><?php esc_html_e( 'Check if database table prefix is the default "wp_"', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Knowing the names of your database tables can help an attacker dump the table\'s data and get to sensitive information like password hashes. Since WP table names are predefined the only way you can change table names is by using a unique prefix. One that\'s different from "wp_" or any similar variation such as "wordpress_".', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you\'re doing a fresh installation defining a unique table prefix is easy. Open wp-config.php and go to line #61 where the table prefix is defined. Enter something unique like "frog99_" and install WP.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you already have WP site running and want to change the table prefix things are a bit more complicated and you should only do the change if you\'re comfortable doing some changes to your DB data via phpMyAdmin or a similar GUI.', 'security-ninja' ); ?></p>
		<p><strong><?php esc_html_e( 'Remember', 'security-ninja' ); ?></strong> - <?php esc_html_e( 'Always backup your files and database before making any changes to the database!', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="debug_check">
	<div class="test_name"><?php esc_html_e( 'Check if site debug mode is enabled', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Having any kind of debug mode (general WP debug mode in this case) or error reporting mode enabled on a production site is extremely bad. Not only will it slow down your site, confuse your visitors with weird messages it will also give the potential attacker valuable information about your system.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'General WordPress debugging mode is enabled/disabled by a constant defined in wp-config.php. Open that file and look for a line similar to:', 'security-ninja' ); ?></p>
		<pre>define('WP_DEBUG', true);</pre>
		<p><?php esc_html_e( 'Comment it out, delete it or replace with the following to disable debugging:', 'security-ninja' ); ?></p>
		<pre>define('WP_DEBUG', false);</pre>
		<p><?php esc_html_e( 'If your blog still fails on this test after you made the changes it means some plugin is enabling debug mode. Disable plugins one by one to find out which one is doing it.', 'security-ninja' ); ?></p>
	</div>
	</div>


<div class="sn_test_details" id="debug_log_file_check">
	<div class="test_name"><?php esc_html_e( 'Check if the debug.log file exists.', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'The log file, debug.log should not be accessible via a browser.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'This file is used when debugging and may contain sensitive information about your server. It is also a clear sign you are running WordPress.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'You should either delete the file, usually located in /wp-content/debug.log or block access to it:', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Via .htaccess:', 'security-ninja' ); ?></p>
<pre>#BEGIN - Block access to debug.log
	&lt;Files debug.log&gt;
	Require all denied
	&lt;/Files&gt;
	#END - Block access to debug.log
</pre>

		<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block.', 'security-ninja' ); ?></p>

<pre>
location ~* /debug\.log$ {
	deny all;
}
</pre>
</div>
</div>



<div class="sn_test_details" id="rest_api_enabled">
	<div class="test_name"><?php esc_html_e( 'Check if the REST API is enabled.', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'The REST API is an advanced system that allows WordPress, its plugins and external services to communicate.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Having the REST API enabled is not a security issue by itself, it is well tested and protected by the developers in the WordPress community.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you want to be certain and protect yourself from attacks via the REST API you can disable it completely or only allow authenticated users to have access.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Warning: Some plugins and external services might not work properly if you block the REST API.', 'security-ninja' ); ?></p>
	</div>
</div>



<div class="sn_test_details" id="db_debug_check">
	<div class="test_name"><?php esc_html_e( 'Check if database debug mode is enabled', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Having any kind of debug mode (WP database debug mode in this case) or error reporting mode enabled on a production server is extremely bad. Not only will it slow down your site, confuse your visitors with weird messages it will also give the potential attacker valuable information about your system.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'WordPress DB debugging mode is enabled with the following command:', 'security-ninja' ); ?></p>
		<pre>$wpdb->show_errors();</pre>
		<p><?php esc_html_e( 'In most cases this debugging mode is enabled by plugins so the only way to solve the problem is to disable plugins one by one and find out which one enabled debugging.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="script_debug_check">
	<div class="test_name"><?php esc_html_e( 'Check if JavaScript debug mode is enabled', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Having any kind of debug mode (WP JavaScript debug mode in this case) or error reporting mode enabled on a production server is extremely bad. Not only will it slow down your site, confuse your visitors with weird messages it will also give the potential attacker valuable information about your system.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'WordPress JavaScript debugging mode is enabled/disabled by a constant defined in wp-config.php open your config file and look for a line similar to:', 'security-ninja' ); ?></p>
		<pre>define('SCRIPT_DEBUG', true);</pre>
		<p><?php esc_html_e( 'Comment it out, delete it or replace with the following to disable debugging:', 'security-ninja' ); ?></p>
		<pre>define('SCRIPT_DEBUG', false);</pre>
		<p><?php esc_html_e( 'If your blog still fails on this test after you made the change it means some plugin is enabling debug mode. Disable plugins one by one to find out which one is doing it.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="display_errors_check">
	<div class="test_name"><?php esc_html_e( 'Check if display_errors PHP directive is turned off', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Displaying any kind of debug info or similar information is extremely bad. If any PHP errors happen on your site they should be logged in a safe place and not displayed to visitors or potential attackers.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Open wp-config.php and place the following code just above the require_once function at the end of the file:', 'security-ninja' ); ?></p>
		<pre>ini_set('display_errors', 0);</pre>
		<p><?php esc_html_e( 'If that doesn\'t work add the following line to your .htaccess file:', 'security-ninja' ); ?></p>
<pre>
#BEGIN - Hide PHP displaying errors
php_flag display_errors Off
#END - Hide PHP displaying errors
</pre>
		<p><?php esc_html_e( 'If that fails as well, contact your hosting provider or try disabling plugins, one by one to find out which one enabled error displaying.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="blog_site_url_check">
	<div class="test_name"><?php esc_html_e( 'Check if WordPress installation address is the same as the site address', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Moving WP core files to any non-standard folder will make your site less vulnerable to automated attacks. Most scripts that script kiddies use rely on default file paths. If your blog is setup on www.site.com you can put WP files in ie: /var/www/vhosts/site.com/www/my-app/ instead of the obvious /var/www/vhosts/site.com/www/.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Site and WP address can easily be changed in', 'security-ninja' ); ?> <a target="_blank" href="options-general.php"><?php esc_html_e( 'Options - General', 'security-ninja' ); ?></a>.</p>

		<p>
		<?php
		printf(
			/* translators: %s: URL to WordPress.org article */
			esc_html__( 'Check out this simple instruction from wordpress.org how to move your core WordPress files to another folder: %s', 'security-ninja' ),
			'<a target="_blank" href="https://wordpress.org/support/article/giving-wordpress-its-own-directory/#method-i-without-url-change" rel="noopener">' . esc_html__( 'Giving WordPress Its Own Directory', 'security-ninja' ) . '</a>'
		);
		?>
		</p>
	</div>
</div>

<div class="sn_test_details" id="config_chmod">
	<div class="test_name"><?php esc_html_e( 'Check if wp-config.php file has the right permissions (chmod) set', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'wp-config.php file contains sensitive information (database username and password) in plain text and should not be accessible to anyone except you and WP (or the web server to be more precise).', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'What\'s the best chmod for your wp-config.php depends on the way your server is configured but there are some general guidelines you can follow.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'The official recommendation is trying to set to 444 which means all users have read-only rights to the file. This is a problem for some plugins that need to write to the file so you can try setting chmod to 644 or 640.', 'security-ninja' ); ?></p> 
		<ul>
			<li><?php esc_html_e( 'Try setting chmod to 0400 or 0440 and if the site works normally that\'s the best one to use', 'security-ninja' ); ?></li>
			<li><?php esc_html_e( 'The "other" users should have no privileges on the file so set the last octal digit to zero', 'security-ninja' ); ?></li>
			<li><?php esc_html_e( 'The "group" users shouldn\'t have any access right as well unless Apache falls under that category, so set group rights to 0 or 4', 'security-ninja' ); ?></li>
		</ul>
		<p><?php printf( esc_html__( 'This can vary depending on your server configuration - please check more details on %s', 'security-ninja' ), '<a href="https://developer.wordpress.org/advanced-administration/server/file-permissions/" target="_blank" rel="noopener">developer.wordpress.org/advanced-administration/server/file-permissions/</a>' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="bruteforce_login">
	<div class="test_name"><?php esc_html_e( "Check users' password strength with a brute-force attack", 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'By using a dictionary of 600 most commonly used passwords we do a brute-force attach on your site\'s user accounts. Any accounts that fail this test pose a serious security issue for the site because they are using passwords like "12345", "qwerty" or "god" which anyone can guess within minutes. Alert those users or change their passwords immediately.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Please note that the plugin tests only the first 5 users (starting from administrators). This limit is imposed to be sure we don\'t temporarily kill the database while doing the brute-force attack.', 'security-ninja' ); ?><br>
		<?php esc_html_e( 'If you want to test more or all users open sn-test.php and change the line #763 which defines this limit.', 'security-ninja' ); ?></p>
		<pre>$max_users_attack = 5;</pre>
	</div>
</div>

<div class="sn_test_details" id="anyone_can_register">
	<div class="test_name"><?php esc_html_e( 'Check if "anyone can register" option is enabled', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Unless you\'re running some kind of community based site this option needs to be disabled. Although it only provides the attacker limited access to your backend it\'s enough to start exploiting other security issues.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Go to', 'security-ninja' ); ?> <a target="_blank" href="options-general.php"><?php esc_html_e( 'Options - General', 'security-ninja' ); ?></a> <?php esc_html_e( 'and uncheck the "Membership - anyone can register" checkbox.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="register_globals_check">
	<div class="test_name"><?php esc_html_e( 'Check if register_globals PHP directive is turned off', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'This is one of the biggest security issues you can have on your site! If your hosting company has this directive enabled by default switch to another company immediately!', 'security-ninja' ); ?> <a target="_blank" href="<?php echo esc_url( __( 'https://php.net/manual/en/security.globals.php', 'security-ninja' ) ); ?>" rel="noopener"><?php esc_html_e( 'PHP manual', 'security-ninja' ); ?></a> <?php esc_html_e( 'has more info why this is so dangerous.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>register_globals = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>register_globals = off</pre>
		<p><?php esc_html_e( 'Alternatively open .htaccess and put this directive into it:', 'security-ninja' ); ?></p>
		<pre>php_flag register_globals off</pre>
		<p><?php esc_html_e( 'If you\'re still unable to disable register_globals contact a security professional.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="safe_mode_check">
	<div class="test_name"><?php esc_html_e( 'Check if safe mode is disabled', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'PHP safe mode is an attempt to solve the shared-server security problem. It is architecturally incorrect to try to solve this problem at the PHP level, but since the alternatives at the web server and OS levels aren\'t very realistic, many people, especially ISP\'s, use safe mode for now. If your hosting company still uses safe mode it might be a good idea to switch. This feature is deprecated in new version of PHP (5.3) which is also old by now.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>safe_mode = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>safe_mode = off</pre>
	</div>
</div>

<div class="sn_test_details" id="expose_php_check">
	<div class="test_name"><?php esc_html_e( 'Check if the expose_php PHP directive is turned off', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( "It's not wise to disclose the exact PHP version you're using because it makes the job of attacking your site much easier.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>expose_php = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>expose_php = off</pre>
	</div>
</div>

<div class="sn_test_details" id="allow_url_include_check">
	<div class="test_name"><?php esc_html_e( 'Check if allow_url_include PHP directive is turned off', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Setting allow_url_include to off in PHP is an important security measure. This configuration option determines whether PHP code can include files from remote locations, which would otherwise accept URLs as file paths if allow_url_include is enabled.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Having this PHP directive enabled will leave your site exposed to cross-site attacks (XSS). There\'s absolutely no valid reason to enable this directive, and using any PHP code that requires it is very risky.', 'security-ninja' ); ?></p>
	</div>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>allow_url_include = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>allow_url_include = off</pre>
		<p><?php esc_html_e( "If you're still unable to disable allow_url_include contact a security professional.", 'security-ninja' ); ?></p>
	</div>

<div class="sn_test_details" id="file_editor">
	<div class="test_name"><?php esc_html_e( 'Check if plugins/themes file editor is enabled', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Plugins and themes file editor is a very convenient tool because it enables you to make quick changes without the need to use FTP. Unfortunately, it\'s also a security issue because it not only shows PHP source but it also enables the attacker to inject malicious code in your site if they manage to gain access to the admin.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'The editor can easily be disabled by placing the following code in theme\'s functions.php file.', 'security-ninja' ); ?></p>
		<pre>define('DISALLOW_FILE_EDIT', true);</pre>
	</div>
</div>

<?php
$tmp = wp_upload_dir();
?>
<div class="sn_test_details" id="uploads_browsable">
	<div class="test_name"><?php esc_html_e( 'Check if the uploads folder is browsable', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Allowing anyone to view all files in the', 'security-ninja' ); ?> <a href="<?php echo esc_url( $tmp['baseurl'] ); ?>" target="_blank"><?php esc_html_e( 'uploads folder', 'security-ninja' ); ?></a>. <?php esc_html_e( 'Just by pointing the browser to it will allow them to easily download all your uploaded files. It\'s a security and a copyright issue.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'To fix the problem open .htaccess and add this directive into it:', 'security-ninja' ); ?></p>
	</div>
	<pre>Options -Indexes</pre>
</div>


<div class="sn_test_details" id="id1_user_check">
	<div class="test_name"><?php esc_html_e( 'Check if user with ID "1" exists', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Although technically not a security issue having a user (which is in 99% cases the admin) with the ID 1 can help an attacker in some circumstances.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Fixing is easy; create a new user with the same privileges. Then delete the old one with ID 1 and tell WP to transfer all of his content to the new user.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="wlw_meta">
	<div class="test_name"><?php esc_html_e( "Check if Windows Live Writer link is present in pages' header data", 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( "If you're not using Windows Live Writer there's really no valid reason to have it's link in the page header thus telling the whole world you're using WordPress.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following line:", 'security-ninja' ); ?></p>
		<pre>remove_action('wp_head', 'wlwmanifest_link');</pre>
	</div>
</div>

<div class="sn_test_details" id="config_location">
	<div class="test_name"><?php esc_html_e( 'Check if wp-config.php is present on the default location', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'If someone gains FTP access to your server this will not save you but it certainly cannot hurt to obfuscate your installation a bit.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'In order to fix this issue you have to move wp-config.php one level up in the folder structure. If the original location was:', 'security-ninja' ); ?></p>
		<pre>/home/www/wp-config.php</pre>
		<p><?php esc_html_e( 'Move the file to', 'security-ninja' ); ?>:</p>
		<pre>/home/wp-config.php</pre>
		<p><?php esc_html_e( 'Or for instance from', 'security-ninja' ); ?>:</p>
		<pre>/home/www/my-blog/wp-config.php</pre>
		<p><?php esc_html_e( 'To', 'security-ninja' ); ?>:</p>
		<pre>/home/www/wp-config.php</pre>
	</div>
</div>

<div class="sn_test_details" id="mysql_external">
	<div class="test_name"><?php esc_html_e( 'Check if MySQL server is connectable from outside of the local network with the WP account', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( "Since MySQL username and password are written in plain-text in wp-config.php it's advisable not to allow any client to use that account unless he's connecting to MySQL from your server (localhost). Allowing him to connect from any host will make some attacks much easier.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Fixing this issue involves changing the MySQL user or server config and it is not something that can be described in a few words so we advise asking someone to fix it for you. If you are really eager to do it we suggest creating a new MySQL user and under "hostname" enter "localhost". Set other properties such as username and password to your own liking and, of course, update wp-config.php with the new user details.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="rpc_meta">
	<div class="test_name"><?php esc_html_e( "Check if EditURI (XML-RPC) link is present in pages' header data", 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'If you are not using any Really Simple Discovery services such as pingbacks there is no need to advertise that endpoint (link) in the header.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Please note that for most sites this is not a security issue because they "want to be discovered" but if you want to hide the fact that you are using WordPress this is the way to go.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Open your theme's functions.php file and add the following line:", 'security-ninja' ); ?></p>
		<pre>remove_action('wp_head', 'rsd_link');</pre>
		<p><?php esc_html_e( 'Additionally, to completely disable XML-RPC functions add this also to the functions.php file:', 'security-ninja' ); ?></p>
		<pre>add_filter('xmlrpc_enabled', '__return_false');</pre>
		<p><?php esc_html_e( 'And also add this code to .htaccess to prevent DDoS attacks:', 'security-ninja' ); ?></p>
<pre>
#BEGIN - Block access to xmlrpc.php
&lt;Files xmlrpc.php&gt;
Order Deny,Allow
Deny from all
&lt;/Files&gt;
#END - Block access to xmlrpc.php
</pre>
	</div>
</div>

<div class="sn_test_details" id="tim_thumb">
	<div class="test_name"><?php esc_html_e( 'Check if Timthumb script is used in the active theme', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'We do not recommend using the Timthumb script to manipulate images. Apart from the security issues some versions had, WordPress has its own built-in functions for manipulating images that should be used instead.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Contact the theme developer and have him update the theme. It is unlikely you will be able to fix this issue yourself.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="shellshock_6271">
	<div class="test_name"><?php esc_html_e( 'Check if the server is vulnerable to the Shellshock bug #6271', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Shellshock, also known as Bashdoor, is a family of security bugs in the widely used Unix Bash shell. Web servers use Bash to process certain commands, allowing an attacker to cause vulnerable versions of Bash to execute arbitrary commands. This can allow an attacker to gain unauthorized access to the system. Although this bug is not related to WordPress directly it is very problematic.', 'security-ninja' ); ?></p>
		<p><a target="_blank" href="http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271" rel="noopener"><?php esc_html_e( 'More details.', 'security-ninja' ); ?></a></p>
		<p><?php esc_html_e( "Contact your server administrator and update the server's Bash shell immediately.", 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="shellshock_7169">
	<div class="test_name"><?php esc_html_e( 'Check if the server is vulnerable to the Shellshock bug #7169', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Shellshock, also known as Bashdoor, is a family of security bugs in the widely used Unix Bash shell. Web servers use Bash to process certain commands, allowing an attacker to cause vulnerable versions of Bash to execute arbitrary commands. This can allow an attacker to gain unauthorized access to the system. Although this bug is not related to WordPress directly it is very problematic.', 'security-ninja' ); ?></p>
		<p><a target="_blank" href="https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-7169" rel="noopener"><?php esc_html_e( 'More details.', 'security-ninja' ); ?></a></p>
		<p><?php esc_html_e( "Contact your server administrator and update the server's Bash shell immediately.", 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="admin_ssl">
	<div class="test_name"><?php esc_html_e( 'Check if admin interface is delivered via SSL', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'You should run your entire site via HTTPS, it makes it more secure and Google will love it too.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "If for some reason you do not want to run the entire website with SSL, at least make the admin secure. Some hosting companies charge a lot for SSL certificates but you can get free ones on Let's Encrypt.", 'security-ninja' ); ?>
		<p><a target="_blank" href="https://letsencrypt.org/" rel="noopener">Let's Encrypt</a>.</p>
		<p><?php esc_html_e( 'If you do not have an SSL certificate you can still try and run the admin via HTTPS. Depending on how your server is configured, it might work. But getting a valid certificate is definitely a good thing to do.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'To enable SSL in admin open wp-config.php and add the following line to it:', 'security-ninja' ); ?></p>
		<pre>define('FORCE_SSL_ADMIN', true);</pre>
	</div>
</div>

<div class="sn_test_details" id="mysql_permissions">
	<div class="test_name"><?php esc_html_e( 'Check if MySQL account used by WordPress has too many permissions', 'security-ninja' ); ?></div>
	<div class="test_description">

		<p><?php esc_html_e( 'If an attacker gains access to your wp-config.php file and gets the MySQL username and password, the attacker will be able to log in to that database and do whatever that account allows him to. ', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "That is why it is important to keep the account's privileges to a bare minimum. For instance, if you're not installing any new plugins or updating WP that account doesn't need the CREATE or DROP table privileges.", 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "For regular, day-to-day usage these are the recommended privileges: SELECT, INSERT, UPDATE, and DELETE. When updating WordPress you will also need the ALTER command. MySQL account privileges can be adjusted in cPanel, but we recommend getting a professional to do it if you've never done this kind of modifications before.", 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="old_plugins">
	<div class="test_name"><?php esc_html_e( 'Check if active plugins have been updated in the last 12 months', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( 'Plugins that have not been updated in over a year and are potentially abandoned by their developers can pose a big security issue. Hackers can exploit known security vulnerabilities that have been open a long time since the plugin is not patched/updated. Be very careful when using such old plugins. A more in-depth look into such plugins is available here:', 'security-ninja' ); ?></p>
		<p><a href="https://wploop.com/old-outdated-wordpress-plugins/" target="_blank" rel="noopener">WP Loop</a></p>
		<p><?php esc_html_e( "There's not much you can do to fix the problem except finding a similar plugin that's properly maintained. If you are truly dependant on that one plugin, we suggest you contact the author and see if he's willing to update it or hire someone to do that for you.", 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="incompatible_plugins">
	<div class="test_name"><?php esc_html_e( 'Check if active plugins are compatible with your version of WordPress', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Plugins that are incompatible with your version of WordPress can cause unpredictable behavior, bring the site down and just in general cause problems. In most cases, incompatibilities are minor and can be ignored, but such plugins are often old and haven not been updated in years. We suggest using plugins that have been tried and tested with the latest version of WordPress that you should be using too.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'There is not much you can do to fix the problem except finding a similar plugin or contacting the author and asking them to update it.', 'security-ninja' ); ?></p>

	</div>
</div>

<div class="sn_test_details" id="php_ver">
	<div class="test_name"><?php esc_html_e( 'Check the PHP version', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Using an outdated version of PHP can expose your site to security vulnerabilities and limit your ability to use modern WordPress features and plugins.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'As of 2024, WordPress recommends using PHP 7.4 or higher, with PHP 8.1 or 8.2 being ideal for optimal performance and security. PHP versions below 7.4 are no longer supported and should not be used.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Contact your hosting provider to upgrade to a supported PHP version. If they cannot accommodate this request, consider moving your site to a hosting provider that offers modern PHP versions.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="mysql_ver">
	<div class="test_name"><?php esc_html_e( 'Check the MySQL/MariaDB version', 'security-ninja' ); ?></div>
	<div class="test_description">
		<p><?php esc_html_e( 'Using an outdated version of MySQL or MariaDB can make your site vulnerable to security issues and performance problems.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'As of 2024, it\'s recommended to use MySQL 8.0 or higher, or MariaDB 10.6 or higher. These versions offer improved security features and performance enhancements.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If your hosting provider doesn\'t offer recent MySQL/MariaDB versions, consider upgrading your hosting plan or switching to a provider that prioritizes keeping their software up-to-date.', 'security-ninja' ); ?></p>
	</div>
</div>

<div class="sn_test_details" id="usernames_enumeration">
	<div class="test_name"><?php esc_html_e( 'Check if usernames can be fetched via user IDs', 'security-ninja' ); ?></div>
	<div class="test_description"><p><?php esc_html_e( "Usernames (unlike passwords) are not secret. By knowing someone's username, you can't login to their account. You need the password too. However, by knowing the username, you are one step closer to logging in, using the username to brute-force the password or to gain access in some similar way. That's why it's advisable to keep the list of usernames a secret. At least to some degree. By default, by accessing siteurl.com/?author={id} and looping through IDs from 1 you can get a list of usernames because WP will redirect you to siteurl.com/author/username/ if the ID exists in the system.", 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'To fix this issue add the following lines to your .htaccess file:', 'security-ninja' ); ?></p>
<pre>
&lt;!-- BEGIN - Block Username enumeration --&gt;
&lt;IfModule mod_rewrite.c&gt;
		RewriteCond %{QUERY_STRING} ^author=([0-9]*)
		RewriteRule .* /? [L,R=302]
&lt;/IfModule&gt;
&lt;!-- END - Block Username enumeration --&gt;
</pre>
<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
<pre>
if ($args ~ "^/?author=([0-9]*)") {
	return 302 $scheme://$server_name;
}
</pre>
	</div>
</div>
