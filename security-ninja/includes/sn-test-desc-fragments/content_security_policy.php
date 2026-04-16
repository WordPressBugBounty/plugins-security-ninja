<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'This limits any browser visiting your website to only load content from approved sources.', 'security-ninja' ); ?></p>

		<p><strong>Warning: <?php esc_html_e( 'If you embed scripts from external websites, Google Analytics or other sources this could break your website functionality. Read and test before implementing.', 'security-ninja' ); ?></strong></p>
		<p><?php esc_html_e( 'Since each website is different, we can only give a general suggestion and strongly advise to remove the fix again if something on your website stops working.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'This example forces a browser to only load JavaScript .js files from your own website. Warning: Inline code will stop working. Add this to your .htaccess file', 'security-ninja' ); ?></p>
		<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If CSP headers are not appearing in your response, add the policy directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>
<pre>#BEGIN - Only allow browsers to load .js files from this website
	# Use Content-Security-Policy-Report-Only to test settings before using Content-Security-Policy.
	# Once you have fixed any problems, you can change to
	# Header set Content-Security-Policy: ...
	
	&lt;IfModule mod_headers.c&gt;
	Header set Content-Security-Policy-Report-Only: "script-src 'self'"
	&lt;/IfModule&gt;
#END - Only allow browsers to load .js files from this website</pre>

			<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
			<pre>add_header Content-Security-Policy "default-src 'self'";</pre>
			<p>
				<a href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'docs', 'docs/security-fixes/content-security-policy/' ) ); ?>" target="_blank" rel="noopener">
					<?php esc_html_e( 'Read our guide to configuring Content Security Policy', 'security-ninja' ); ?>
				</a>
			</p>
