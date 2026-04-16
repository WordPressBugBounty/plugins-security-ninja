<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Setting this will force a browser to only load external resources if the content-type matches what is expected. This prevents malicious hidden code in unexpected files', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
				<pre>header('X-Content-Type-Options: nosniff');</pre>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
				<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>
<pre>#BEGIN - Prevent code in unexpected files
	&lt;IfModule mod_headers.c&gt;
	Header set X-Content-Type-Options nosniff
	&lt;/IfModule&gt;
#END - Prevent code in unexpected files</pre>
				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header X-Content-Type-Options nosniff;</pre>
