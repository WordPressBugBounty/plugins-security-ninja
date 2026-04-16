<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'As with the WordPress version it is not wise to disclose the exact PHP version you are using because it makes the job of attacking your site much easier.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( 'This issue is not directly WP related but it definitely affects your site.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( 'You will most probably have to ask your hosting company to configure the HTTP server not to show PHP version info but you can also try adding these directives to the .htacces file:', 'security-ninja' ); ?></p>
<pre>#BEGIN - Hide PHP version in header
	&lt;IfModule mod_headers.c&gt;
	Header unset X-Powered-By
	Header unset Server
	&lt;/IfModule&gt;
#END - Hide PHP version in header</pre>
