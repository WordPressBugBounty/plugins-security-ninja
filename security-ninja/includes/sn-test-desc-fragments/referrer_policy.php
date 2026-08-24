<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Referrer-Policy is a way to control when the "referrer" header information is allowed.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'This means which websites can see where visitors are referred from.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'The default setting "strict-origin-when-cross-origin" matches modern browsers. Same-origin requests still get the full URL. Cross-origin HTTPS requests get the origin only. HTTPS to HTTP sends nothing. Stricter values like "same-origin" or "no-referrer" can break embeds such as Google Maps or YouTube.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>

				<pre>header('Referrer-Policy: strict-origin-when-cross-origin');</pre>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
				<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>

<pre>
	#BEGIN - Set Referrer-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Referrer-Policy "strict-origin-when-cross-origin"
	&lt;/IfModule&gt;
	#END - Set Referrer-Policy
</pre>

				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header Referrer-Policy strict-origin-when-cross-origin;</pre>
