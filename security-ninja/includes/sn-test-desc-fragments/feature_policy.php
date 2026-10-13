<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'This is a way to instruct a browser which features it can use on a website.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'With this you can explicitly prevent access to the camera, microphone, geolocation and many other features.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'For a full and updated list check out the link.', 'security-ninja' ); ?> <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy" target="_blank" rel="noopener">Mozilla.org - Permissions Policy</a></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
<pre>add_filter( 'wp_headers', function ( $headers ) {
	if ( is_admin() ) {
		return $headers;
	}

	$headers['Permissions-Policy'] = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), usb=()';

	return $headers;
} );</pre>

				<p><?php esc_html_e( 'This example turns off device sensors and APIs a typical site does not need. Fullscreen, autoplay, encrypted media, and payment stay allowed so embedded video and card wallets keep working.', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
				<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>

<pre>
	#BEGIN - Set Permissions-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), usb=()"
	&lt;/IfModule&gt;
	#END - Set Permissions-Policy
</pre>
				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
<pre>add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), usb=()";</pre>
