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
<pre>header("Permissions-Policy: accelerometer 'none' ; ambient-light-sensor 'none' ; autoplay 'none' ; camera 'none' ; encrypted-media 'none' ; fullscreen 'none' ; geolocation 'none' ; gyroscope 'none' ; magnetometer 'none' ; microphone 'none' ; midi 'none' ; payment 'none' ; speaker 'none' ; sync-xhr 'none' ; usb 'none' ; notifications 'none' ; vibrate 'none' ; push 'none' ; vr 'none' ");</pre>

				<p><?php esc_html_e( 'NOTE: This example disables everything, so if you have website that uses some of the features please check the link to Mozilla on more details on how to finetune.', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
				<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>

<pre>
	#BEGIN - Set Permissions-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Permissions-Policy "accelerometer 'none' ; ambient-light-sensor 'none' ; autoplay 'none' ; camera 'none' ; encrypted-media 'none' ; fullscreen 'none' ; geolocation 'none' ; gyroscope 'none' ; magnetometer 'none' ; microphone 'none' ; midi 'none' ; payment 'none' ; speaker 'none' ; sync-xhr 'none' ; usb 'none' ; notifications 'none' ; vibrate 'none' ; push 'none' ; vr 'none' "
	&lt;/IfModule&gt;
	#END - Set Permissions-Policy
</pre>
				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
<pre>add_header Permissions-Policy "accelerometer 'none'; autoplay 'none'; camera 'none'; encrypted-media 'none'; fullscreen 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; payment 'none'; sync-xhr 'none'; usb 'none';";</pre>
