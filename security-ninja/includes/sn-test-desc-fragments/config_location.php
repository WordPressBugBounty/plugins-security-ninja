<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If someone gains FTP access to your server this will not save you but it certainly cannot hurt to obfuscate your installation a bit.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'In order to fix this issue you have to move wp-config.php one level up in the folder structure. If the original location was:', 'security-ninja' ); ?></p>
		<pre>/home/www/wp-config.php</pre>
		<p><?php esc_html_e( 'Move the file to', 'security-ninja' ); ?>:</p>
		<pre>/home/wp-config.php</pre>
		<p><?php esc_html_e( 'Or for instance from', 'security-ninja' ); ?>:</p>
		<pre>/home/www/my-blog/wp-config.php</pre>
		<p><?php esc_html_e( 'To', 'security-ninja' ); ?>:</p>
		<pre>/home/www/wp-config.php</pre>
