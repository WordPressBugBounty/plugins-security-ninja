<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "It's not wise to disclose the exact PHP version you're using because it makes the job of attacking your site much easier.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>expose_php = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>expose_php = off</pre>
