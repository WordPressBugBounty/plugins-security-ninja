<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Having any kind of debug mode (general WP debug mode in this case) or error reporting mode enabled on a production site is extremely bad. Not only will it slow down your site, confuse your visitors with weird messages it will also give the potential attacker valuable information about your system.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'General WordPress debugging mode is enabled/disabled by a constant defined in wp-config.php. Open that file and look for a line similar to:', 'security-ninja' ); ?></p>
		<pre>define('WP_DEBUG', true);</pre>
		<p><?php esc_html_e( 'Comment it out, delete it or replace with the following to disable debugging:', 'security-ninja' ); ?></p>
		<pre>define('WP_DEBUG', false);</pre>
		<p><?php esc_html_e( 'If your blog still fails on this test after you made the changes it means some plugin is enabling debug mode. Disable plugins one by one to find out which one is doing it.', 'security-ninja' ); ?></p>
