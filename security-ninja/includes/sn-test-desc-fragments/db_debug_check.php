<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Having any kind of debug mode (WP database debug mode in this case) or error reporting mode enabled on a production server is extremely bad. Not only will it slow down your site, confuse your visitors with weird messages it will also give the potential attacker valuable information about your system.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'WordPress DB debugging mode is enabled with the following command:', 'security-ninja' ); ?></p>
		<pre>$wpdb->show_errors();</pre>
		<p><?php esc_html_e( 'In most cases this debugging mode is enabled by plugins so the only way to solve the problem is to disable plugins one by one and find out which one enabled debugging.', 'security-ninja' ); ?></p>
