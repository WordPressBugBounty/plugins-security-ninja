<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Knowing the names of your database tables can help an attacker dump the table\'s data and get to sensitive information like password hashes. Since WP table names are predefined the only way you can change table names is by using a unique prefix. One that\'s different from "wp_" or any similar variation such as "wordpress_".', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you\'re doing a fresh installation defining a unique table prefix is easy. Open wp-config.php and go to line #61 where the table prefix is defined. Enter something unique like "frog99_" and install WP.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you already have WP site running and want to change the table prefix things are a bit more complicated and you should only do the change if you\'re comfortable doing some changes to your DB data via phpMyAdmin or a similar GUI.', 'security-ninja' ); ?></p>
		<p><strong><?php esc_html_e( 'Remember', 'security-ninja' ); ?></strong> - <?php esc_html_e( 'Always backup your files and database before making any changes to the database!', 'security-ninja' ); ?></p>
