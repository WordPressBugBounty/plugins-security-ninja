<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If an attacker gains access to your wp-config.php file and gets the MySQL username and password, the attacker will be able to log in to that database and do whatever that account allows him to. ', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "That is why it is important to keep the account's privileges to a bare minimum. For instance, if you're not installing any new plugins or updating WP that account doesn't need the CREATE or DROP table privileges.", 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "For regular, day-to-day usage these are the recommended privileges: SELECT, INSERT, UPDATE, and DELETE. When updating WordPress you will also need the ALTER command. MySQL account privileges can be adjusted in cPanel, but we recommend getting a professional to do it if you've never done this kind of modifications before.", 'security-ninja' ); ?></p>
