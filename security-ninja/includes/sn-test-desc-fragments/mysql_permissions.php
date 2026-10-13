<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If an attacker gains access to your wp-config.php file and gets the MySQL username and password, the attacker will be able to log in to that database and do whatever that account allows him to.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'Keep the account on this site\'s database only. A global grant (ON *.*) or GRANT OPTION lets that password reach every database on the server, or create new accounts.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'WordPress updates run dbDelta(), which needs CREATE, ALTER, and INDEX. Uninstalls need DROP. Backup tools that use mysqldump need LOCK TABLES and SHOW VIEW. These privileges are enough for WordPress, WooCommerce, updates, uninstalls, and backups:', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'Keep: SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, CREATE TEMPORARY TABLES, LOCK TABLES, REFERENCES, CREATE VIEW, SHOW VIEW.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'Remove: CREATE ROUTINE, ALTER ROUTINE, EXECUTE, EVENT, TRIGGER.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'MySQL reports a full set of individually granted privileges as ALL PRIVILEGES. Ticking every box in cPanel still leaves the account too open. Privileges can be adjusted in cPanel. Get a professional to do it if you have never changed database grants before.', 'security-ninja' ); ?></p>
