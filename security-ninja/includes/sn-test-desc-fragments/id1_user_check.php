<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Although technically not a security issue having a user (which is in 99% cases the admin) with the ID 1 can help an attacker in some circumstances.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Fixing is easy; create a new user with the same privileges. Then delete the old one with ID 1 and tell WP to transfer all of his content to the new user.', 'security-ninja' ); ?></p>
