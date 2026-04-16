<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'A new feature introduced in WordPress 5.6', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Allows you to give external systems access to control your website via generated passwords.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'No known exploits are known, but if you do not need this feature there is no need to leave it on.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'You can disable this feature by adding this single line of code to your functions.php:', 'security-ninja' ); ?></p>
		<p><code>add_filter(&#39;wp_is_application_passwords_available&#39;, &#39;__return_false&#39;);</code>
		</p>
