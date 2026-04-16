<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Plugins and themes file editor is a very convenient tool because it enables you to make quick changes without the need to use FTP. Unfortunately, it\'s also a security issue because it not only shows PHP source but it also enables the attacker to inject malicious code in your site if they manage to gain access to the admin.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'The editor can easily be disabled by placing the following code in theme\'s functions.php file.', 'security-ninja' ); ?></p>
		<pre>define('DISALLOW_FILE_EDIT', true);</pre>
