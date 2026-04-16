<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Displaying any kind of debug info or similar information is extremely bad. If any PHP errors happen on your site they should be logged in a safe place and not displayed to visitors or potential attackers.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Open wp-config.php and place the following code just above the require_once function at the end of the file:', 'security-ninja' ); ?></p>
		<pre>ini_set('display_errors', 0);</pre>
		<p><?php esc_html_e( 'If that doesn\'t work add the following line to your .htaccess file:', 'security-ninja' ); ?></p>
<pre>
#BEGIN - Hide PHP displaying errors
php_flag display_errors Off
#END - Hide PHP displaying errors
</pre>
		<p><?php esc_html_e( 'If that fails as well, contact your hosting provider or try disabling plugins, one by one to find out which one enabled error displaying.', 'security-ninja' ); ?></p>
