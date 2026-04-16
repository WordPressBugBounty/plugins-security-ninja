<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'The log file, debug.log should not be accessible via a browser.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'This file is used when debugging and may contain sensitive information about your server. It is also a clear sign you are running WordPress.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'You should either delete the file, usually located in /wp-content/debug.log or block access to it:', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Via .htaccess:', 'security-ninja' ); ?></p>
<pre>#BEGIN - Block access to debug.log
	&lt;Files debug.log&gt;
	Require all denied
	&lt;/Files&gt;
	#END - Block access to debug.log
</pre>

		<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block.', 'security-ninja' ); ?></p>

<pre>
location ~* /debug\.log$ {
	deny all;
}
</pre>
