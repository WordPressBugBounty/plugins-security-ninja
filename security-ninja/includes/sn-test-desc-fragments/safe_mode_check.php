<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'PHP safe mode is an attempt to solve the shared-server security problem. It is architecturally incorrect to try to solve this problem at the PHP level, but since the alternatives at the web server and OS levels aren\'t very realistic, many people, especially ISP\'s, use safe mode for now. If your hosting company still uses safe mode it might be a good idea to switch. This feature is deprecated in new version of PHP (5.3) which is also old by now.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>safe_mode = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>safe_mode = off</pre>
