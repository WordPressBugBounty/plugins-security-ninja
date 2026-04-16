<?php
/**
 * Security test help fragment.
 *
 * @package SecurityNinja
 */

defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Setting allow_url_include to off in PHP is an important security measure. This configuration option determines whether PHP code can include files from remote locations, which would otherwise accept URLs as file paths if allow_url_include is enabled.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( 'Having this PHP directive enabled will leave your site exposed to cross-site attacks (XSS). There\'s absolutely no valid reason to enable this directive, and using any PHP code that requires it is very risky.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
<pre>allow_url_include = on</pre>
<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
<pre>allow_url_include = off</pre>
<p><?php esc_html_e( "If you're still unable to disable allow_url_include contact a security professional.", 'security-ninja' ); ?></p>
