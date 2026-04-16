<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'This is one of the biggest security issues you can have on your site! If your hosting company has this directive enabled by default switch to another company immediately!', 'security-ninja' ); ?> <a target="_blank" href="<?php echo esc_url( 'https://php.net/manual/en/security.globals.php' ); ?>" rel="noopener"><?php esc_html_e( 'PHP manual', 'security-ninja' ); ?></a> <?php esc_html_e( 'has more info why this is so dangerous.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'If you have access to php.ini file locate', 'security-ninja' ); ?></p>
		<pre>register_globals = on</pre>
		<p><?php esc_html_e( 'and change it to:', 'security-ninja' ); ?></p>
		<pre>register_globals = off</pre>
		<p><?php esc_html_e( 'Alternatively open .htaccess and put this directive into it:', 'security-ninja' ); ?></p>
		<pre>php_flag register_globals off</pre>
		<p><?php esc_html_e( 'If you\'re still unable to disable register_globals contact a security professional.', 'security-ninja' ); ?></p>
