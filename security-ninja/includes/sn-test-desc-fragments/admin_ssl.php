<?php
/**
 * Security test help fragment.
 *
 * @package SecurityNinja
 */

defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'You should run your entire site via HTTPS, it makes it more secure and Google will love it too.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( "If for some reason you do not want to run the entire website with SSL, at least make the admin secure. Some hosting companies charge a lot for SSL certificates but you can get free ones on Let's Encrypt.", 'security-ninja' ); ?></p>
<p><a target="_blank" href="https://letsencrypt.org/" rel="noopener noreferrer"><?php esc_html_e( "Let's Encrypt", 'security-ninja' ); ?></a>.</p>
<p><?php esc_html_e( 'If you do not have an SSL certificate you can still try and run the admin via HTTPS. Depending on how your server is configured, it might work. But getting a valid certificate is definitely a good thing to do.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( 'To enable SSL in admin open wp-config.php and add the following line to it:', 'security-ninja' ); ?></p>
<pre>define('FORCE_SSL_ADMIN', true);</pre>
