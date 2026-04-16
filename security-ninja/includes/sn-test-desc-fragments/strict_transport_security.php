<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Instructs your webserver to only use HTTPS and not allow HTTP insecure connections.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'It is important you verify your website has a SSL certificate and it is working correctly before implementing this.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Setting up is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
		<pre>header('Strict-Transport-Security: max-age=31536000;');</pre>

		<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
		<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>
<pre>#BEGIN - Forces only HTTPS
	&lt;IfModule mod_headers.c&gt;
	Header set Strict-Transport-Security "max-age=31536000;"
	&lt;/IfModule&gt;
#END - Forces only HTTPS</pre>
		<p><?php esc_html_e( 'You can add "includeSubDomains" if you want this to include any subdomains you might have.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
		<pre>add_header Strict-Transport-Security "max-age=31536000;";</pre>

		<p><?php esc_html_e( 'Further reading and test:', 'security-ninja' ); ?> <a href="https://hstspreload.org" target="_blank" rel="noopener noreferrer">https://hstspreload.org</a></p>
