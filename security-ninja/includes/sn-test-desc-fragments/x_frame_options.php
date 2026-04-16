<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'The X-Frame-Options response header indicates if a page is allowed to render a page in an iframe, frame or object. Avoid clickjacking attacks simply by not allowing your content to be embedded on other websites.', 'security-ninja' ); ?></p>

			<p><strong><?php esc_html_e( 'Warning: The fix is easy, but some sites have problems with the theme customizer preview when this code is enabled.', 'security-ninja' ); ?></strong></p>

			<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
			<pre>header('X-Frame-Options: SAMEORIGIN');</pre>

			<p><?php esc_html_e( 'You can also add this to your .htaccess file', 'security-ninja' ); ?></p>
			<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If this header is not appearing in your response, add it directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>
<pre>#BEGIN - Prevent page-framing and click-jacking
	&lt;IfModule mod_headers.c&gt;
	Header always append X-Frame-Options SAMEORIGIN
	&lt;/IfModule&gt;
#END - Prevent page-framing and click-jacking</pre>
			<p>

				<p><?php esc_html_e( 'You can use the following values: DENY, SAMEORIGIN or ALLOW-FROM', 'security-ninja' ); ?></p>
				<p><?php esc_html_e( 'WARNING: If you use iframes on your website you need to be careful configuring this.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
				<pre>add_header X-Frame-Options "SAMEORIGIN";</pre>

				<p>
				<?php
				printf(
					/* translators: %s: link to GeekFlare article about X-Frame-Options */
					esc_html__( 'Read more about %s.', 'security-ninja' ),
					'<a href="https://geekflare.com/http-header-implementation/#X-Frame-Options" target="_blank" rel="noopener">' . esc_html__( 'the different options on GeekFlare', 'security-ninja' ) . '</a>'
				);
				?>
				</p>
