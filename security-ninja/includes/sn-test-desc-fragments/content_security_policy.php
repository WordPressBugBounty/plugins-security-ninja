<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'This tells the browser which sources it may load, and which sites may embed your pages.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'The example below is safe on a normal WordPress site. It blocks clickjacking, locks the base URL, and stops old plugin embeds such as Flash. It does not block scripts or styles, so the dashboard, page builders, and checkout keep working.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( "Add this to your theme's functions.php file:", 'security-ninja' ); ?></p>
<pre>add_filter( 'wp_headers', function ( $headers ) {
	if ( is_admin() ) {
		return $headers;
	}

	$policy = "frame-ancestors 'self'; base-uri 'self'; object-src 'none'";
	if ( is_ssl() ) {
		$policy = 'upgrade-insecure-requests; ' . $policy;
	}
	$headers['Content-Security-Policy'] = $policy;

	return $headers;
} );</pre>

		<p><?php esc_html_e( 'You can also add this to your .htaccess file. Include upgrade-insecure-requests only when the site is served over HTTPS.', 'security-ninja' ); ?></p>
		<p><strong><?php esc_html_e( 'LiteSpeed servers:', 'security-ninja' ); ?></strong> <?php esc_html_e( 'The PHP header interface may not work correctly on LiteSpeed. If CSP headers are not appearing in your response, add the policy directly to your .htaccess file using the example below.', 'security-ninja' ); ?></p>
<pre>#BEGIN - Set Content-Security-Policy
	&lt;IfModule mod_headers.c&gt;
	Header set Content-Security-Policy "upgrade-insecure-requests; frame-ancestors 'self'; base-uri 'self'; object-src 'none'"
	&lt;/IfModule&gt;
#END - Set Content-Security-Policy</pre>

		<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
		<pre>add_header Content-Security-Policy "upgrade-insecure-requests; frame-ancestors 'self'; base-uri 'self'; object-src 'none'";</pre>

		<p><?php esc_html_e( 'Script limits are an advanced step. Start with Content-Security-Policy-Report-Only. WordPress needs nonces or \'unsafe-inline\' for scripts. Report-Only will not pass this test.', 'security-ninja' ); ?></p>
		<p>
			<a href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'security_tests_docs', 'docs/security-fixes/content-security-policy/' ) ); ?>" target="_blank" rel="noopener">
				<?php esc_html_e( 'Read our guide to configuring Content Security Policy', 'security-ninja' ); ?>
			</a>
		</p>
