<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'WordPress comes with a powerful REST API system that allows access to different data in a structured format. We recommend you disable these links showing in the header.', 'security-ninja' ); ?></p>

				<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following:", 'security-ninja' ); ?></p>
<pre>
remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
remove_action('wp_head', 'rest_output_link_wp_head');
remove_action('template_redirect', 'rest_output_link_header', 11, 0);</pre>
