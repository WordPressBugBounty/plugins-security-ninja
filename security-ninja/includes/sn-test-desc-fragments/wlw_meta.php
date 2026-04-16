<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "If you're not using Windows Live Writer there's really no valid reason to have it's link in the page header thus telling the whole world you're using WordPress.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Fixing is very easy. Open your theme's functions.php file and add the following line:", 'security-ninja' ); ?></p>
		<pre>remove_action('wp_head', 'wlwmanifest_link');</pre>
