<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If you are not using any Really Simple Discovery services such as pingbacks there is no need to advertise that endpoint (link) in the header.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Please note that for most sites this is not a security issue because they "want to be discovered" but if you want to hide the fact that you are using WordPress this is the way to go.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( "Open your theme's functions.php file and add the following line:", 'security-ninja' ); ?></p>
		<pre>remove_action('wp_head', 'rsd_link');</pre>
		<p><?php esc_html_e( 'Additionally, to completely disable XML-RPC functions add this also to the functions.php file:', 'security-ninja' ); ?></p>
		<pre>add_filter('xmlrpc_enabled', '__return_false');</pre>
		<p><?php esc_html_e( 'And also add this code to .htaccess to prevent DDoS attacks:', 'security-ninja' ); ?></p>
<pre>
#BEGIN - Block access to xmlrpc.php
&lt;Files xmlrpc.php&gt;
Order Deny,Allow
Deny from all
&lt;/Files&gt;
#END - Block access to xmlrpc.php
</pre>
