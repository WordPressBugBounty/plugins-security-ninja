<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "Usernames (unlike passwords) are not secret. By knowing someone's username, you can't login to their account. You need the password too. However, by knowing the username, you are one step closer to logging in, using the username to brute-force the password or to gain access in some similar way. That's why it's advisable to keep the list of usernames a secret. At least to some degree. By default, by accessing siteurl.com/?author={id} and looping through IDs from 1 you can get a list of usernames because WP will redirect you to siteurl.com/author/username/ if the ID exists in the system.", 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'To fix this issue add the following lines to your .htaccess file:', 'security-ninja' ); ?></p>
<pre>
&lt;!-- BEGIN - Block Username enumeration --&gt;
&lt;IfModule mod_rewrite.c&gt;
		RewriteCond %{QUERY_STRING} ^author=([0-9]*)
		RewriteRule .* /? [L,R=302]
&lt;/IfModule&gt;
&lt;!-- END - Block Username enumeration --&gt;
</pre>
<p><?php esc_html_e( 'For Nginx add this to the nginx.conf under server block', 'security-ninja' ); ?></p>
<pre>
if ($args ~ "^/?author=([0-9]*)") {
	return 302 $scheme://$server_name;
}
</pre>
