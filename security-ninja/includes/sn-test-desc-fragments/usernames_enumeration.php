<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "Usernames (unlike passwords) are not secret. By knowing someone's username, you can't login to their account. You need the password too. However, by knowing the username, you are one step closer to logging in, using the username to brute-force the password or to gain access in some similar way. That's why it's advisable to keep the list of usernames a secret. At least to some degree.", 'security-ninja' ); ?></p>

<p><?php esc_html_e( 'By default, WordPress exposes usernames in two common ways: (1) accessing siteurl.com/?author={id} and looping through IDs redirects to siteurl.com/author/username/ when the ID exists, and (2) anonymous GET requests to /wp-json/wp/v2/users (or ?rest_route=/wp/v2/users) return a public list of users.', 'security-ninja' ); ?></p>

<p><?php esc_html_e( 'Security Ninja can block both vectors. Go to Fixes and enable "Disable Username Enumeration". That stops ?author=N scans, removes anonymous access to the REST users endpoint, and filters oEmbed author data.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'You can also harden ?author= at the server. Add the following lines to your .htaccess file:', 'security-ninja' ); ?></p>
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
