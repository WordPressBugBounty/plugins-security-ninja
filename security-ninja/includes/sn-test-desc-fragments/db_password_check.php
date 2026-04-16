<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'There is no such thing as an "unimportant password"! The same goes for WordPress database password. Although most servers are configured so that the database cannot be accessed from other hosts (or from outside of the local network) that does not mean your database passsword should be "12345".', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Choose a proper password, at least 12 characters long with a combination of letters, numbers and special characters.', 'security-ninja' ); ?></p>
		<h3><?php esc_html_e( 'To change the database password', 'security-ninja' ); ?></h3>
		<p><?php esc_html_e( '1. Open cPanel, Plesk or any other hosting control panel you have. Find the option to change the database password and make the new password strong enough. If you cannot find that option or you are uncomfortable changing it contact your hosting provider. After the password is changed open wp-config.php and change the password', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( '2. After the password is changed open wp-config.php and change the password', 'security-ninja' ); ?></p>
<pre>/** MySQL database password */
define('DB_PASSWORD', 'YOUR_NEW_DB_PASSWORD_GOES_HERE');
</pre>
<p><strong><?php esc_html_e( 'IMPORTANT: While you are changing the password your website will be offline.', 'security-ninja' ); ?></strong></p>
<p><?php esc_html_e( 'Random password suggestions - Feel free to use or make your own. Remember to change the database password BOTH places.', 'security-ninja' ); ?></p>
<ul>
<?php
for ( $i = 0; $i < 3; $i++ ) {

	echo '<li>' . esc_html( wp_generate_password( 24, true, false ) ) . '</li>';
}

?>
</ul>
