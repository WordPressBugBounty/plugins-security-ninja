<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "Since MySQL username and password are written in plain-text in wp-config.php it's advisable not to allow any client to use that account unless he's connecting to MySQL from your server (localhost). Allowing him to connect from any host will make some attacks much easier.", 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Fixing this issue involves changing the MySQL user or server config and it is not something that can be described in a few words so we advise asking someone to fix it for you. If you are really eager to do it we suggest creating a new MySQL user and under "hostname" enter "localhost". Set other properties such as username and password to your own liking and, of course, update wp-config.php with the new user details.', 'security-ninja' ); ?></p>
