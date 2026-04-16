<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'By default on failed login attempts WordPress will tell you whether username or password is wrong. An attacker can use that to find out which usernames are active on your system and then use brute-force methods to hack the password.', 'security-ninja' ); ?></p>
			<p><?php esc_html_e( "The solution to this problem is simple. Whether user enters a wrong username or wrong password we always tell him 'wrong username or password' so that he does not know which of the two is wrong. Open your theme's functions.php file and copy/paste the following code:", 'security-ninja' ); ?></p>
			<pre>function wrong_login() {
				return 'Wrong username or password.';
			}
		add_filter('login_errors', 'wrong_login');</pre>
