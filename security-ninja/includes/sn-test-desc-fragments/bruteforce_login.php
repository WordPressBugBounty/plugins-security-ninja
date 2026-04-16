<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'By using a dictionary of 600 most commonly used passwords we do a brute-force attach on your site\'s user accounts. Any accounts that fail this test pose a serious security issue for the site because they are using passwords like "12345", "qwerty" or "god" which anyone can guess within minutes. Alert those users or change their passwords immediately.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Please note that the plugin tests only the first 5 users (starting from administrators). This limit is imposed to be sure we don\'t temporarily kill the database while doing the brute-force attack.', 'security-ninja' ); ?><br>
		<?php esc_html_e( 'If you want to test more or all users open sn-test.php and change the line #763 which defines this limit.', 'security-ninja' ); ?></p>
		<pre>$max_users_attack = 5;</pre>
