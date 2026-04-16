<?php
/**
 * Security test help fragment.
 *
 * @package SecurityNinja
 */

defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If someone tries to guess your username and password or tries a brute-force attack they will most probably start with username "admin". This is the default username used by too many sites and should be removed.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( 'Create a new user and assign him the "administrator" role. Try not to use usernames like: "root", "god", "null" or similar ones. Once you have the new user created delete the "admin" one and assign all post/pages he may have created to the new user.', 'security-ninja' ); ?></p>
