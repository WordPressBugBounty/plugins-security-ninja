<?php
/**
 * Security test help fragment.
 *
 * @package SecurityNinja
 */

defined( 'ABSPATH' ) || exit;
$wf_sn_upload_dir = wp_upload_dir();
$wf_sn_baseurl    = isset( $wf_sn_upload_dir['baseurl'] ) ? $wf_sn_upload_dir['baseurl'] : '';
?>
<p><?php esc_html_e( 'Allowing anyone to view all files in the', 'security-ninja' ); ?> <a href="<?php echo esc_url( $wf_sn_baseurl ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'uploads folder', 'security-ninja' ); ?></a>. <?php esc_html_e( 'Just by pointing the browser to it will allow them to easily download all your uploaded files. It\'s a security and a copyright issue.', 'security-ninja' ); ?></p>
<p><?php esc_html_e( 'To fix the problem open .htaccess and add this directive into it:', 'security-ninja' ); ?></p>
<pre>Options -Indexes</pre>
