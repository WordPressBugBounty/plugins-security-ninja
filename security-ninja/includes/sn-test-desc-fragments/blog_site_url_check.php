<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'Moving WP core files to any non-standard folder will make your site less vulnerable to automated attacks. Most scripts that script kiddies use rely on default file paths. If your blog is setup on www.site.com you can put WP files in ie: /var/www/vhosts/site.com/www/my-app/ instead of the obvious /var/www/vhosts/site.com/www/.', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'Site and WP address can easily be changed in', 'security-ninja' ); ?> <a target="_blank" href="options-general.php"><?php esc_html_e( 'Options - General', 'security-ninja' ); ?></a>.</p>

		<p>
		<?php
		printf(
			/* translators: %s: URL to WordPress.org article */
			esc_html__( 'Check out this simple instruction from wordpress.org how to move your core WordPress files to another folder: %s', 'security-ninja' ),
			'<a target="_blank" href="https://wordpress.org/support/article/giving-wordpress-its-own-directory/#method-i-without-url-change" rel="noopener">' . esc_html__( 'Giving WordPress Its Own Directory', 'security-ninja' ) . '</a>'
		);
		?>
		</p>
