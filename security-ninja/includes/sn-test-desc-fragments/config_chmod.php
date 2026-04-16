<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'wp-config.php file contains sensitive information (database username and password) in plain text and should not be accessible to anyone except you and WP (or the web server to be more precise).', 'security-ninja' ); ?></p>
		<p><?php esc_html_e( 'What\'s the best chmod for your wp-config.php depends on the way your server is configured but there are some general guidelines you can follow.', 'security-ninja' ); ?></p>

		<p><?php esc_html_e( 'The official recommendation is trying to set to 444 which means all users have read-only rights to the file. This is a problem for some plugins that need to write to the file so you can try setting chmod to 644 or 640.', 'security-ninja' ); ?></p> 
		<ul>
			<li><?php esc_html_e( 'Try setting chmod to 0400 or 0440 and if the site works normally that\'s the best one to use', 'security-ninja' ); ?></li>
			<li><?php esc_html_e( 'The "other" users should have no privileges on the file so set the last octal digit to zero', 'security-ninja' ); ?></li>
			<li><?php esc_html_e( 'The "group" users shouldn\'t have any access right as well unless Apache falls under that category, so set group rights to 0 or 4', 'security-ninja' ); ?></li>
		</ul>
		<p>
		<?php
		/* translators: %s: link to file permissions documentation */
		printf( esc_html__( 'This can vary depending on your server configuration - please check more details on %s', 'security-ninja' ), '<a href="https://developer.wordpress.org/advanced-administration/server/file-permissions/" target="_blank" rel="noopener noreferrer">developer.wordpress.org/advanced-administration/server/file-permissions/</a>' );
		?>
		</p>
