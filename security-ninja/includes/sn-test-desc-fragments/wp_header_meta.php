<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "You should be proud that your site is powered by WordPress and there's no need to hide that information. However disclosing the full WP version info in the default location (page header meta) is not wise. People with bad intentions can easily use Google to find site's that use a specific version of WordPress and target them with (0-day) exploits.", 'security-ninja' ); ?></p>
				<p><?php esc_html_e( "Place the following code in your theme's functions.php file in order to remove the header meta version info:", 'security-ninja' ); ?></p>
				<pre>function remove_version() {
					return '';
				}
			add_filter('the_generator', 'remove_version');</pre>
