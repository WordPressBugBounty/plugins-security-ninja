<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "If you're not using a theme remove it from the WP themes folder. There's no reason to keep it there and in case the code is malicious or it has some vulnerabilities it can still be exploited by a hacker regardless of the fact the theme is not active.", 'security-ninja' ); ?></p>
					<p><em><?php esc_html_e( 'Note: To accommodate the WP Health Test, the test filters out the latest default WP theme you have installed.', 'security-ninja' ); ?></em></p>
					<p>
					<?php
							printf(
								wp_kses(
									/* translators: %s: URL to Appearance - Themes page */
									__( 'Open <a target="_blank" href="%s">Appearance - Themes</a> and use the list above to delete the themes you do not need.', 'security-ninja' ),
									array(
										'a' => array(
											'href'   => array(),
											'target' => array(),
										),
									)
								),
								esc_url( 'themes.php' )
							);
							?>
					</p>
