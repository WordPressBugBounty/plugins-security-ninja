<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "As with the WordPress core, keeping plugins up to date is one of the most important and easiest ways to keep your site secure. Since most plugins are free and therefore their code is available to anyone, having the latest version will ensure you're not prone to attacks based on known vulnerabilities.", 'security-ninja' ); ?></p>
				<p>
				<?php
					printf(
						wp_kses(
							/* translators: %s: URL to Dashboard - Updates page */
							__( 'If you downloaded a plugin from the official WP repository you can easily check if there are any updates available, and update it by opening <a target="_blank" href="%s">Dashboard - Updates</a>. If you bought the plugin from somewhere else check the item\'s support on instructions how to upgrade manually. <b>Remember</b> - always backup your files and database before upgrading!', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
								'b' => array(),
							)
						),
						esc_url( admin_url( 'update-core.php' ) )
					);
					?>
				</p>
