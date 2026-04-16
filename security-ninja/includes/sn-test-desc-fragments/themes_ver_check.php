<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "As with the WordPress core, keeping the themes up to date is one of the most important and easiest ways to keep your site secure. Since most themes are free and therefore their code is available to anyone having the latest version will ensure you're not prone to attacks based on known vulnerabilities. Also, having the latest version will ensure your theme is compatible with the latest version of WordPress.", 'security-ninja' ); ?></p>
				<p>
				<?php
						printf(
							wp_kses(
								/* translators: %s: URL to Appearance - Themes page */
								__( 'If you downloaded a theme from the official WP repository you can easily check if there are any updates available, and upgrade it by opening <a target="_blank" href="%s">Appearance - Themes</a>. If you bought the theme from a theme shop check their support and upgrade manually. <b>Remember</b> - always backup your files and database before upgrading!', 'security-ninja' ),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
									'b' => array(),
								)
							),
							esc_url( 'themes.php' )
						);
						?>
				</p>
