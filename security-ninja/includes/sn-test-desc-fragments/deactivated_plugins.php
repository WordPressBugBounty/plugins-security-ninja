<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( 'If you are not using a plugin remove it from the WP plugins folder. It is that simple. There is no reason to keep it there and in case the code is malicious or it has some vulnerabilities it can still be exploited by a hacker regardless of the fact the plugin is not active.', 'security-ninja' ); ?></p>
				<p>
				<?php
					printf(
						wp_kses(
							/* translators: %s: URL to plugins page */
							__( 'Open <a target="_blank" href="%s">plugins</a> and simply delete all plugins that are not active. Or login via FTP and move them to some folder that\'s not /wp-content/plugins/.', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
								),
							)
						),
						esc_url( admin_url( 'plugins.php?plugin_status=inactive' ) )
					);
					?>
				</p>
