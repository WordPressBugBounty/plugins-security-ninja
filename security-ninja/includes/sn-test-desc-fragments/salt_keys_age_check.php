<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "It's recommended to change the security keys and salts once in a while. The process will invalidate all existing cookies. This does mean that all users will have to login again. It's a minor inconvenience that will ensure nobody can login with an old or stolen cookie.", 'security-ninja' ); ?></p>
			<p>
			<?php
					printf(
						wp_kses(
							/* translators: %s: URL to generate new security keys */
							__( 'To edit the keys open wp-config.php, <a target="_blank" href="%s" rel="noopener">generate new keys</a> and copy/paste them to overwrite the old ones.', 'security-ninja' ),
							array(
								'a' => array(
									'href'   => array(),
									'target' => array(),
									'rel'    => array(),
								),
							)
						),
						esc_url( 'https://api.wordpress.org/secret-key/1.1/salt/' )
					);
					?>
			</p>
