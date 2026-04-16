<?php
/**
 * Security test help fragment (auto-split from sn-tests-description.php).
 */
defined( 'ABSPATH' ) || exit;
?>
<p><?php esc_html_e( "Security keys are used to ensure better encryption of information stored in the user's cookies and hashed passwords. They make your site harder to hack and access harder to crack by adding random elements to the password. You don't have to remember these keys. In fact once you set them you'll never see them again. Therefore there's no excuse for not setting them properly.", 'security-ninja' ); ?></p>
		<p>
		<?php
				$translation = __( 'Security keys (there are eight) are defined in wp-config.php as constants on lines #49-56. They should be as unique and as long as possible. WordPress made a great script which helps you generate those strings. Please use it! After the script generates strings those 8 lines of code should look something like this:', 'security-ninja' );
				$salt_url      = 'https://api.wordpress.org/secret-key/1.1/salt/';
				printf(
					wp_kses(
						/* translators: 1: introductory text, 2: URL to WordPress secret key API */
						'%1$s <a target="_blank" href="%2$s" rel="noopener noreferrer">' . esc_html__( 'Get new security keys', 'security-ninja' ) . '</a>',
						array(
							'a' => array(
								'href'   => array(),
								'target' => array(),
								'rel'    => array(),
							),
						)
					),
					esc_html( $translation ),
					esc_url( $salt_url )
				);
				?>
		</p>
		<pre>define('AUTH_KEY',         '}D4@p&lt;0VFKb*pdhM8c&lt;bb:qB%Fr8:- dc}U(,[K?hobrzsn*:r?,e^/eHsm6nHls');
			define('SECURE_AUTH_KEY',  'M2wEPuf7.%FWW1xvy]ar&amp;vy3gj,:1Go&gt;qs7d_N)nX}O[-(+AaDsiPbvAOdLG~dt}');
			define('LOGGED_IN_KEY',    'iA#+3)Xhf0E*oyN1A4#:0wVp|d&lt;F-rQQ Sf_HNMk,rVj,F,GdKF|b-:xBEM,y(,f');
			define('NONCE_KEY',        'ctGmyOSSfm1-WR/V:J6[;Zh|?a$slsWs_9BIKcM[}uh~+C|R}ylW4cU%D tIOG=d');
			define('AUTH_SALT',        '|@tYo .T&amp;-{wMmP&gt;ggj4p{,HKs!&gt;vsUXz/aPDlZ=1.D54m+#1xyt+%w)3r&amp;j]r?:');
			define('SECURE_AUTH_SALT', '`^mxb~AvK*Agn+h&gt;U!0GL2*2|R+HHyY%h1b%Aoo,Jy|M{}TP`mSTt&lt;fcm=O9`=bA');
			define('LOGGED_IN_SALT',   'Ow||n$:: HWM5%H7k+MW7{!Z[Z|G-UJZ6Pp8;Id^&lt;lK-&amp;W+}Q?wHw!xlp2g(1% w');
			define('NONCE_SALT',       'IoLWhDF-d&lt;&gt;`u}R4oEe5kXf+)&lt;.}Ib?BPE&lt;C9R=NQivhZ|8k^b@LhkpuqojnzdVI');
		</pre>

		<p><b><?php esc_html_e( 'Warning', 'security-ninja' ); ?></b>: <?php esc_html_e( 'Do NOT use the keys above. They are just an example, publicly available and therefore not safe. Generate your own ones.', 'security-ninja' ); ?></p>
