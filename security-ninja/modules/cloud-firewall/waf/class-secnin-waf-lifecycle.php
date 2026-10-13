<?php
/**
 * Early Firewall lifecycle helpers (free-shipping).
 *
 * Install orchestration stays premium-only. This class ships in Free so
 * Pro→Free downgrade and deactivation can still safely remove owned markers
 * and present recovery metadata.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Lifecycle
 */
class Secnin_Waf_Lifecycle {

	const HTACCESS_BEGIN = '# BEGIN Security Ninja WAF';
	const HTACCESS_END   = '# END Security Ninja WAF';
	const USERINI_BEGIN  = '; BEGIN Security Ninja WAF';
	const USERINI_END    = '; END Security Ninja WAF';
	const PROXY_MARKER   = 'secnin-waf-owned';
	const RECOVERY_OPT   = 'wf_sn_cf_waf_recovery';

	/**
	 * Allowed lifecycle statuses.
	 *
	 * @return string[]
	 */
	public static function allowed_statuses() {
		return array(
			'off',
			'probing',
			'pending',
			'partial',
			'active',
			'removal_pending',
			'failed_safe',
			'failed',
		);
	}

	/**
	 * Absolute path for root proxy file.
	 *
	 * @return string
	 */
	public static function get_bootstrap_path() {
		$abspath = defined( 'ABSPATH' ) ? ABSPATH : '';
		return trailingslashit( $abspath ) . 'secnin-waf.php';
	}

	/**
	 * .htaccess path.
	 *
	 * @return string
	 */
	public static function get_htaccess_path() {
		return trailingslashit( ABSPATH ) . '.htaccess';
	}

	/**
	 * .user.ini path.
	 *
	 * Returns false when user_ini.filename is empty (feature disabled / not scanned).
	 *
	 * @return string|false
	 */
	public static function get_user_ini_path() {
		if ( defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) && array_key_exists( 'secnin_test_user_ini_filename', $GLOBALS ) ) {
			$name = (string) $GLOBALS['secnin_test_user_ini_filename'];
			if ( '' === $name ) {
				return false;
			}
			return trailingslashit( ABSPATH ) . $name;
		}
		$name = ini_get( 'user_ini.filename' );
		if ( ! is_string( $name ) || '' === $name ) {
			return false;
		}
		return trailingslashit( ABSPATH ) . $name;
	}

	/**
	 * Preferred private data directory for WAF runtime/config.
	 *
	 * Prefer WP_CONTENT_DIR/security-ninja-waf (not under uploads).
	 *
	 * @return string
	 */
	public static function get_data_dir() {
		if ( defined( 'SECNIN_WAF_DATA_DIR' ) && is_string( SECNIN_WAF_DATA_DIR ) && '' !== SECNIN_WAF_DATA_DIR ) {
			return rtrim( SECNIN_WAF_DATA_DIR, '/\\' );
		}
		return trailingslashit( WP_CONTENT_DIR ) . 'security-ninja-waf';
	}

	/**
	 * Detect server profile for prepend install.
	 *
	 * @return string apache-mod_php|litespeed|cgi|nginx|iis|unknown
	 */
	public static function detect_server_profile() {
		if ( defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) && isset( $GLOBALS['secnin_test_server_profile'] ) ) {
			return (string) $GLOBALS['secnin_test_server_profile'];
		}

		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		$sapi     = strtolower( (string) PHP_SAPI );

		if ( false !== strpos( $software, 'litespeed' ) || false !== strpos( $sapi, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( false !== strpos( $software, 'microsoft-iis' ) || 'isapi' === $sapi ) {
			return 'iis';
		}
		// Prefer SAPI over SERVER_SOFTWARE so nginx-fronted mod_php is not forced onto .user.ini-only.
		if ( in_array( $sapi, array( 'apache2handler', 'apache' ), true ) || false !== strpos( $sapi, 'apache' ) ) {
			return 'apache-mod_php';
		}
		if ( false !== strpos( $software, 'nginx' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $sapi, 'cgi' ) || false !== strpos( $sapi, 'fpm' ) || 'fpm-fcgi' === $sapi ) {
			return 'cgi';
		}
		return 'unknown';
	}

	/**
	 * Whether Early Firewall installation is eligible on this site.
	 *
	 * @return array{ok:bool,code:string,message:string,profile:string}
	 */
	public static function eligibility() {
		$profile = self::detect_server_profile();

		if ( is_multisite() ) {
			return array(
				'ok'      => false,
				'code'    => 'multisite',
				'message' => __( 'Early Firewall is not available on multisite yet. WordPress-hooks firewall protection remains available.', 'security-ninja' ),
				'profile' => $profile,
			);
		}

		if ( 'iis' === $profile ) {
			return array(
				'ok'      => false,
				'code'    => 'iis',
				'message' => __( 'Early Firewall is not available on IIS in this beta.', 'security-ninja' ),
				'profile' => $profile,
			);
		}

		if ( 'unknown' === $profile ) {
			return array(
				'ok'      => false,
				'code'    => 'unknown_sapi',
				'message' => __( 'Early Firewall cannot safely detect this PHP/server profile yet.', 'security-ninja' ),
				'profile' => $profile,
			);
		}

		if ( in_array( $profile, array( 'cgi', 'nginx' ), true ) && ! self::get_user_ini_path() ) {
			return array(
				'ok'      => false,
				'code'    => 'user_ini_disabled',
				'message' => __( 'PHP user_ini.filename is empty on this host, so Early Firewall cannot set auto_prepend_file via .user.ini.', 'security-ninja' ),
				'profile' => $profile,
			);
		}

		$current = self::current_auto_prepend();
		$label   = self::label_prepend_path( $current );
		if ( '' !== $current && ! empty( $label['is_competing_waf'] ) ) {
			return array(
				'ok'      => false,
				'code'    => 'competing_waf',
				'message' => __( 'Another security WAF already owns auto_prepend_file. Disable or migrate away from it before enabling Early Firewall. Security Ninja will not chain competing WAFs.', 'security-ninja' ),
				'profile' => $profile,
				'current' => $current,
				'label'   => $label,
			);
		}
		if ( '' !== $current && ! empty( $label['is_unknown'] ) ) {
			return array(
				'ok'      => false,
				'code'    => 'unknown_prepend',
				'message' => __( 'An unrecognized PHP prepend file is already set. Guided migration is required; Security Ninja will not chain unknown prepends.', 'security-ninja' ),
				'profile' => $profile,
				'current' => $current,
				'label'   => $label,
			);
		}

		// Host php.ini prepends (e.g. Local WP local-bootstrap.php). We attempt site-level
		// override via .user.ini / .htaccess and chain the prior file after confirm. Many
		// hosts never yield (php.ini / php_admin_value wins); Verify must fail-safe and clean up.
		if ( self::is_host_ini_prepend() ) {
			if ( ! empty( $label['is_non_waf'] ) ) {
				return array(
					'ok'                       => true,
					'code'                     => 'host_ini_non_waf',
					'message'                  => __( 'PHP currently prepends a host/application file (not a security WAF). Early Firewall will try to override it for this site and chain that file after you confirm. If the host locks auto_prepend_file in php.ini, Enable will not become Active and WordPress-hooks protection stays in place.', 'security-ninja' ),
					'profile'                  => $profile,
					'current'                  => $current,
					'label'                    => $label,
					'requires_confirm_non_waf' => true,
				);
			}
			return array(
				'ok'      => false,
				'code'    => 'host_ini',
				'message' => __( 'auto_prepend_file appears to be set in the host php.ini and could not be classified as a safe non-WAF bootstrap. Early Firewall was not enabled.', 'security-ninja' ),
				'profile' => $profile,
				'current' => $current,
				'label'   => $label,
			);
		}

		$requires_confirm = ( '' !== $current && ! empty( $label['is_non_waf'] ) && empty( $label['is_ours'] ) );

		return array(
			'ok'                       => true,
			'code'                     => $requires_confirm ? 'non_waf_prepend' : 'eligible',
			'message'                  => $requires_confirm
				? __( 'An existing non-WAF PHP prepend was found. Enabling Early Firewall will chain it after you confirm.', 'security-ninja' )
				: '',
			'profile'                  => $profile,
			'current'                  => $current,
			'label'                    => $label,
			'requires_confirm_non_waf' => $requires_confirm,
		);
	}

	/**
	 * Current auto_prepend_file value.
	 *
	 * @return string
	 */
	public static function current_auto_prepend() {
		if ( defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) && array_key_exists( 'secnin_test_auto_prepend', $GLOBALS ) ) {
			return (string) $GLOBALS['secnin_test_auto_prepend'];
		}
		$val = ini_get( 'auto_prepend_file' );
		return is_string( $val ) ? $val : '';
	}

	/**
	 * Label an existing auto_prepend_file path.
	 *
	 * Unknown prepends default to refuse (guided migration). Only an explicit
	 * allowlist of non-WAF host/APM shims may be chained after confirm.
	 *
	 * @param string $path Path from ini_get.
	 * @return array{label:string,risk:string,is_ours:bool,is_competing_waf:bool,is_non_waf:bool,is_unknown:bool}
	 */
	public static function label_prepend_path( $path ) {
		$path = (string) $path;
		if ( '' === $path ) {
			return array(
				'label'            => 'none',
				'risk'             => 'none',
				'is_ours'          => false,
				'is_competing_waf' => false,
				'is_non_waf'       => false,
				'is_unknown'       => false,
			);
		}
		$base = strtolower( basename( $path ) );
		$full = strtolower( str_replace( '\\', '/', $path ) );
		if ( false !== strpos( $full, 'secnin-waf.php' ) ) {
			return array(
				'label'            => __( 'Already installed', 'security-ninja' ),
				'risk'             => 'ours',
				'is_ours'          => true,
				'is_competing_waf' => false,
				'is_non_waf'       => false,
				'is_unknown'       => false,
			);
		}
		if ( self::path_looks_like_competing_waf( $full, $base ) ) {
			return array(
				'label'            => __( 'Another security plugin', 'security-ninja' ),
				'risk'             => 'competing_waf',
				'is_ours'          => false,
				'is_competing_waf' => true,
				'is_non_waf'       => false,
				'is_unknown'       => false,
			);
		}
		if ( self::path_looks_like_allowlisted_non_waf( $full, $base ) ) {
			return array(
				'label'            => __( 'Host or APM prepend (non-WAF)', 'security-ninja' ),
				'risk'             => 'non_waf',
				'is_ours'          => false,
				'is_competing_waf' => false,
				'is_non_waf'       => true,
				'is_unknown'       => false,
			);
		}
		return array(
			'label'            => __( 'Unrecognized PHP prepend', 'security-ninja' ),
			'risk'             => 'unknown_prepend',
			'is_ours'          => false,
			'is_competing_waf' => false,
			'is_non_waf'       => false,
			'is_unknown'       => true,
		);
	}

	/**
	 * Competing security WAF path patterns.
	 *
	 * @param string $full Lowercased path with forward slashes.
	 * @param string $base Lowercased basename.
	 * @return bool
	 */
	private static function path_looks_like_competing_waf( $full, $base ) {
		$needles = array(
			'wordfence-waf.php',
			'wordfence/waf/bootstrap.php',
			'ninjafirewall',
			'nfw-comm',
			'nexura-waf',
			'sucuri',
			'aiowps',
			'malcare',
			'icwp-wpsf',
			'wp-simple-firewall',
			'wp-cerber',
			'cerber-scanner',
			'bpsprotect',
			'bulletproof',
		);
		foreach ( $needles as $needle ) {
			if ( false !== strpos( $full, $needle ) ) {
				return true;
			}
		}
		if ( false !== strpos( $base, 'nfw' ) || false !== strpos( $base, 'wordfence' ) || false !== strpos( $base, 'malcare' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Allowlisted non-WAF host/APM prepends that may be chained after confirm.
	 *
	 * @param string $full Lowercased path with forward slashes.
	 * @param string $base Lowercased basename.
	 * @return bool
	 */
	private static function path_looks_like_allowlisted_non_waf( $full, $base ) {
		if ( 'local-bootstrap.php' === $base || false !== strpos( $full, '/local-bootstrap.php' ) ) {
			return true;
		}
		$needles = array(
			'newrelic',
			'new_relic',
			'datadog',
			'ddtrace',
			'blackfire',
		);
		foreach ( $needles as $needle ) {
			if ( false !== strpos( $full, $needle ) || false !== strpos( $base, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether prepend appears to come from a host php.ini we cannot rewrite.
	 *
	 * @return bool
	 */
	public static function is_host_ini_prepend() {
		if ( defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) && array_key_exists( 'secnin_test_host_ini_prepend', $GLOBALS ) ) {
			return ! empty( $GLOBALS['secnin_test_host_ini_prepend'] );
		}
		$current = self::current_auto_prepend();
		if ( '' === $current ) {
			return false;
		}
		$info = self::label_prepend_path( $current );
		if ( $info['is_ours'] ) {
			return false;
		}
		$user_ini = self::get_user_ini_path();
		$htaccess = self::get_htaccess_path();
		$in_user  = false;
		$in_ht    = false;
		if ( $user_ini && is_readable( $user_ini ) ) {
			$in_user = false !== strpos( (string) file_get_contents( $user_ini ), 'auto_prepend_file' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		}
		if ( $htaccess && is_readable( $htaccess ) ) {
			$in_ht = false !== strpos( (string) file_get_contents( $htaccess ), 'auto_prepend_file' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		}
		return ! $in_user && ! $in_ht;
	}

	/**
	 * Generate root proxy PHP content.
	 *
	 * @param string|null $chain_file Prior non-WAF auto_prepend_file to include.
	 * @param string|null $runtime_bootstrap Absolute path to runtime bootstrap outside plugin dir.
	 * @return string
	 */
	public static function get_proxy_content( $chain_file = null, $runtime_bootstrap = null ) {
		$proxy_dir = dirname( self::get_bootstrap_path() );

		if ( is_string( $runtime_bootstrap ) && '' !== $runtime_bootstrap ) {
			$target = $runtime_bootstrap;
		} else {
			$target = ( defined( 'WF_SN_PLUGIN_DIR' ) ? WF_SN_PLUGIN_DIR : '' ) . 'modules/cloud-firewall/waf/bootstrap.php';
		}

		$rel = Secnin_Fs_Atomic::relative_include_suffix( $proxy_dir, $target );

		$chain = '';
		if ( $chain_file && is_string( $chain_file ) && is_file( $chain_file ) ) {
			$chain = sprintf(
				"\n// Prior auto_prepend_file during Security Ninja WAF install (%s)\nif (file_exists(%s)) {\n\tinclude_once %s;\n}\n",
				gmdate( 'r' ),
				var_export( $chain_file, true ),
				var_export( $chain_file, true )
			);
		}

		return "<?php\n"
			. "// Security Ninja Early Firewall proxy (" . self::PROXY_MARKER . ").\n"
			. "// Before removing this file, verify auto_prepend_file does not point here.\n"
			. $chain
			. "\$__secnin_waf_target = __DIR__ . " . var_export( $rel, true ) . ";\n"
			. "if (is_string(\$__secnin_waf_target) && file_exists(\$__secnin_waf_target)) {\n"
			. "\tinclude_once \$__secnin_waf_target;\n"
			. "}\n";
	}

	/**
	 * Whether an existing root proxy is owned by Security Ninja.
	 *
	 * @param string $path Proxy path.
	 * @return bool
	 */
	public static function proxy_is_owned( $path = '' ) {
		$path = $path ? (string) $path : self::get_bootstrap_path();
		if ( ! is_readable( $path ) ) {
			return false;
		}
		$contents = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		return false !== strpos( $contents, self::PROXY_MARKER )
			|| false !== strpos( $contents, 'Security Ninja WAF' )
			|| false !== strpos( $contents, 'modules/cloud-firewall/waf/bootstrap.php' );
	}

	/**
	 * Admin notice for removal_pending / stranded Early Firewall state (Free+Pro).
	 *
	 * @return void
	 */
	public static function maybe_admin_notice() {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			return;
		}
		$ext = Secnin_Waf_Extended::get();
		if ( 'removal_pending' === $ext['status'] ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html__( 'Early Firewall is turning off. Open Firewall settings to confirm when it is done.', 'security-ninja' );
			echo '</p></div>';
			return;
		}
		if ( 'failed_safe' === $ext['status'] && ! empty( $ext['install_error'] ) ) {
			echo '<div class="notice notice-error"><p>';
			echo esc_html( $ext['install_error'] );
			echo '</p></div>';
		}
	}

	/**
	 * Save recovery metadata (public fields) and optional encrypted snapshots.
	 *
	 * @param array $data Recovery data.
	 * @return void
	 */
	public static function store_recovery( $data ) {
		$current = get_option( self::RECOVERY_OPT, array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}
		$merged = array_merge( $current, is_array( $data ) ? $data : array() );
		$merged['updated_at'] = time();
		update_option( self::RECOVERY_OPT, $merged, false );
	}

	/**
	 * Get recovery metadata for admin display.
	 *
	 * @return array
	 */
	public static function get_recovery() {
		$raw = get_option( self::RECOVERY_OPT, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Snapshot a config file for admin-assisted recovery (not auto-restored).
	 *
	 * @param string $source_path File path.
	 * @param string $label       Label.
	 * @return array{ok:bool,path?:string,hash?:string,error?:string}
	 */
	public static function snapshot_for_recovery( $source_path, $label ) {
		if ( ! class_exists( __NAMESPACE__ . '\\Secnin_Secure_Snapshot' ) || ! class_exists( __NAMESPACE__ . '\\Secnin_Fs_Atomic' ) ) {
			return array(
				'ok'    => false,
				'error' => 'snapshot_unavailable',
			);
		}
		if ( ! is_readable( $source_path ) ) {
			return array(
				'ok'    => true,
				'hash'  => '',
				'note'  => 'source_missing',
			);
		}

		$created = Secnin_Secure_Snapshot::create_from_file( $source_path, $label );
		if ( empty( $created['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => isset( $created['error'] ) ? $created['error'] : 'create_failed',
			);
		}

		$dir = trailingslashit( self::get_data_dir() ) . 'recovery';
		Secnin_Fs_Atomic::protect_directory( dirname( $dir ) );
		Secnin_Fs_Atomic::protect_directory( $dir );
		$path = $dir . '/' . preg_replace( '/[^a-zA-Z0-9_-]/', '', $label ) . '-' . time() . '.php';
		$write = Secnin_Secure_Snapshot::write_guarded_php( $path, $created['envelope'] );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'    => false,
				'error' => 'write_failed',
			);
		}

		return array(
			'ok'   => true,
			'path' => $path,
			'hash' => isset( $created['envelope']['h'] ) ? $created['envelope']['h'] : '',
		);
	}

	/**
	 * Remove owned .htaccess WAF block only.
	 *
	 * @return array{ok:bool,changed:bool,message:string}
	 */
	public static function remove_htaccess_block() {
		$path = self::get_htaccess_path();
		if ( ! is_readable( $path ) ) {
			return array(
				'ok'      => true,
				'changed' => false,
				'message' => 'missing',
			);
		}
		$existing = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$regex    = '/' . preg_quote( self::HTACCESS_BEGIN, '/' ) . '.*?' . preg_quote( self::HTACCESS_END, '/' ) . '\s*/is';
		if ( ! preg_match( $regex, $existing ) ) {
			return array(
				'ok'      => true,
				'changed' => false,
				'message' => 'no_block',
			);
		}
		$updated = preg_replace( $regex, '', $existing );
		$write   = Secnin_Fs_Atomic::write_file( $path, (string) $updated, 0 );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'      => false,
				'changed' => false,
				'message' => 'write_failed',
			);
		}
		return array(
			'ok'      => true,
			'changed' => true,
			'message' => 'removed',
		);
	}

	/**
	 * Remove owned .user.ini WAF block only.
	 *
	 * @return array{ok:bool,changed:bool,message:string}
	 */
	public static function remove_user_ini_block() {
		$path = self::get_user_ini_path();
		if ( ! $path || ! is_readable( $path ) ) {
			return array(
				'ok'      => true,
				'changed' => false,
				'message' => 'missing',
			);
		}
		$existing = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$regex    = '/' . preg_quote( self::USERINI_BEGIN, '/' ) . '.*?' . preg_quote( self::USERINI_END, '/' ) . '\s*/is';
		if ( ! preg_match( $regex, $existing ) ) {
			return array(
				'ok'      => true,
				'changed' => false,
				'message' => 'no_block',
			);
		}
		$updated = preg_replace( $regex, '', $existing );
		$write   = Secnin_Fs_Atomic::write_file( $path, (string) $updated, 0 );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'      => false,
				'changed' => false,
				'message' => 'write_failed',
			);
		}
		return array(
			'ok'      => true,
			'changed' => true,
			'message' => 'removed',
		);
	}

	/**
	 * Whether two auto_prepend paths refer to the same file.
	 *
	 * @param string $a Path A.
	 * @param string $b Path B.
	 * @return bool
	 */
	public static function paths_same_prepend( $a, $b ) {
		$a = (string) $a;
		$b = (string) $b;
		if ( '' === $a || '' === $b ) {
			return false;
		}
		if ( $a === $b ) {
			return true;
		}
		$ra = realpath( $a );
		$rb = realpath( $b );
		return ( is_string( $ra ) && is_string( $rb ) && '' !== $ra && $ra === $rb );
	}

	/**
	 * Abort a Pending install that never became live (host still owns prepend).
	 *
	 * Safe to delete the proxy when PHP is not loading it. Leaves WordPress-hooks
	 * protection as the only layer (mode legacy / failed_safe).
	 *
	 * @param string $message Error shown in admin.
	 * @return array{success:bool,message:string,data?:array}
	 */
	public static function abort_inert_install( $message ) {
		$ht = self::remove_htaccess_block();
		$ui = self::remove_user_ini_block();

		$ours    = self::get_bootstrap_path();
		$current = self::current_auto_prepend();
		$label   = self::label_prepend_path( $current );
		$removed = ! empty( $ht['ok'] ) && ! empty( $ui['ok'] );

		if ( $removed && empty( $label['is_ours'] ) && is_file( $ours ) && self::proxy_is_owned( $ours ) ) {
			@unlink( $ours ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
		}

		$final_message = $message;
		$mode          = 'legacy';
		if ( ! $removed || ! empty( $label['is_ours'] ) ) {
			$mode          = 'extended';
			$final_message = __( 'Early Firewall could not be rolled back safely. Its proxy file was kept because PHP may still reference it. WordPress-hooks protection remains active; review file permissions and try Disable again.', 'security-ninja' );
		}

		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			Secnin_Waf_Extended::update(
				array(
					'mode'          => $mode,
					'status'        => 'failed_safe',
					'install_error' => $final_message,
					'install_hint'  => '',
					'verify_fails'  => 0,
				)
			);
		}

		self::store_recovery(
			array(
				'aborted_inert_at' => time(),
				'note'             => 'Inert install cleaned: host still owned auto_prepend_file.',
			)
		);

		return array(
			'success' => false,
			'message' => $final_message,
			'data'    => array(
				'htaccess' => $ht,
				'user_ini' => $ui,
			),
		);
	}

	/**
	 * Begin safe removal: remove directives, keep proxy until verified unused.
	 *
	 * @param array $args Optional args.
	 * @return array{success:bool,message:string,data?:array}
	 */
	public static function begin_removal( $args = array() ) {
		$ht = self::remove_htaccess_block();
		$ui = self::remove_user_ini_block();

		if ( ! $ht['ok'] || ! $ui['ok'] ) {
			if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
				Secnin_Waf_Extended::update(
					array(
						'status'        => 'failed_safe',
						'install_error' => __( 'Could not fully remove Early Firewall configuration markers. Proxy file was kept to avoid a fatal auto_prepend error.', 'security-ninja' ),
					)
				);
			}
			return array(
				'success' => false,
				'message' => __( 'Could not fully remove Early Firewall configuration markers. Proxy file was kept to avoid a fatal auto_prepend error.', 'security-ninja' ),
				'data'    => array(
					'htaccess' => $ht,
					'user_ini' => $ui,
				),
			);
		}

		$ttl = (int) ini_get( 'user_ini.cache_ttl' );
		if ( $ttl <= 0 ) {
			$ttl = 300;
		}

		if ( empty( $args['skip_status'] ) && class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			Secnin_Waf_Extended::update(
				array(
					'mode'          => 'extended',
					'status'        => 'removal_pending',
					'install_error' => '',
					'last_rollback' => '',
				)
			);
		}

		self::store_recovery(
			array(
				'removal_started'   => time(),
				'removal_ttl'       => $ttl,
				'prior_prepend'     => isset( $args['prior_prepend'] ) ? (string) $args['prior_prepend'] : '',
				'note'              => 'Owned markers removed. Proxy retained until PHP no longer prepends it.',
			)
		);

		return array(
			'success' => true,
			'message' => __( 'Early Firewall is turning off. PHP can keep the old setting for a few minutes.', 'security-ninja' ),
			'data'    => array(
				'ttl'      => $ttl,
				'htaccess' => $ht,
				'user_ini' => $ui,
			),
		);
	}

	/**
	 * Finish removal only when TTL elapsed and prepend no longer points at our proxy.
	 *
	 * Prefer leaving an inert owned stub over deleting a still-referenced proxy.
	 *
	 * @return array{success:bool,message:string}
	 */
	public static function finish_removal_if_safe() {
		$recovery = self::get_recovery();
		$started  = ! empty( $recovery['removal_started'] ) ? (int) $recovery['removal_started'] : 0;
		$ttl      = ! empty( $recovery['removal_ttl'] ) ? (int) $recovery['removal_ttl'] : (int) ini_get( 'user_ini.cache_ttl' );
		if ( $ttl <= 0 ) {
			$ttl = 300;
		}

		if ( $started > 0 && ( time() - $started ) < $ttl ) {
			return array(
				'success' => false,
				'message' => __( 'Early Firewall is still turning off. Try again in a few minutes.', 'security-ninja' ),
			);
		}

		$current = self::current_auto_prepend();
		$ours    = self::get_bootstrap_path();
		$still   = self::prepend_still_ours( $current, $ours );

		// Loopback probe: if our proxy would still load, do not delete.
		if ( ! $still && file_exists( $ours ) ) {
			$probe_still = self::loopback_still_prepends_ours();
			if ( $probe_still ) {
				$still = true;
			}
		}

		if ( $still ) {
			self::write_inert_proxy_stub( $ours );
			if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
				Secnin_Waf_Extended::update(
					array(
						'status'        => 'failed_safe',
						'install_error' => __( 'PHP may still reference secnin-waf.php. An inert stub was left in place. Wait for host TTL, then use Verify removal again.', 'security-ninja' ),
					)
				);
			}
			return array(
				'success' => false,
				'message' => __( 'PHP still appears to prepend secnin-waf.php. An inert stub was kept to avoid include warnings. Wait for cache TTL and try again.', 'security-ninja' ),
			);
		}

		if ( file_exists( $ours ) && self::proxy_is_owned( $ours ) ) {
			$deleted = @unlink( $ours ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			if ( ! $deleted && file_exists( $ours ) ) {
				self::write_inert_proxy_stub( $ours );
				if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
					Secnin_Waf_Extended::update(
						array(
							'status'        => 'failed_safe',
							'install_error' => __( 'Could not delete secnin-waf.php. An inert stub was written instead.', 'security-ninja' ),
						)
					);
				}
				return array(
					'success' => false,
					'message' => __( 'Could not delete secnin-waf.php. An inert stub was left so PHP will not fatal. Remove it manually after PHP stops prepending it.', 'security-ninja' ),
				);
			}
		}

		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			Secnin_Waf_Extended::update(
				array(
					'mode'            => 'legacy',
					'status'          => 'off',
					'prepend_path'    => '',
					'chained_prepend' => '',
					'install_error'   => '',
					'install_hint'    => '',
				)
			);
		}

		return array(
			'success' => true,
			'message' => __( 'Early Firewall fully removed.', 'security-ninja' ),
		);
	}

	/**
	 * Whether current prepend still points at our proxy.
	 *
	 * @param string $current Current auto_prepend_file.
	 * @param string $ours    Our proxy path.
	 * @return bool
	 */
	private static function prepend_still_ours( $current, $ours ) {
		if ( '' === $current ) {
			return false;
		}
		$label = self::label_prepend_path( $current );
		if ( ! empty( $label['is_ours'] ) ) {
			return true;
		}
		$rp_c = realpath( $current );
		$rp_o = realpath( $ours );
		return ( $rp_c && $rp_o && $rp_c === $rp_o );
	}

	/**
	 * Loopback check: home URL probe should not return our WAF marker header.
	 *
	 * @return bool True if prepend still appears active.
	 */
	private static function loopback_still_prepends_ours() {
		if ( ! function_exists( 'wp_remote_get' ) || ! class_exists( __NAMESPACE__ . '\\Secnin_Waf_Config' ) ) {
			return true;
		}
		$token = function_exists( 'wp_generate_password' ) ? wp_generate_password( 12, false, false ) : uniqid( 'sn', true );
		$key   = Secnin_Waf_Config::ensure_integrity_key();
		if ( '' === $key ) {
			return true;
		}
		$expected = hash_hmac( 'sha256', $token, $key );
		$url      = add_query_arg(
			array(
				'secnin_waf_probe' => rawurlencode( $token ),
				'nocache'          => (string) time(),
			),
			home_url( '/' )
		);
		$resp = wp_remote_get(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		if ( is_wp_error( $resp ) ) {
			return true;
		}
		$header = wp_remote_retrieve_header( $resp, 'x-secnin-waf' );
		return is_string( $header ) && '' !== $header && hash_equals( $expected, $header );
	}

	/**
	 * Write an inert owned proxy stub (file_exists-guarded includes only).
	 *
	 * @param string $path Proxy path.
	 * @return bool
	 */
	public static function write_inert_proxy_stub( $path ) {
		if ( '' === $path ) {
			return false;
		}
		$content = "<?php\n"
			. "// Security Ninja Early Firewall inert stub (removal in progress)\n"
			. "// Owned by Security Ninja — do not delete while PHP may still prepend this file.\n"
			. "if (!defined('ABSPATH') && !defined('SECNIN_WAF_INERT_STUB')) {\n"
			. "\tdefine('SECNIN_WAF_INERT_STUB', true);\n"
			. "}\n"
			. "return;\n";
		$write = Secnin_Fs_Atomic::write_file( $path, $content, 0644 );
		return Secnin_Fs_Atomic::is_ok( $write );
	}

	/**
	 * Wipe private WAF data directory when safe (uninstall / data removal).
	 *
	 * @return bool
	 */
	public static function wipe_data_dir_if_safe() {
		$dir = self::get_data_dir();
		if ( ! is_dir( $dir ) ) {
			return true;
		}
		$ours  = self::get_bootstrap_path();
		$still = self::prepend_still_ours( self::current_auto_prepend(), $ours );
		if ( $still ) {
			self::write_inert_proxy_stub( $ours );
			return false;
		}
		return self::rrmdir( $dir );
	}

	/**
	 * Recursively remove a directory.
	 *
	 * @param string $dir Directory.
	 * @return bool
	 */
	private static function rrmdir( $dir ) {
		$dir = rtrim( $dir, '/\\' );
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return true;
		}
		$items = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $items ) ) {
			return false;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . DIRECTORY_SEPARATOR . $item;
			if ( is_dir( $path ) ) {
				self::rrmdir( $path );
			} else {
				@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}
		return @rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	}

	/**
	 * Delete WAF-related options used by Early Firewall.
	 *
	 * @return void
	 */
	public static function delete_waf_options() {
		$keys = array(
			'wf_sn_cf_extended',
			'wf_sn_cf_waf_recovery',
			'wf_sn_cf_waf_cookie_key',
			'wf_sn_cf_waf_event_receipts',
		);
		foreach ( $keys as $key ) {
			delete_option( $key );
		}
	}

	/**
	 * Safe uninstall entry for Free/Pro deactivation paths.
	 *
	 * Removes owned markers; does not delete proxy until finish_removal_if_safe().
	 * On marker write failure: keep inert stub and surface failed_safe.
	 *
	 * @param array $args Args.
	 * @return array{success:bool,message:string}
	 */
	public static function safe_deactivate_cleanup( $args = array() ) {
		$result = self::begin_removal( $args );
		if ( empty( $result['success'] ) ) {
			$ours = self::get_bootstrap_path();
			if ( file_exists( $ours ) && self::proxy_is_owned( $ours ) ) {
				self::write_inert_proxy_stub( $ours );
			}
			if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
				Secnin_Waf_Extended::update(
					array(
						'status'        => 'failed_safe',
						'install_error' => isset( $result['message'] ) ? (string) $result['message'] : __( 'Early Firewall marker removal failed. Proxy kept as inert stub until host TTL clears.', 'security-ninja' ),
					)
				);
			}
			return $result;
		}
		// Attempt immediate finish when prepend already cleared (mod_php often instant).
		$finish = self::finish_removal_if_safe();
		if ( ! empty( $finish['success'] ) ) {
			return $finish;
		}
		return $result;
	}
}
