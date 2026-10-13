<?php
/**
 * Sync firewall options to guarded Early WAF configuration generations.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Config
 */
class Secnin_Waf_Config {

	const SCHEMA_VERSION = 2;
	const ACTIVE_POINTER = 'active.php';

	/**
	 * Absolute path to the private WAF data directory.
	 *
	 * @return string
	 */
	public static function get_config_dir() {
		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
			return trailingslashit( Secnin_Waf_Lifecycle::get_data_dir() ) . 'config';
		}
		return trailingslashit( WP_CONTENT_DIR ) . 'security-ninja-waf/config';
	}

	/**
	 * Root data directory.
	 *
	 * @return string
	 */
	public static function get_data_dir() {
		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
			return Secnin_Waf_Lifecycle::get_data_dir();
		}
		return trailingslashit( WP_CONTENT_DIR ) . 'security-ninja-waf';
	}

	/**
	 * Ensure private config directory exists with denial files.
	 *
	 * @return bool
	 */
	public static function ensure_dir() {
		$data = self::get_data_dir();
		$dir  = self::get_config_dir();
		if ( ! class_exists( __NAMESPACE__ . '\\Secnin_Fs_Atomic' ) ) {
			return false;
		}
		Secnin_Fs_Atomic::protect_directory( $data );
		Secnin_Fs_Atomic::protect_directory( $dir );
		Secnin_Fs_Atomic::protect_directory( trailingslashit( $data ) . 'generations' );
		Secnin_Fs_Atomic::protect_directory( trailingslashit( $data ) . 'queue' );
		return is_dir( $dir ) && is_writable( $dir );
	}

	/**
	 * Whether Early Firewall is installed enough to keep runtime config synced.
	 *
	 * @return bool
	 */
	public static function should_sync() {
		if ( is_multisite() ) {
			return false;
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			return false;
		}
		return Secnin_Waf_Extended::is_installed() || Secnin_Waf_Extended::is_active();
	}

	/**
	 * One-way hash of unblock secret (never store plaintext in runtime files).
	 *
	 * @param string $secret Secret.
	 * @return string
	 */
	public static function hash_unblock_secret( $secret ) {
		$secret = (string) $secret;
		if ( '' === $secret ) {
			return '';
		}
		return hash_hmac( 'sha256', $secret, 'secnin-waf-unblock' );
	}

	/**
	 * Build generation payload from live options (not stale static caches).
	 *
	 * @param array|null $options Optional options override (e.g. from update_option).
	 * @return array
	 */
	public static function build_generation_payload( $options = null ) {
		if ( null === $options ) {
			// Always read from DB to avoid stale wf_sn_cf::$options after update_option.
			$options = get_option( 'wf_sn_cf', array() );
		}
		if ( ! is_array( $options ) ) {
			$options = array();
		}

		$cookie_key = get_option( 'wf_sn_cf_waf_cookie_key', '' );
		if ( ! is_string( $cookie_key ) || '' === $cookie_key ) {
			$cookie_key = wp_generate_password( 64, true, true );
			update_option( 'wf_sn_cf_waf_cookie_key', $cookie_key, false );
		}

		$unblock = isset( $options['unblock_url'] ) ? (string) $options['unblock_url'] : '';
		$login_slug = '';
		if ( ! empty( $options['change_login_url'] ) && ! empty( $options['new_login_url'] ) ) {
			$login_slug = sanitize_title( (string) $options['new_login_url'] );
		}

		$cloudflare = array();
		if ( class_exists( __NAMESPACE__ . '\\Wf_sn_cf_Utils' ) ) {
			$cloudflare = Wf_sn_cf_Utils::get_cloudflare_proxy_cidrs();
		}

		$bans_raw = get_option( 'wf_sn_banned_ips', array() );
		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Ban_Clock' ) ) {
			$bans_raw = Secnin_Waf_Ban_Clock::maybe_migrate();
		}
		$bans = is_array( $bans_raw ) ? $bans_raw : array();

		$cloud_raw = get_option( 'wf_sn_cf_ips', array() );
		$cloud     = array(
			'ips'     => ( is_array( $cloud_raw ) && isset( $cloud_raw['ips'] ) && is_array( $cloud_raw['ips'] ) ) ? $cloud_raw['ips'] : array(),
			'subnets' => ( is_array( $cloud_raw ) && isset( $cloud_raw['subnets'] ) && is_array( $cloud_raw['subnets'] ) ) ? $cloud_raw['subnets'] : array(),
		);

		$validated = get_option( 'wf_sn_cf_validated_crawlers', array() );
		if ( ! is_array( $validated ) ) {
			$validated = array();
		}

		$generation_id = (string) time() . '-' . wp_generate_password( 8, false, false );

		$rules_8g = array();
		$rules_file = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/waf/rules-8g.php';
		if ( is_readable( $rules_file ) ) {
			$loaded = include $rules_file;
			if ( is_array( $loaded ) ) {
				$rules_8g = $loaded;
			}
		}
		$skip_query = (bool) apply_filters( 'wf_sn_cf_skip_bad_query_check', false );
		$query_rules = array(
			'request_uri'  => apply_filters( 'request_uri_items', isset( $rules_8g['request_uri'] ) && is_array( $rules_8g['request_uri'] ) ? $rules_8g['request_uri'] : array() ),
			'query_string' => apply_filters( 'query_string_items', isset( $rules_8g['query_string'] ) && is_array( $rules_8g['query_string'] ) ? $rules_8g['query_string'] : array() ),
			'user_agent'   => apply_filters( 'user_agent_items', isset( $rules_8g['user_agent'] ) && is_array( $rules_8g['user_agent'] ) ? $rules_8g['user_agent'] : array() ),
			'referrer'     => apply_filters( 'referrer_items', isset( $rules_8g['referrer'] ) && is_array( $rules_8g['referrer'] ) ? $rules_8g['referrer'] : array() ),
		);
		$temp_login_params = array();
		$temp_login_file   = WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/class-wf-sn-cf-temp-login.php';
		if ( is_readable( $temp_login_file ) ) {
			require_once $temp_login_file;
		}
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Cf_Temp_Login' ) ) {
			$temp_login_params = Wf_Sn_Cf_Temp_Login::get_active_parameter_rules();
		}

		$payload = array(
			'schema'              => self::SCHEMA_VERSION,
			'generation_id'       => $generation_id,
			'created_at'          => time(),
			'active'              => ! empty( $options['active'] ) ? 1 : 0,
			'filterqueries'       => ! empty( $options['filterqueries'] ) ? 1 : 0,
			'skip_query_filter'   => $skip_query ? 1 : 0,
			'query_rules'         => $query_rules,
			'usecloud'            => ! empty( $options['usecloud'] ) ? 1 : 0,
			'global'              => ! empty( $options['global'] ) ? 1 : 0,
			'ip_source'           => isset( $options['ip_source'] ) ? (string) $options['ip_source'] : 'auto',
			'trusted_proxy_cidrs' => isset( $options['trusted_proxy_cidrs'] ) && is_array( $options['trusted_proxy_cidrs'] ) ? $options['trusted_proxy_cidrs'] : array(),
			'cloudflare_cidrs'    => $cloudflare,
			'unblock_secret_hash' => self::hash_unblock_secret( $unblock ),
			'message'             => isset( $options['message'] ) ? (string) $options['message'] : 'You are not allowed to visit this website.',
			'redirect_url'        => isset( $options['redirect_url'] ) ? (string) $options['redirect_url'] : '',
			'login_slug'          => $login_slug,
			'cookie_key'          => $cookie_key,
			'temp_login_params'   => $temp_login_params,
			'ajax_allow'          => array(
				'secnin_generate_qr_code',
				'secnin_skip_2fa',
				'secnin_verify_2fa_code',
				'secnin_send_2fa_email',
			),
			'whitelist'           => isset( $options['whitelist'] ) && is_array( $options['whitelist'] ) ? array_values( $options['whitelist'] ) : array(),
			'blacklist'           => isset( $options['blacklist'] ) && is_array( $options['blacklist'] ) ? array_values( $options['blacklist'] ) : array(),
			'bans'                => $bans,
			'cloud'               => $cloud,
			'validated_crawlers'  => array_values( $validated ),
			'service_whitelist'   => self::collect_service_whitelist_ips(),
			'woocommerce_active'  => class_exists( 'WooCommerce' ) ? 1 : 0,
			'surecart_active'     => defined( 'SURECART_PLUGIN_FILE' ) ? 1 : 0,
		);

		$payload['checksum'] = self::checksum_payload( $payload );
		return $payload;
	}

	/**
	 * Collect static service whitelist IPs when premium files exist.
	 *
	 * @return array
	 */
	private static function collect_service_whitelist_ips() {
		$ips = array();
		$files = array(
			WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/whitelist-managewp.json',
			WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/whitelist-uptimerobot.json',
			WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/whitelist-uptimia.json',
		);
		foreach ( $files as $file ) {
			if ( ! is_readable( $file ) ) {
				continue;
			}
			$decoded = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( ! is_array( $decoded ) ) {
				continue;
			}
			foreach ( $decoded as $entry ) {
				if ( is_string( $entry ) && filter_var( $entry, FILTER_VALIDATE_IP ) ) {
					$ips[] = $entry;
				} elseif ( is_array( $entry ) && ! empty( $entry['ip'] ) && filter_var( $entry['ip'], FILTER_VALIDATE_IP ) ) {
					$ips[] = $entry['ip'];
				}
			}
		}
		return array_values( array_unique( $ips ) );
	}

	/**
	 * Path to integrity key used before WordPress loads.
	 *
	 * @return string
	 */
	public static function get_integrity_key_path() {
		return trailingslashit( self::get_data_dir() ) . 'runtime/integrity.key';
	}

	/**
	 * Ensure a binary integrity key exists for generation HMAC.
	 *
	 * @return string Hex key or empty.
	 */
	public static function ensure_integrity_key() {
		$path = self::get_integrity_key_path();
		if ( is_readable( $path ) ) {
			$hex = trim( (string) file_get_contents( $path ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( 64 === strlen( $hex ) && ctype_xdigit( $hex ) ) {
				return $hex;
			}
		}
		try {
			$hex = bin2hex( random_bytes( 32 ) );
		} catch ( \Exception $e ) {
			$hex = hash( 'sha256', wp_generate_password( 64, true, true ) );
		}
		Secnin_Fs_Atomic::mkdir_p( dirname( $path ), 0755 );
		Secnin_Fs_Atomic::write_file( $path, $hex, 0600 );
		return $hex;
	}

	/**
	 * Checksum excluding the checksum field itself.
	 *
	 * @param array       $payload Payload.
	 * @param string|null $key_hex Optional hex key.
	 * @return string
	 */
	public static function checksum_payload( $payload, $key_hex = null ) {
		$copy = $payload;
		unset( $copy['checksum'] );
		// Bootstrap runs before WordPress, so both sides must use PHP's encoder.
		$json = json_encode( $copy ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Must match the pre-WordPress bootstrap.
		if ( null === $key_hex ) {
			$key_hex = self::ensure_integrity_key();
		}
		return hash_hmac( 'sha256', (string) $json, (string) $key_hex );
	}

	/**
	 * Validate a loaded generation payload.
	 *
	 * @param array       $payload Payload.
	 * @param string|null $key_hex Optional integrity key.
	 * @return bool
	 */
	public static function is_valid_generation( $payload, $key_hex = null ) {
		if ( ! is_array( $payload ) ) {
			return false;
		}
		if ( empty( $payload['schema'] ) || (int) $payload['schema'] !== self::SCHEMA_VERSION ) {
			return false;
		}
		if ( empty( $payload['generation_id'] ) || empty( $payload['checksum'] ) ) {
			return false;
		}
		$expected = self::checksum_payload( $payload, $key_hex );
		return hash_equals( $expected, (string) $payload['checksum'] );
	}

	/**
	 * Write guarded PHP generation and activate it atomically via pointer.
	 *
	 * @param array $payload Payload.
	 * @return bool
	 */
	public static function activate_generation( $payload ) {
		if ( ! self::ensure_dir() || ! self::is_valid_generation( $payload ) ) {
			return false;
		}

		$gen_dir = trailingslashit( self::get_data_dir() ) . 'generations';
		$file    = $gen_dir . '/gen-' . preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $payload['generation_id'] ) . '.php';
		$export  = var_export( $payload, true );
		$content = "<?php\n// Security Ninja WAF config generation. Do not edit.\nif (!defined('SECNIN_WAF_BOOTSTRAP') && !defined('ABSPATH') && !defined('SECNIN_FS_ATOMIC_STANDALONE')) { exit('Access denied'); }\nreturn " . $export . ";\n";

		if ( ! Secnin_Fs_Atomic::is_ok( Secnin_Fs_Atomic::write_file( $file, $content, 0600 ) ) ) {
			return false;
		}

		$pointer = "<?php\n// Active WAF generation pointer.\nif (!defined('SECNIN_WAF_BOOTSTRAP') && !defined('ABSPATH') && !defined('SECNIN_FS_ATOMIC_STANDALONE')) { exit('Access denied'); }\nreturn " . var_export( $file, true ) . ";\n";
		$active  = trailingslashit( self::get_config_dir() ) . self::ACTIVE_POINTER;
		if ( ! Secnin_Fs_Atomic::is_ok( Secnin_Fs_Atomic::write_file( $active, $pointer, 0600 ) ) ) {
			return false;
		}

		// Also write a runtime-local active pointer beside the published bootstrap.
		$runtime_active = trailingslashit( self::get_data_dir() ) . 'runtime/active-config.php';
		Secnin_Fs_Atomic::write_file( $runtime_active, $pointer, 0600 );

		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Extended' ) ) {
			Secnin_Waf_Extended::update(
				array(
					'config_generation' => (int) $payload['created_at'],
				)
			);
		}

		self::prune_old_generations( $file );
		return true;
	}

	/**
	 * Keep last few generations for rollback.
	 *
	 * @param string $keep Absolute path to keep.
	 * @return void
	 */
	private static function prune_old_generations( $keep ) {
		$gen_dir = trailingslashit( self::get_data_dir() ) . 'generations';
		$files   = glob( $gen_dir . '/gen-*.php' );
		if ( ! is_array( $files ) || count( $files ) <= 5 ) {
			return;
		}
		usort(
			$files,
			static function ( $a, $b ) {
				return filemtime( $b ) <=> filemtime( $a );
			}
		);
		$i = 0;
		foreach ( $files as $file ) {
			$i++;
			if ( $i <= 5 || $file === $keep ) {
				continue;
			}
			@unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
		}
	}

	/**
	 * Load active generation path.
	 *
	 * @return string
	 */
	public static function get_active_generation_path() {
		$active = trailingslashit( self::get_config_dir() ) . self::ACTIVE_POINTER;
		if ( ! is_readable( $active ) ) {
			$active = trailingslashit( self::get_data_dir() ) . 'runtime/active-config.php';
		}
		if ( ! is_readable( $active ) ) {
			return '';
		}
		$path = include $active;
		return is_string( $path ) ? $path : '';
	}

	/**
	 * Sync all early-WAF files from WordPress options.
	 *
	 * @param mixed ...$args Optional update_option args, options array, or true to force sync during install.
	 * @return bool
	 */
	public static function sync_all( ...$args ) {
		$force = false;
		if ( isset( $args[0] ) && true === $args[0] && ! isset( $args[1] ) ) {
			$force = true;
			$args  = array();
		} elseif ( isset( $args[0] ) && is_array( $args[0] ) && isset( $args[0]['force'] ) && $args[0]['force'] ) {
			$force   = true;
			$options = isset( $args[0]['options'] ) && is_array( $args[0]['options'] ) ? $args[0]['options'] : null;
			$args    = null !== $options ? array( $options ) : array();
		}

		if ( ! $force && ! self::should_sync() ) {
			return false;
		}
		if ( ! self::ensure_dir() ) {
			return false;
		}

		$options = self::resolve_sync_options( $args );

		$key = self::ensure_integrity_key();
		if ( '' === $key ) {
			return false;
		}

		$payload = self::build_generation_payload( $options );
		$ok      = self::activate_generation( $payload );
		self::consume_unlock_pending( $options );
		return $ok;
	}

	/**
	 * Resolve firewall options from a sync callback argument list.
	 *
	 * WordPress passes the updated value as argument two for every
	 * update_option_* hook. Only wf_sn_cf contains firewall settings; the
	 * banned-IP and cloud-IP hooks must reload wf_sn_cf instead.
	 *
	 * @param array $args Sync callback arguments.
	 * @return array|null
	 */
	private static function resolve_sync_options( $args ) {
		if ( isset( $args[2] ) && 'wf_sn_cf' === $args[2] ) {
			return isset( $args[1] ) && is_array( $args[1] ) ? $args[1] : null;
		}
		if ( 1 === count( $args ) && isset( $args[0] ) && is_array( $args[0] ) ) {
			return $args[0];
		}
		return null;
	}

	/**
	 * Hook-friendly sync after settings save (no args).
	 *
	 * @return void
	 */
	public static function sync_all_void() {
		self::sync_all();
	}

	/**
	 * Persist unlock-URL IP into WP whitelist if early WAF wrote a flag.
	 *
	 * @param array|null $options Current options.
	 * @return void
	 */
	public static function consume_unlock_pending( $options = null ) {
		$flag = trailingslashit( self::get_config_dir() ) . 'unlock-pending.php';
		if ( ! is_readable( $flag ) ) {
			// Legacy JSON flag support during migration.
			$legacy = trailingslashit( self::get_config_dir() ) . 'unlock-pending.json';
			$legacy_uploads = '';
			$upload = wp_upload_dir( null, false );
			if ( ! empty( $upload['basedir'] ) ) {
				$legacy_uploads = trailingslashit( $upload['basedir'] ) . 'security-ninja/waf/unlock-pending.json';
			}
			foreach ( array( $legacy, $legacy_uploads ) as $candidate ) {
				if ( $candidate && is_readable( $candidate ) ) {
					$raw = json_decode( (string) file_get_contents( $candidate ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
					@unlink( $candidate ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
					if ( is_array( $raw ) && ! empty( $raw['ip'] ) && filter_var( $raw['ip'], FILTER_VALIDATE_IP ) && class_exists( __NAMESPACE__ . '\\wf_sn_cf' ) ) {
						wf_sn_cf::add_ip_to_whitelist( $raw['ip'] );
					}
				}
			}
			return;
		}

		$raw = include $flag;
		@unlink( $flag ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
		if ( ! is_array( $raw ) || empty( $raw['ip'] ) || ! filter_var( $raw['ip'], FILTER_VALIDATE_IP ) ) {
			return;
		}
		if ( class_exists( __NAMESPACE__ . '\\wf_sn_cf' ) ) {
			wf_sn_cf::add_ip_to_whitelist( $raw['ip'] );
		}
	}

	/**
	 * Set admin HMAC cookie when a manage_options user is logged in.
	 *
	 * @return void
	 */
	public static function maybe_set_admin_cookie() {
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( headers_sent() ) {
			return;
		}
		$key = get_option( 'wf_sn_cf_waf_cookie_key', '' );
		if ( ! is_string( $key ) || '' === $key ) {
			return;
		}
		$uid    = (string) get_current_user_id();
		$exp    = (string) ( time() + WEEK_IN_SECONDS );
		$sig    = hash_hmac( 'sha256', $uid . '|' . $exp, $key );
		$value  = $uid . '|' . $exp . '|' . $sig;
		$secure = is_ssl();
		setcookie(
			'secnin_waf_admin',
			$value,
			array(
				'expires'  => (int) $exp,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}
}
