<?php
/**
 * Deterministic security fact snapshot for comparisons and AI reports.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin;

use function WPSecurityNinja\Plugin\secnin_fs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Security_Snapshot
 */
class Wf_Sn_Security_Snapshot {

	const CACHE_KEY = 'wf_sn_security_snapshot_current';

	/**
	 * Build a fresh snapshot from live plugin data.
	 *
	 * @return array<string, mixed>
	 */
	public static function build() {
		$scores = array(
			'score'   => 0,
			'good'    => 0,
			'warning' => 0,
			'bad'     => 0,
		);
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
			$scores = Wf_Sn::return_test_scores();
		}

		$failed_ids   = array();
		$warning_ids  = array();
		$test_results = self::get_test_rows();
		foreach ( $test_results as $testid => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$status = isset( $row['status'] ) ? (int) $row['status'] : 10;
			$tid    = sanitize_key( (string) $testid );
			if ( 0 === $status ) {
				$failed_ids[] = $tid;
			} elseif ( 10 !== $status ) {
				$warning_ids[] = $tid;
			}
		}

		$vuln_count = 0;
		$vuln_slugs = array();
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Vu' ) ) {
			$scan = Wf_Sn_Vu::get_scan_summary();
			if ( ! empty( $scan['has_vulnerabilities'] ) && ! empty( $scan['vulnerabilities'] ) && is_array( $scan['vulnerabilities'] ) ) {
				foreach ( array( 'plugins', 'themes', 'wordpress' ) as $type ) {
					if ( empty( $scan['vulnerabilities'][ $type ] ) || ! is_array( $scan['vulnerabilities'][ $type ] ) ) {
						continue;
					}
					foreach ( $scan['vulnerabilities'][ $type ] as $slug => $row ) {
						$vuln_slugs[] = sanitize_key( is_string( $slug ) ? $slug : '' );
						++$vuln_count;
					}
				}
			}
		}

		if ( ! class_exists( 'WPSecurityNinja\\Plugin\\Wf_Sn_Cs_Utils' ) ) {
			require_once WF_SN_PLUGIN_DIR . 'modules/core-scanner/class-wf-sn-cs-utils.php';
		}
		$cs = \WPSecurityNinja\Plugin\Wf_Sn_Cs_Utils::get_scan_results( array() );
		if ( ! is_array( $cs ) ) {
			$cs = array();
		}
		$core_issues = 0;
		foreach ( array( 'changed_bad', 'missing_bad', 'unknown_bad' ) as $key ) {
			if ( ! empty( $cs[ $key ] ) && is_array( $cs[ $key ] ) ) {
				$core_issues += count( $cs[ $key ] );
			}
		}

		$malware_count = 0;
		$malware_last  = 0;
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ms' ) ) {
			$malware_count = (int) Wf_Sn_Ms::count_suspicious_files();
			$ms_all        = Wf_Sn_Ms::get_results();
			if ( is_array( $ms_all ) && isset( $ms_all['last_run'] ) ) {
				$malware_last = (int) $ms_all['last_run'];
			}
		}

		$flags   = self::get_feature_flags();
		$updates = self::get_update_counts();

		$active_plugins = array();
		if ( function_exists( 'get_option' ) ) {
			$raw = get_option( 'active_plugins', array() );
			if ( is_array( $raw ) ) {
				foreach ( $raw as $plugin_file ) {
					if ( is_string( $plugin_file ) && '' !== $plugin_file ) {
						$active_plugins[] = $plugin_file;
					}
				}
			}
		}
		sort( $active_plugins );

		$tests_last = 0;
		$wf_results = get_option( 'wf_sn_results', array() );
		if ( is_array( $wf_results ) && ! empty( $wf_results['last_run'] ) ) {
			$tests_last = (int) $wf_results['last_run'];
		}

		$vuln_cache_ts = (int) get_option( 'wf_sn_vulnerabilities_cache_timestamp', 0 );

		$snapshot = array(
			'timestamp'              => time(),
			'plugin_version'         => class_exists( __NAMESPACE__ . '\\Utils' ) ? Utils::get_plugin_version() : '',
			'wp_version'             => get_bloginfo( 'version' ),
			'security_score'         => isset( $scores['score'] ) ? (int) $scores['score'] : 0,
			'tests_passed'           => isset( $scores['good'] ) ? (int) $scores['good'] : 0,
			'tests_warning'          => isset( $scores['warning'] ) ? (int) $scores['warning'] : 0,
			'tests_failed'           => isset( $scores['bad'] ) ? (int) $scores['bad'] : 0,
			'failed_test_ids'        => array_values( array_unique( $failed_ids ) ),
			'warning_test_ids'       => array_values( array_unique( $warning_ids ) ),
			'vulnerability_count'    => $vuln_count,
			'vulnerability_slugs'    => array_values( array_unique( array_filter( $vuln_slugs ) ) ),
			'core_scanner_issues'    => $core_issues,
			'core_scanner_last_run'  => isset( $cs['last_run'] ) ? (int) $cs['last_run'] : 0,
			'malware_issues'         => $malware_count,
			'malware_last_run'       => $malware_last,
			'firewall_enabled'       => ! empty( $flags['firewall_enabled'] ),
			'login_protection_enabled' => ! empty( $flags['login_protection_enabled'] ),
			'two_factor_enabled'     => ! empty( $flags['two_factor_enabled'] ),
			'woocommerce_active'     => class_exists( 'WooCommerce' ),
			'update_plugins'         => (int) $updates['plugins'],
			'update_themes'          => (int) $updates['themes'],
			'update_core'            => (int) $updates['core'],
			'update_total'           => (int) $updates['total'],
			'active_plugins'         => $active_plugins,
			'active_plugins_hash'    => md5( wp_json_encode( $active_plugins ) ),
			'tests_last_run'         => $tests_last,
			'vuln_scan_last_run'     => $vuln_cache_ts,
			'events_logger_active'   => class_exists( __NAMESPACE__ . '\\Wf_Sn_El' ) && Wf_Sn_El::is_active(),
		);

		/**
		 * Filter the deterministic security snapshot before storage/display.
		 *
		 * @param array $snapshot Snapshot array.
		 */
		return (array) apply_filters( 'wf_sn_security_snapshot', $snapshot );
	}

	/**
	 * Cached current snapshot (refreshed on scan hooks / cron).
	 *
	 * @param bool $force_refresh Skip cache.
	 * @return array<string, mixed>
	 */
	public static function get_current( $force_refresh = false ) {
		if ( ! $force_refresh ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( is_array( $cached ) && ! empty( $cached['timestamp'] ) ) {
				return $cached;
			}
		}
		$built = self::build();
		set_transient( self::CACHE_KEY, $built, HOUR_IN_SECONDS );
		return $built;
	}

	/**
	 * Invalidate and rebuild cached snapshot.
	 *
	 * @return void
	 */
	public static function refresh_cache() {
		delete_transient( self::CACHE_KEY );
		self::get_current( true );
	}

	/**
	 * Register hooks to refresh snapshot after scans.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		$hooks = array(
			'security_ninja_done_testing',
			'security_ninja_vulnerability_scan_done',
			'security_ninja_core_scanner_done_scanning',
			'security_ninja_malware_scanner_done_scanning',
			'security_ninja_scheduled_scanner_done_cron',
		);
		foreach ( $hooks as $hook ) {
			add_action( $hook, array( __CLASS__, 'refresh_cache' ), 20 );
		}
		add_action( 'wf_sn_refresh_security_snapshot', array( __CLASS__, 'refresh_cache' ) );
		if ( ! wp_next_scheduled( 'wf_sn_refresh_security_snapshot_daily' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'wf_sn_refresh_security_snapshot_daily' );
		}
		add_action( 'wf_sn_refresh_security_snapshot_daily', array( __CLASS__, 'refresh_cache' ) );
	}

	/**
	 * WordPress plugin/theme/core update counts.
	 *
	 * @return array{plugins: int, themes: int, core: int, total: int}
	 */
	public static function get_update_counts() {
		$plugin_updates = function_exists( 'get_plugin_updates' ) ? get_plugin_updates() : array();
		$plugin_count   = is_array( $plugin_updates ) ? count( $plugin_updates ) : 0;

		$theme_count = 0;
		$theme_updates = get_site_transient( 'update_themes' );
		if ( is_object( $theme_updates ) && ! empty( $theme_updates->response ) && is_array( $theme_updates->response ) ) {
			$theme_count = count( $theme_updates->response );
		}

		$core_count = 0;
		if ( function_exists( 'get_core_updates' ) ) {
			$core_updates = get_core_updates();
			if ( is_array( $core_updates ) ) {
				foreach ( $core_updates as $update ) {
					if ( is_object( $update ) && ! empty( $update->response ) && 'upgrade' === $update->response ) {
						++$core_count;
						break;
					}
				}
			}
		}

		$total = $plugin_count + $theme_count + $core_count;

		return array(
			'plugins' => $plugin_count,
			'themes'  => $theme_count,
			'core'    => $core_count,
			'total'   => $total,
		);
	}

	/**
	 * Feature flags aligned with AI payload (firewall, login, 2FA).
	 *
	 * @return array{firewall_enabled: bool, login_protection_enabled: bool, two_factor_enabled: bool}
	 */
	public static function get_feature_flags() {
		$flags    = array(
			'firewall_enabled'         => false,
			'login_protection_enabled' => false,
			'two_factor_enabled'       => false,
		);
		$cf_class = __NAMESPACE__ . '\\Wf_sn_cf';
		if ( class_exists( $cf_class ) ) {
			$cf_class::get_options();
			if ( method_exists( $cf_class, 'is_active' ) ) {
				$flags['firewall_enabled'] = ( (int) $cf_class::is_active() ) === 1;
			}
			$cf = $cf_class::get_options();
			if ( is_array( $cf ) ) {
				$flags['login_protection_enabled'] = ! empty( $cf['protect_login_form'] );
				$flags['two_factor_enabled']       = ! empty( $cf['2fa_enabled'] );
			}
		}
		return $flags;
	}

	/**
	 * Decode snapshot JSON from DB column.
	 *
	 * @param string|null $json Stored JSON.
	 * @return array<string, mixed>|null
	 */
	public static function decode( $json ) {
		if ( ! is_string( $json ) || '' === $json ) {
			return null;
		}
		$decoded = json_decode( $json, true );
		return is_array( $decoded ) ? $decoded : null;
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private static function get_test_rows() {
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
			return array();
		}
		$response = Wf_Sn::get_test_results();
		if ( is_array( $response ) && ! empty( $response['test'] ) && is_array( $response['test'] ) ) {
			return $response['test'];
		}
		$results = get_option( 'wf_sn_results', array() );
		if ( is_array( $results ) && ! empty( $results['test'] ) && is_array( $results['test'] ) ) {
			return $results['test'];
		}
		return array();
	}
}
