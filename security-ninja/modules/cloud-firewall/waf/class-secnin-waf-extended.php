<?php
/**
 * Early Firewall site-local option (not importable / not MainWP).
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Extended
 */
class Secnin_Waf_Extended {

	const OPTION_KEY = 'wf_sn_cf_extended';

	/**
	 * Default option values.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'mode'              => 'legacy',
			'status'            => 'off',
			'last_verify'       => 0,
			'last_rollback'     => '',
			'prepend_path'      => '',
			'chained_prepend'   => '',
			'server_profile'    => '',
			'install_error'     => '',
			'install_hint'      => '',
			'verify_fails'      => 0,
			'runtime_path'      => '',
			'config_generation' => 0,
			'bundle_version'    => '',
			'capabilities'      => array(),
		);
	}

	/**
	 * Allowed statuses (state machine).
	 *
	 * @return string[]
	 */
	public static function allowed_statuses() {
		if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
			return Secnin_Waf_Lifecycle::allowed_statuses();
		}
		return array( 'off', 'probing', 'pending', 'partial', 'active', 'removal_pending', 'failed_safe', 'failed' );
	}

	/**
	 * Get extended option (sanitized).
	 *
	 * @return array
	 */
	public static function get() {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$out = array_merge( self::defaults(), $raw );
		$out['mode'] = ( 'extended' === $out['mode'] ) ? 'extended' : 'legacy';
		$allowed     = self::allowed_statuses();
		if ( ! in_array( $out['status'], $allowed, true ) ) {
			$out['status'] = 'off';
		}
		if ( ! is_array( $out['capabilities'] ) ) {
			$out['capabilities'] = array();
		}
		$out['config_generation'] = (int) $out['config_generation'];
		return $out;
	}

	/**
	 * Update extended option.
	 *
	 * @param array $data Partial data.
	 * @return array Updated full option.
	 */
	public static function update( $data ) {
		$current = self::get();
		if ( ! is_array( $data ) ) {
			$data = array();
		}
		$merged         = array_merge( $current, $data );
		$merged['mode'] = ( isset( $merged['mode'] ) && 'extended' === $merged['mode'] ) ? 'extended' : 'legacy';
		$allowed        = self::allowed_statuses();
		if ( ! isset( $merged['status'] ) || ! in_array( $merged['status'], $allowed, true ) ) {
			$merged['status'] = 'off';
		}
		if ( ! isset( $merged['capabilities'] ) || ! is_array( $merged['capabilities'] ) ) {
			$merged['capabilities'] = array();
		}
		$merged['config_generation'] = isset( $merged['config_generation'] ) ? (int) $merged['config_generation'] : 0;
		update_option( self::OPTION_KEY, $merged, false );
		return $merged;
	}

	/**
	 * Whether Extended is verified and active.
	 *
	 * @return bool
	 */
	public static function is_active() {
		$opt = self::get();
		return ( 'extended' === $opt['mode'] && 'active' === $opt['status'] );
	}

	/**
	 * Whether Early Firewall is installed in any non-off state (pending/active/removal).
	 *
	 * @return bool
	 */
	public static function is_installed() {
		$opt = self::get();
		if ( 'extended' !== $opt['mode'] ) {
			return false;
		}
		return in_array( $opt['status'], array( 'probing', 'pending', 'partial', 'active', 'removal_pending', 'failed_safe' ), true );
	}

	/**
	 * Whether the early WAF bootstrap was attempted on this request.
	 *
	 * Do not use this alone to skip legacy checks.
	 *
	 * @return bool
	 */
	public static function early_waf_attempted() {
		return defined( 'SECNIN_WAF_ATTEMPTED' ) && SECNIN_WAF_ATTEMPTED;
	}

	/**
	 * Whether early WAF completed a full engine pass with valid config.
	 *
	 * @return bool
	 */
	public static function early_waf_engine_complete() {
		return defined( 'SECNIN_WAF_ENGINE_COMPLETE' ) && SECNIN_WAF_ENGINE_COMPLETE;
	}

	/**
	 * Whether a named capability completed in early mode this request.
	 *
	 * @param string $capability Capability name.
	 * @return bool
	 */
	public static function early_capability_complete( $capability ) {
		if ( empty( $GLOBALS['SECNIN_WAF_CAPABILITIES'] ) || ! is_array( $GLOBALS['SECNIN_WAF_CAPABILITIES'] ) ) {
			return false;
		}
		return ! empty( $GLOBALS['SECNIN_WAF_CAPABILITIES'][ (string) $capability ] );
	}

	/**
	 * Legacy helper: early WAF ran (attempted). Prefer capability checks.
	 *
	 * @return bool
	 */
	public static function early_waf_ran() {
		if ( defined( 'SECNIN_WAF_ENGINE_COMPLETE' ) && SECNIN_WAF_ENGINE_COMPLETE ) {
			return true;
		}
		return defined( 'SECNIN_WAF_AUTO_PREPEND' ) && SECNIN_WAF_AUTO_PREPEND;
	}
}
