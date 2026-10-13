<?php
/**
 * Temporary ban clock: store and compare UTC Unix timestamps.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Ban_Clock
 */
class Secnin_Waf_Ban_Clock {

	const SCHEMA_OPTION = 'wf_sn_banned_ips_schema';
	const SCHEMA_UTC    = 2;

	/**
	 * Current UTC unix timestamp for ban storage/comparison.
	 *
	 * @return int
	 */
	public static function now() {
		return time();
	}

	/**
	 * Expiry timestamp for a duration in minutes.
	 *
	 * @param int $minutes Minutes.
	 * @return int
	 */
	public static function expiry_from_minutes( $minutes ) {
		return self::now() + ( max( 0, (int) $minutes ) * 60 );
	}

	/**
	 * Whether schema is already UTC.
	 *
	 * @return bool
	 */
	public static function is_migrated() {
		return (int) get_option( self::SCHEMA_OPTION, 1 ) >= self::SCHEMA_UTC;
	}

	/**
	 * Migrate pseudo-local expiries to UTC while preserving remaining duration.
	 *
	 * Idempotent. Already-expired entries stay expired (expiry <= now).
	 *
	 * @return array Migrated ban map.
	 */
	public static function maybe_migrate() {
		$bans = get_option( 'wf_sn_banned_ips', array() );
		if ( ! is_array( $bans ) ) {
			$bans = array();
		}

		if ( self::is_migrated() ) {
			return $bans;
		}

		$old_now = function_exists( 'current_time' ) ? (int) current_time( 'timestamp' ) : time();
		$new_now = self::now();
		$migrated = array();

		foreach ( $bans as $ip => $expiry ) {
			$expiry = (int) $expiry;
			$remaining = $expiry - $old_now;
			if ( $remaining <= 0 ) {
				// Preserve as already expired relative to new clock.
				$migrated[ $ip ] = $new_now - 1;
			} else {
				$migrated[ $ip ] = $new_now + $remaining;
			}
		}

		update_option( 'wf_sn_banned_ips', $migrated, false );
		update_option( self::SCHEMA_OPTION, self::SCHEMA_UTC, false );
		return $migrated;
	}

	/**
	 * Whether an expiry is still active.
	 *
	 * @param int $expiry Expiry unix UTC.
	 * @return bool
	 */
	public static function is_active( $expiry ) {
		return (int) $expiry > self::now();
	}
}
