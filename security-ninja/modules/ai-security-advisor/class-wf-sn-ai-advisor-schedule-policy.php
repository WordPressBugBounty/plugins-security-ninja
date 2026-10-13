<?php
/**
 * AI Security Advisor – schedule and connection policy (FREE + PRO).
 *
 * Pure helpers so tests can pass premium and connection inputs without Freemius.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Schedule_Policy
 */
class Wf_Sn_Ai_Advisor_Schedule_Policy {

	const INTERVAL_MONTHLY = 'monthly';
	const INTERVAL_WEEKLY  = 'weekly';
	const INTERVAL_DAILY   = 'daily';

	const CRON_MONTHLY = 'wf_sn_ai_monthly';

	const STATE_UNAVAILABLE   = 'unavailable';
	const STATE_NO_CONNECTOR  = 'no_connector';
	const STATE_NOT_SELECTED  = 'not_selected';
	const STATE_READY         = 'ready';

	/**
	 * Allowed stored interval slugs for a plan.
	 *
	 * @param bool $is_premium Whether premium code may be used.
	 * @return string[]
	 */
	public static function allowed_intervals( $is_premium ) {
		if ( $is_premium ) {
			return array( self::INTERVAL_MONTHLY, self::INTERVAL_WEEKLY, self::INTERVAL_DAILY );
		}
		return array( self::INTERVAL_MONTHLY );
	}

	/**
	 * Clamp a requested interval to what the plan allows.
	 *
	 * @param string $interval    Requested interval.
	 * @param bool   $is_premium  Whether premium code may be used.
	 * @return string
	 */
	public static function normalize_interval( $interval, $is_premium ) {
		$interval = sanitize_key( (string) $interval );
		$allowed  = self::allowed_intervals( $is_premium );
		if ( in_array( $interval, $allowed, true ) ) {
			return $interval;
		}
		return self::INTERVAL_MONTHLY;
	}

	/**
	 * WordPress cron schedule name for a stored interval.
	 *
	 * @param string $interval Normalized interval slug.
	 * @return string
	 */
	public static function cron_schedule_slug( $interval ) {
		$interval = sanitize_key( (string) $interval );
		if ( self::INTERVAL_MONTHLY === $interval ) {
			return self::CRON_MONTHLY;
		}
		if ( self::INTERVAL_WEEKLY === $interval ) {
			return 'weekly';
		}
		return 'daily';
	}

	/**
	 * Recurring interval in seconds.
	 *
	 * @param string $interval Normalized interval slug.
	 * @return int
	 */
	public static function interval_seconds( $interval ) {
		$interval = sanitize_key( (string) $interval );
		if ( self::INTERVAL_MONTHLY === $interval ) {
			return 30 * DAY_IN_SECONDS;
		}
		if ( self::INTERVAL_WEEKLY === $interval ) {
			return WEEK_IN_SECONDS;
		}
		return DAY_IN_SECONDS;
	}

	/**
	 * Whether a cron event may be registered.
	 *
	 * @param string $connection_state Connection state slug.
	 * @param bool   $enabled          Toggle value.
	 * @return bool
	 */
	public static function can_queue( $connection_state, $enabled ) {
		return (bool) $enabled && self::STATE_READY === (string) $connection_state;
	}

	/**
	 * Resolve connection state from explicit inputs (unit-testable).
	 *
	 * @param bool     $wp_ai_available      WordPress AI client is present.
	 * @param string[] $configured_providers Configured connector ids.
	 * @param string   $selected_connector   Selected connector id.
	 * @return string
	 */
	public static function resolve_connection_state( $wp_ai_available, $configured_providers, $selected_connector ) {
		if ( ! $wp_ai_available ) {
			return self::STATE_UNAVAILABLE;
		}
		if ( ! is_array( $configured_providers ) ) {
			$configured_providers = array();
		}
		$configured_providers = array_values( array_filter( array_map( 'strval', $configured_providers ) ) );
		if ( empty( $configured_providers ) ) {
			return self::STATE_NO_CONNECTOR;
		}
		$selected = sanitize_key( (string) $selected_connector );
		if ( '' === $selected || ! in_array( $selected, $configured_providers, true ) ) {
			return self::STATE_NOT_SELECTED;
		}
		return self::STATE_READY;
	}

	/**
	 * Live connection state from WordPress AI connectors and stored options.
	 *
	 * @return string
	 */
	public static function get_connection_state() {
		$available  = false;
		$configured = array();
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Provider_Wp_Connectors' ) ) {
			$available = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available();
			if ( $available ) {
				$configured = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
			}
		}
		$options  = class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Page' ) ? Wf_Sn_Ai_Advisor_Page::get_options() : get_option( 'wf_sn_ai_advisor', array() );
		$selected = '';
		if ( is_array( $options ) && ! empty( $options['last_connector_provider'] ) ) {
			$selected = sanitize_key( (string) $options['last_connector_provider'] );
		}
		return self::resolve_connection_state( $available, $configured, $selected );
	}

	/**
	 * Human label for a stored interval.
	 *
	 * @param string $interval Interval slug.
	 * @return string
	 */
	public static function interval_label( $interval ) {
		$interval = sanitize_key( (string) $interval );
		if ( self::INTERVAL_WEEKLY === $interval ) {
			return __( 'Weekly', 'security-ninja' );
		}
		if ( self::INTERVAL_DAILY === $interval ) {
			return __( 'Daily', 'security-ninja' );
		}
		return __( 'Monthly', 'security-ninja' );
	}
}
