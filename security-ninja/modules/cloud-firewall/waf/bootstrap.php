<?php
/**
 * Early WAF bootstrap (auto_prepend_file target via root proxy or runtime copy).
 *
 * No WordPress, Freemius, or Composer. Fail-open always.
 * Capability flags tell WordPress which checks completed successfully.
 *
 * @package Security_Ninja
 */

if ( defined( 'SECNIN_WAF_RUN_COMPLETE' ) ) {
	return;
}
define( 'SECNIN_WAF_RUN_COMPLETE', true );
define( 'SECNIN_WAF_BOOTSTRAP', true );
define( 'SECNIN_WAF_ATTEMPTED', true );
// Legacy alias: means prepend bootstrap ran, NOT that all checks completed.
define( 'SECNIN_WAF_AUTO_PREPEND', true );

$GLOBALS['SECNIN_WAF_CAPABILITIES'] = array();
$GLOBALS['SECNIN_WAF_PROBE_TOKEN']  = '';

if ( ! empty( $_GET['secnin_waf_probe'] ) && is_string( $_GET['secnin_waf_probe'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$GLOBALS['SECNIN_WAF_PROBE_TOKEN'] = rawurldecode( (string) $_GET['secnin_waf_probe'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
}

/**
 * Emit probe response headers when requested.
 *
 * @param string $token Probe token.
 * @param string $key   HMAC key (hex or raw string).
 * @param bool   $engine_complete Whether engine finished.
 * @return void
 */
$secnin_waf_emit_probe = static function ( $token, $key, $engine_complete = false ) {
	if ( '' === $token || '' === $key || headers_sent() ) {
		return;
	}
	$sig = hash_hmac( 'sha256', $token, $key );
	header( 'X-Secnin-Waf: ' . $sig );
	if ( $engine_complete ) {
		header( 'X-Secnin-Waf-Engine: complete' );
	} else {
		header( 'X-Secnin-Waf-Engine: incomplete' );
	}
};

$sapi = PHP_SAPI;
$force_web = (bool) getenv( 'SECNIN_WAF_FORCE_WEB' );
if ( ! $force_web && ( 'cli' === $sapi || 'phpdbg' === $sapi ) ) {
	return;
}

try {
	$waf_dir = dirname( __FILE__ );
	$runner_file = $waf_dir . '/class-secnin-waf-runner.php';
	if ( ! is_readable( $runner_file ) ) {
		return;
	}

	$config_file = '';
	$pointer     = $waf_dir . '/active-config.php';
	if ( is_readable( $pointer ) ) {
		$loaded = include $pointer;
		if ( is_string( $loaded ) && is_readable( $loaded ) ) {
			$config_file = $loaded;
		}
	}

	if ( '' === $config_file ) {
		// Fallback: sibling config/active.php when bootstrap lives in runtime/.
		$candidate = dirname( $waf_dir ) . '/config/active.php';
		if ( is_readable( $candidate ) ) {
			$loaded = include $candidate;
			if ( is_string( $loaded ) && is_readable( $loaded ) ) {
				$config_file = $loaded;
			}
		}
	}

	$key_path = dirname( $waf_dir ) . '/runtime/integrity.key';
	if ( ! is_readable( $key_path ) ) {
		$key_path = $waf_dir . '/integrity.key';
	}
	$key_hex = '';
	if ( is_readable( $key_path ) ) {
		$key_hex = trim( (string) file_get_contents( $key_path ) );
		if ( 64 !== strlen( $key_hex ) || ! ctype_xdigit( $key_hex ) ) {
			$key_hex = '';
		}
	}

	if ( '' === $config_file ) {
		if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) && '' !== $key_hex ) {
			$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, false );
		}
		return;
	}

	$payload = include $config_file;
	if ( ! is_array( $payload ) ) {
		if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) && '' !== $key_hex ) {
			$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, false );
		}
		return;
	}

	if ( '' === $key_hex ) {
		return;
	}

	$copy = $payload;
	unset( $copy['checksum'] );
	$json     = json_encode( $copy );
	$expected = hash_hmac( 'sha256', (string) $json, $key_hex );
	if ( empty( $payload['checksum'] ) || ! hash_equals( $expected, (string) $payload['checksum'] ) ) {
		if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) ) {
			$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, false );
		}
		return;
	}
	if ( empty( $payload['schema'] ) || (int) $payload['schema'] !== 2 ) {
		if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) ) {
			$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, false );
		}
		return;
	}

	if ( ! defined( 'SECNIN_WAF_CONFIG_VALID' ) ) {
		define( 'SECNIN_WAF_CONFIG_VALID', true );
	}

	require_once $runner_file;
	if ( ! class_exists( 'Secnin_Waf_Runner', false ) ) {
		if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) ) {
			$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, false );
		}
		return;
	}

	$runner = new Secnin_Waf_Runner( $payload );
	$runner->run();

	if ( ! defined( 'SECNIN_WAF_ENGINE_COMPLETE' ) ) {
		define( 'SECNIN_WAF_ENGINE_COMPLETE', true );
	}

	if ( ! empty( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'] ) ) {
		$secnin_waf_emit_probe( $GLOBALS['SECNIN_WAF_PROBE_TOKEN'], $key_hex, true );
	}
} catch ( Exception $e ) {
	return;
} catch ( Throwable $e ) {
	return;
}
