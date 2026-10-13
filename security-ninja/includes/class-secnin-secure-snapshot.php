<?php
/**
 * Authenticated encrypted file snapshots (AES-256-GCM).
 *
 * Free-shipping. Encryption key is stored separately from ciphertext.
 * Used by Early Firewall recovery metadata and Auto Fixer backups.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Secure_Snapshot
 */
class Secnin_Secure_Snapshot {

	const FORMAT_VERSION = 2;
	const OPTION_KEY     = 'wf_sn_snapshot_key_v2';
	const CIPHER         = 'aes-256-gcm';

	/**
	 * Create an encrypted snapshot envelope of exact file bytes.
	 *
	 * @param string $source_path Absolute path to snapshot.
	 * @param string $label       Logical label (e.g. htaccess_pre_install).
	 * @param array  $extra_meta  Extra metadata (not encrypted).
	 * @return array{ok:bool,envelope?:array,error?:string}
	 */
	public static function create_from_file( $source_path, $label = '', $extra_meta = array() ) {
		$read = Secnin_Fs_Atomic::read_file( $source_path );
		if ( empty( $read['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => isset( $read['error'] ) ? $read['error'] : 'read_failed',
			);
		}
		return self::create_from_bytes( $read['contents'], $label, array_merge(
			array(
				'source_path' => (string) $source_path,
				'source_hash' => $read['hash'],
				'source_meta' => Secnin_Fs_Atomic::file_meta( $source_path ),
			),
			is_array( $extra_meta ) ? $extra_meta : array()
		) );
	}

	/**
	 * Create envelope from raw bytes.
	 *
	 * @param string $bytes Raw file bytes.
	 * @param string $label Label.
	 * @param array  $meta  Public metadata.
	 * @return array{ok:bool,envelope?:array,error?:string}
	 */
	public static function create_from_bytes( $bytes, $label = '', $meta = array() ) {
		$key = self::get_key_binary();
		if ( false === $key ) {
			return array(
				'ok'    => false,
				'error' => 'key_unavailable',
			);
		}

		$iv = self::random_bytes( 12 );
		if ( false === $iv ) {
			return array(
				'ok'    => false,
				'error' => 'iv_failed',
			);
		}

		$tag        = '';
		$ciphertext = openssl_encrypt( (string) $bytes, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16 );
		if ( false === $ciphertext || 16 !== strlen( $tag ) ) {
			return array(
				'ok'    => false,
				'error' => 'encrypt_failed',
			);
		}

		$envelope = array(
			'v'     => self::FORMAT_VERSION,
			'alg'   => self::CIPHER,
			'label' => (string) $label,
			'ts'    => time(),
			'iv'    => base64_encode( $iv ),
			'tag'   => base64_encode( $tag ),
			'ct'    => base64_encode( $ciphertext ),
			'h'     => hash( 'sha256', (string) $bytes ),
			'meta'  => is_array( $meta ) ? $meta : array(),
		);

		return array(
			'ok'       => true,
			'envelope' => $envelope,
		);
	}

	/**
	 * Decrypt an envelope to raw bytes.
	 *
	 * @param array $envelope Envelope.
	 * @return array{ok:bool,bytes?:string,error?:string}
	 */
	public static function decrypt( $envelope ) {
		if ( ! is_array( $envelope ) || empty( $envelope['v'] ) || (int) $envelope['v'] !== self::FORMAT_VERSION ) {
			return array(
				'ok'    => false,
				'error' => 'unsupported_version',
			);
		}
		if ( empty( $envelope['iv'] ) || empty( $envelope['tag'] ) || empty( $envelope['ct'] ) || empty( $envelope['h'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'malformed',
			);
		}

		$key = self::get_key_binary();
		if ( false === $key ) {
			return array(
				'ok'    => false,
				'error' => 'key_unavailable',
			);
		}

		$iv  = base64_decode( (string) $envelope['iv'], true );
		$tag = base64_decode( (string) $envelope['tag'], true );
		$ct  = base64_decode( (string) $envelope['ct'], true );
		if ( false === $iv || false === $tag || false === $ct || 12 !== strlen( $iv ) || 16 !== strlen( $tag ) ) {
			return array(
				'ok'    => false,
				'error' => 'decode_failed',
			);
		}

		$plain = openssl_decrypt( $ct, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $plain ) {
			return array(
				'ok'    => false,
				'error' => 'decrypt_failed',
			);
		}

		if ( ! hash_equals( (string) $envelope['h'], hash( 'sha256', $plain ) ) ) {
			return array(
				'ok'    => false,
				'error' => 'hash_mismatch',
			);
		}

		return array(
			'ok'    => true,
			'bytes' => $plain,
		);
	}

	/**
	 * Persist envelope as JSON (Auto Fixer backups). Never PHP.
	 *
	 * @param string $path     Destination path.
	 * @param array  $envelope Envelope.
	 * @return true|\WP_Error|array
	 */
	public static function write_envelope_json( $path, $envelope ) {
		if ( ! is_array( $envelope ) ) {
			return Secnin_Fs_Atomic::is_ok( false ) ? false : array(
				'ok'      => false,
				'code'    => 'invalid_envelope',
				'message' => 'Invalid envelope.',
			);
		}
		if ( function_exists( 'wp_json_encode' ) ) {
			$json = wp_json_encode( $envelope );
		} else {
			$json = json_encode( $envelope ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		}
		if ( ! is_string( $json ) || '' === $json ) {
			return Secnin_Fs_Atomic::is_ok( false ) ? false : array(
				'ok'      => false,
				'code'    => 'encode_failed',
				'message' => 'JSON encode failed.',
			);
		}
		return Secnin_Fs_Atomic::write_file( $path, $json, 0600 );
	}

	/**
	 * Load envelope from a JSON file. Never includes/executes the path.
	 *
	 * @param string $path Path.
	 * @return array{ok:bool,envelope?:array,error?:string}
	 */
	public static function load_envelope_json( $path ) {
		$path = (string) $path;
		if ( '' === $path || ! is_readable( $path ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_readable',
			);
		}
		$raw = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $raw || '' === $raw ) {
			return array(
				'ok'    => false,
				'error' => 'read_failed',
			);
		}
		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['v'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_payload',
			);
		}
		return array(
			'ok'       => true,
			'envelope' => $decoded,
		);
	}

	/**
	 * Persist envelope as guarded PHP file (cannot be served as plaintext JSON).
	 *
	 * @param string $path     Destination .php path.
	 * @param array  $envelope Envelope.
	 * @return true|\WP_Error|array
	 */
	public static function write_guarded_php( $path, $envelope ) {
		if ( ! is_array( $envelope ) ) {
			return Secnin_Fs_Atomic::is_ok( false ) ? false : array(
				'ok'      => false,
				'code'    => 'invalid_envelope',
				'message' => 'Invalid envelope.',
			);
		}
		$export  = var_export( $envelope, true );
		$content = "<?php\n// Security Ninja guarded snapshot. Do not edit.\nif ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) { exit; }\nreturn " . $export . ";\n";
		return Secnin_Fs_Atomic::write_file( $path, $content, 0600 );
	}

	/**
	 * Whether a file is an inert Auto Fixer v2 guarded snapshot under sn-backups.
	 *
	 * Reads bytes and tokenizes only. Never includes/executes the file. A matching
	 * filename alone is never enough.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	public static function is_inert_guarded_snapshot( $path ) {
		$path = (string) $path;
		if ( '' === $path || ! is_file( $path ) || ! is_readable( $path ) ) {
			return false;
		}

		if ( ! preg_match( '/\.wfbkp\.php$/i', basename( $path ) ) ) {
			return false;
		}

		if ( ! class_exists( __NAMESPACE__ . '\\Secnin_Af_Backup', false ) ) {
			return false;
		}

		$backup_dir = Secnin_Af_Backup::backup_dir();
		$real_dir   = realpath( rtrim( (string) $backup_dir, '/\\' ) );
		$real_file  = realpath( $path );
		if ( false === $real_dir || false === $real_file ) {
			return false;
		}

		$real_dir  = rtrim( str_replace( '\\', '/', $real_dir ), '/' ) . '/';
		$real_file = str_replace( '\\', '/', $real_file );
		if ( 0 !== strpos( $real_file, $real_dir ) ) {
			return false;
		}

		$size = filesize( $path );
		if ( false === $size || $size < 1 || $size > 2097152 ) {
			return false;
		}

		$contents = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( ! is_string( $contents ) || '' === $contents ) {
			return false;
		}

		$header = "<?php\n// Security Ninja guarded snapshot. Do not edit.\n";
		if ( 0 !== strpos( $contents, $header ) ) {
			return false;
		}

		$tokens = @token_get_all( $contents ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $tokens ) || empty( $tokens ) ) {
			return false;
		}

		$allowed_strings = array(
			'defined' => true,
			'true'    => true,
			'false'   => true,
			'null'    => true,
		);
		$allowed_chars   = array(
			'(' => true,
			')' => true,
			'{' => true,
			'}' => true,
			';' => true,
			',' => true,
			'!' => true,
		);
		$allowed_types   = array(
			T_OPEN_TAG                 => true,
			T_COMMENT                  => true,
			T_WHITESPACE               => true,
			T_IF                       => true,
			T_BOOLEAN_AND              => true,
			T_STRING                   => true,
			T_CONSTANT_ENCAPSED_STRING => true,
			T_EXIT                     => true,
			T_RETURN                   => true,
			T_ARRAY                    => true,
			T_DOUBLE_ARROW             => true,
			T_LNUMBER                  => true,
			T_DNUMBER                  => true,
		);

		$open_tags     = 0;
		$saw_return    = false;
		$comment_count = 0;
		$required_keys = array(
			'v'   => false,
			'alg' => false,
			'iv'  => false,
			'tag' => false,
			'ct'  => false,
			'h'   => false,
		);
		$has_v2        = false;
		$has_alg       = false;
		$semicolons    = array();
		$token_count   = count( $tokens );

		for ( $i = 0; $i < $token_count; $i++ ) {
			$token = $tokens[ $i ];

			if ( ! is_array( $token ) ) {
				if ( ! isset( $allowed_chars[ $token ] ) ) {
					return false;
				}
				if ( ';' === $token ) {
					$semicolons[] = $i;
				}
				continue;
			}

			$type  = $token[0];
			$value = $token[1];

			if ( ! isset( $allowed_types[ $type ] ) ) {
				return false;
			}

			if ( T_OPEN_TAG === $type ) {
				++$open_tags;
				if ( $open_tags > 1 || 0 !== $i ) {
					return false;
				}
				continue;
			}

			if ( T_STRING === $type ) {
				$lower = strtolower( $value );
				if ( ! isset( $allowed_strings[ $lower ] ) ) {
					return false;
				}
			}

			if ( T_COMMENT === $type ) {
				++$comment_count;
				if ( 1 !== $comment_count || '// Security Ninja guarded snapshot. Do not edit.' !== trim( $value ) ) {
					return false;
				}
			}

			if ( T_RETURN === $type ) {
				$saw_return = true;
			}

			if ( T_CONSTANT_ENCAPSED_STRING === $type && $saw_return ) {
				$key = self::unquote_php_string( $value );
				if ( isset( $required_keys[ $key ] ) ) {
					$j = $i + 1;
					while ( $j < $token_count && is_array( $tokens[ $j ] ) && T_WHITESPACE === $tokens[ $j ][0] ) {
						++$j;
					}
					if ( $j < $token_count && is_array( $tokens[ $j ] ) && T_DOUBLE_ARROW === $tokens[ $j ][0] ) {
						$required_keys[ $key ] = true;
						++$j;
						while ( $j < $token_count && is_array( $tokens[ $j ] ) && T_WHITESPACE === $tokens[ $j ][0] ) {
							++$j;
						}
						if ( $j < $token_count && is_array( $tokens[ $j ] ) ) {
							if ( 'v' === $key && T_LNUMBER === $tokens[ $j ][0] && '2' === $tokens[ $j ][1] ) {
								$has_v2 = true;
							}
							if ( 'alg' === $key && T_CONSTANT_ENCAPSED_STRING === $tokens[ $j ][0]
								&& self::CIPHER === self::unquote_php_string( $tokens[ $j ][1] ) ) {
								$has_alg = true;
							}
						}
					}
				}
			}
		}

		// Guard uses `exit;` and the payload ends with `return ...;` — exactly two semicolons.
		if ( 2 !== count( $semicolons ) ) {
			return false;
		}
		$final_semi = $semicolons[1];
		for ( $i = $final_semi + 1; $i < $token_count; $i++ ) {
			$token = $tokens[ $i ];
			if ( ! is_array( $token ) || T_WHITESPACE !== $token[0] ) {
				return false;
			}
		}

		if ( 1 !== $open_tags || 1 !== $comment_count || ! $saw_return || ! $has_v2 || ! $has_alg ) {
			return false;
		}

		foreach ( $required_keys as $present ) {
			if ( ! $present ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Strip quotes from a T_CONSTANT_ENCAPSED_STRING token value.
	 *
	 * @param string $token_value Token text including quotes.
	 * @return string
	 */
	private static function unquote_php_string( $token_value ) {
		$token_value = (string) $token_value;
		if ( strlen( $token_value ) >= 2 ) {
			$q = $token_value[0];
			if ( ( '"' === $q || "'" === $q ) && $q === substr( $token_value, -1 ) ) {
				return stripcslashes( substr( $token_value, 1, -1 ) );
			}
		}
		return $token_value;
	}

	/**
	 * Load guarded PHP envelope.
	 *
	 * @param string $path Path.
	 * @return array{ok:bool,envelope?:array,error?:string}
	 */
	public static function load_guarded_php( $path ) {
		$path = (string) $path;
		if ( '' === $path || ! is_readable( $path ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_readable',
			);
		}
		$loaded = include $path;
		if ( ! is_array( $loaded ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_payload',
			);
		}
		return array(
			'ok'       => true,
			'envelope' => $loaded,
		);
	}

	/**
	 * Get or create 32-byte key (hex stored in option when WP available).
	 *
	 * @return string|false Binary key.
	 */
	public static function get_key_binary() {
		if ( function_exists( 'get_option' ) && function_exists( 'update_option' ) ) {
			$hex = get_option( self::OPTION_KEY, '' );
			if ( ! is_string( $hex ) || 64 !== strlen( $hex ) || ! ctype_xdigit( $hex ) ) {
				$raw = self::random_bytes( 32 );
				if ( false === $raw ) {
					return false;
				}
				$hex = bin2hex( $raw );
				update_option( self::OPTION_KEY, $hex, false );
			}
			$bin = @hex2bin( $hex ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return ( false !== $bin && 32 === strlen( $bin ) ) ? $bin : false;
		}

		// Standalone test / early runtime: derive from optional constant.
		if ( defined( 'SECNIN_SNAPSHOT_TEST_KEY' ) && is_string( SECNIN_SNAPSHOT_TEST_KEY ) && 64 === strlen( SECNIN_SNAPSHOT_TEST_KEY ) ) {
			$bin = @hex2bin( SECNIN_SNAPSHOT_TEST_KEY ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return ( false !== $bin && 32 === strlen( $bin ) ) ? $bin : false;
		}

		return false;
	}

	/**
	 * Cryptographically secure random bytes.
	 *
	 * @param int $length Length.
	 * @return string|false
	 */
	private static function random_bytes( $length ) {
		$length = (int) $length;
		try {
			return random_bytes( $length );
		} catch ( \Exception $e ) {
			if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
				$strong = false;
				$bytes  = openssl_random_pseudo_bytes( $length, $strong );
				if ( false !== $bytes && $strong && strlen( $bytes ) === $length ) {
					return $bytes;
				}
			}
			return false;
		}
	}
}
