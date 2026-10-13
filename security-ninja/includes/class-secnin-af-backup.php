<?php
/**
 * Auto Fixer authenticated file backups (v2 JSON) with legacy restore/migration.
 *
 * Free-shipping helper. Key is never stored beside ciphertext.
 * Backups are .wfbkp JSON data files (not PHP).
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Af_Backup
 */
class Secnin_Af_Backup {

	/**
	 * Relative backup directory under WP_CONTENT_DIR.
	 *
	 * @var string
	 */
	const DIR_NAME = 'sn-backups';

	/**
	 * Absolute backup directory.
	 *
	 * @return string
	 */
	public static function backup_dir() {
		$base = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '';
		return rtrim( (string) $base, '/\\' ) . '/' . self::DIR_NAME . '/';
	}

	/**
	 * Build basename for a backup (without extension).
	 *
	 * @param string $file_path Source path.
	 * @param string $timestamp Timestamp.
	 * @param string $fix      Fix slug.
	 * @return string
	 */
	public static function backup_basename( $file_path, $timestamp, $fix ) {
		$ts   = preg_replace( '/[^0-9]/', '', (string) $timestamp );
		$slug = preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $fix );
		return basename( (string) $file_path ) . '_' . $ts . '_' . $slug;
	}

	/**
	 * Create an authenticated v2 JSON backup (.wfbkp).
	 *
	 * @param string $file_path Path to file.
	 * @param string $timestamp Timestamp.
	 * @param string $fix      Fix slug.
	 * @return array{ok:bool,path?:string,error?:string}
	 */
	public static function backup_file( $file_path, $timestamp, $fix ) {
		$file_path = (string) $file_path;
		if ( '' === $file_path || ! is_readable( $file_path ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_readable',
			);
		}

		$dir = self::backup_dir();
		Secnin_Fs_Atomic::protect_directory( $dir );

		$created = Secnin_Secure_Snapshot::create_from_file(
			$file_path,
			(string) $fix,
			array(
				'fix'      => preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $fix ),
				'timestamp' => preg_replace( '/[^0-9]/', '', (string) $timestamp ),
			)
		);
		if ( empty( $created['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => isset( $created['error'] ) ? $created['error'] : 'encrypt_failed',
			);
		}

		$dest  = $dir . self::backup_basename( $file_path, $timestamp, $fix ) . '.wfbkp';
		$write = Secnin_Secure_Snapshot::write_envelope_json( $dest, $created['envelope'] );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'    => false,
				'error' => 'write_failed',
			);
		}

		return array(
			'ok'   => true,
			'path' => $dest,
		);
	}

	/**
	 * Restore a backup (JSON v2 preferred, then guarded PHP, then legacy v1).
	 *
	 * @param string $file_path Destination path.
	 * @param string $timestamp Timestamp.
	 * @param string $fix      Fix slug.
	 * @return array{ok:bool,error?:string}
	 */
	public static function restore_file( $file_path, $timestamp, $fix ) {
		$file_path = (string) $file_path;
		if ( '' === $file_path || false !== strpos( $file_path, "\0" ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_path',
			);
		}

		// Refuse restoring outside common WordPress roots when constants exist.
		if ( defined( 'ABSPATH' ) && defined( 'WP_CONTENT_DIR' ) ) {
			$real     = realpath( dirname( $file_path ) );
			$ok_roots = array(
				realpath( ABSPATH ),
				realpath( WP_CONTENT_DIR ),
				realpath( dirname( ABSPATH ) ),
			);
			$allowed = false;
			if ( false !== $real ) {
				foreach ( $ok_roots as $root ) {
					if ( false !== $root && 0 === strpos( $real, $root ) ) {
						$allowed = true;
						break;
					}
				}
			}
			if ( ! $allowed && is_dir( dirname( $file_path ) ) ) {
				$parent = realpath( dirname( $file_path ) );
				foreach ( $ok_roots as $root ) {
					if ( false !== $parent && false !== $root && 0 === strpos( $parent, $root ) ) {
						$allowed = true;
						break;
					}
				}
			}
			if ( ! $allowed ) {
				return array(
					'ok'    => false,
					'error' => 'path_not_allowed',
				);
			}
		}

		$dir      = self::backup_dir();
		$base     = self::backup_basename( $file_path, $timestamp, $fix );
		$json_path = $dir . $base . '.wfbkp';
		$php_path  = $dir . $base . '.wfbkp.php';
		$bytes     = false;

		if ( is_readable( $json_path ) ) {
			$loaded = Secnin_Secure_Snapshot::load_envelope_json( $json_path );
			if ( ! empty( $loaded['ok'] ) ) {
				$version = (int) $loaded['envelope']['v'];
				if ( 2 === $version ) {
					$decoded = Secnin_Secure_Snapshot::decrypt( $loaded['envelope'] );
					if ( ! empty( $decoded['ok'] ) ) {
						$bytes = $decoded['bytes'];
					}
				} elseif ( 1 === $version ) {
					$legacy = self::decrypt_legacy_v1( $json_path );
					if ( ! empty( $legacy['ok'] ) ) {
						$bytes = $legacy['bytes'];
						self::migrate_legacy_file( $json_path );
					}
				}
			}
		}

		if ( false === $bytes && is_readable( $php_path ) ) {
			$loaded = Secnin_Secure_Snapshot::load_guarded_php( $php_path );
			if ( ! empty( $loaded['ok'] ) ) {
				$decoded = Secnin_Secure_Snapshot::decrypt( $loaded['envelope'] );
				if ( ! empty( $decoded['ok'] ) ) {
					$bytes = $decoded['bytes'];
					self::migrate_guarded_php_file( $php_path );
				}
			}
		}

		if ( false === $bytes ) {
			return array(
				'ok'    => false,
				'error' => 'backup_not_found',
			);
		}

		$write = Secnin_Fs_Atomic::write_file( $file_path, $bytes, 0 );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'    => false,
				'error' => 'restore_write_failed',
			);
		}

		return array( 'ok' => true );
	}

	/**
	 * Decrypt legacy Auto Fixer v1 .wfbkp (key embedded in JSON).
	 *
	 * @param string $backup_file_path Path to .wfbkp.
	 * @return array{ok:bool,bytes?:string,error?:string}
	 */
	public static function decrypt_legacy_v1( $backup_file_path ) {
		$backup_content = @file_get_contents( $backup_file_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $backup_content ) {
			return array(
				'ok'    => false,
				'error' => 'read_failed',
			);
		}
		$backup_data = json_decode( $backup_content, true );
		if ( ! is_array( $backup_data ) || ! isset( $backup_data['v'], $backup_data['k'], $backup_data['i'], $backup_data['h'], $backup_data['d'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'malformed',
			);
		}
		if ( 1 !== (int) $backup_data['v'] ) {
			return array(
				'ok'    => false,
				'error' => 'unsupported_version',
			);
		}
		$key = @hex2bin( $backup_data['k'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$iv  = base64_decode( $backup_data['i'], true );
		$ct  = base64_decode( $backup_data['d'], true );
		if ( false === $key || false === $iv || false === $ct ) {
			return array(
				'ok'    => false,
				'error' => 'decode_failed',
			);
		}
		$decrypted = openssl_decrypt( $ct, 'AES-256-CBC', $key, 0, $iv );
		if ( false === $decrypted ) {
			return array(
				'ok'    => false,
				'error' => 'decrypt_failed',
			);
		}
		if ( ! hash_equals( (string) $backup_data['h'], substr( md5( $decrypted ), 0, 8 ) ) ) {
			return array(
				'ok'    => false,
				'error' => 'hash_mismatch',
			);
		}
		return array(
			'ok'    => true,
			'bytes' => $decrypted,
		);
	}

	/**
	 * Migrate one legacy v1 JSON backup to authenticated v2 JSON in place.
	 *
	 * @param string $v1_path Path to .wfbkp.
	 * @return array{ok:bool,path?:string,error?:string}
	 */
	public static function migrate_legacy_file( $v1_path ) {
		$v1_path = (string) $v1_path;
		if ( '' === $v1_path || ! preg_match( '/\.wfbkp$/', $v1_path ) || preg_match( '/\.wfbkp\.php$/', $v1_path ) || ! is_readable( $v1_path ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_v1',
			);
		}

		$existing = Secnin_Secure_Snapshot::load_envelope_json( $v1_path );
		if ( ! empty( $existing['ok'] ) && 2 === (int) $existing['envelope']['v'] ) {
			return array(
				'ok'   => true,
				'path' => $v1_path,
			);
		}

		$legacy = self::decrypt_legacy_v1( $v1_path );
		if ( empty( $legacy['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => isset( $legacy['error'] ) ? $legacy['error'] : 'decrypt_failed',
			);
		}

		$created = Secnin_Secure_Snapshot::create_from_bytes( $legacy['bytes'], 'migrated_v1', array( 'migrated_from' => basename( $v1_path ) ) );
		if ( empty( $created['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'reencrypt_failed',
			);
		}

		$tmp = $v1_path . '.migrating';
		$write = Secnin_Secure_Snapshot::write_envelope_json( $tmp, $created['envelope'] );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'write_failed',
			);
		}

		$loaded = Secnin_Secure_Snapshot::load_envelope_json( $tmp );
		if ( empty( $loaded['ok'] ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'verify_load_failed',
			);
		}
		$decoded = Secnin_Secure_Snapshot::decrypt( $loaded['envelope'] );
		if ( empty( $decoded['ok'] ) || ! hash_equals( $legacy['bytes'], $decoded['bytes'] ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'verify_decrypt_failed',
			);
		}

		@unlink( $v1_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
		if ( ! @rename( $tmp, $v1_path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'replace_failed',
			);
		}

		return array(
			'ok'   => true,
			'path' => $v1_path,
		);
	}

	/**
	 * Migrate one 5.304 guarded PHP snapshot to JSON .wfbkp.
	 *
	 * @param string $php_path Path to .wfbkp.php.
	 * @return array{ok:bool,path?:string,error?:string}
	 */
	public static function migrate_guarded_php_file( $php_path ) {
		$php_path = (string) $php_path;
		if ( '' === $php_path || ! preg_match( '/\.wfbkp\.php$/', $php_path ) || ! is_readable( $php_path ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_php',
			);
		}

		$loaded = Secnin_Secure_Snapshot::load_guarded_php( $php_path );
		if ( empty( $loaded['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'load_failed',
			);
		}

		$decoded = Secnin_Secure_Snapshot::decrypt( $loaded['envelope'] );
		if ( empty( $decoded['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'decrypt_failed',
			);
		}

		$json_path = preg_replace( '/\.wfbkp\.php$/', '.wfbkp', $php_path );
		$write     = Secnin_Secure_Snapshot::write_envelope_json( $json_path, $loaded['envelope'] );
		if ( ! Secnin_Fs_Atomic::is_ok( $write ) ) {
			return array(
				'ok'    => false,
				'error' => 'write_failed',
			);
		}

		$verify = Secnin_Secure_Snapshot::load_envelope_json( $json_path );
		if ( empty( $verify['ok'] ) ) {
			@unlink( $json_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'verify_load_failed',
			);
		}
		$verify_dec = Secnin_Secure_Snapshot::decrypt( $verify['envelope'] );
		if ( empty( $verify_dec['ok'] ) || ! hash_equals( $decoded['bytes'], $verify_dec['bytes'] ) ) {
			@unlink( $json_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return array(
				'ok'    => false,
				'error' => 'verify_decrypt_failed',
			);
		}

		@unlink( $php_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink

		return array(
			'ok'   => true,
			'path' => $json_path,
		);
	}

	/**
	 * Migrate guarded PHP snapshots and legacy v1 backups in the backup directory.
	 *
	 * @return int Number migrated.
	 */
	public static function migrate_all_legacy() {
		$dir = self::backup_dir();
		if ( ! is_dir( $dir ) ) {
			return 0;
		}

		$count = 0;

		$php_files = glob( $dir . '*.wfbkp.php' );
		if ( is_array( $php_files ) ) {
			foreach ( $php_files as $file ) {
				$result = self::migrate_guarded_php_file( $file );
				if ( ! empty( $result['ok'] ) ) {
					++$count;
				}
			}
		}

		$json_files = glob( $dir . '*.wfbkp' );
		if ( is_array( $json_files ) ) {
			foreach ( $json_files as $file ) {
				if ( ! is_string( $file ) || preg_match( '/\.wfbkp\.php$/', $file ) ) {
					continue;
				}
				$existing = Secnin_Secure_Snapshot::load_envelope_json( $file );
				if ( ! empty( $existing['ok'] ) && 2 === (int) $existing['envelope']['v'] ) {
					continue;
				}
				$result = self::migrate_legacy_file( $file );
				if ( ! empty( $result['ok'] ) ) {
					++$count;
				}
			}
		}

		return $count;
	}

	/**
	 * Prune oldest owned backup files, keeping newest $keep.
	 *
	 * @param int $keep Number to keep.
	 * @return int Number deleted.
	 */
	public static function cleanup_backups( $keep = 15 ) {
		$keep = max( 1, (int) $keep );
		$dir  = self::backup_dir();
		if ( ! is_dir( $dir ) ) {
			return 0;
		}

		$backup_files = array_merge(
			glob( $dir . '*.wfbkp' ) ? glob( $dir . '*.wfbkp' ) : array(),
			glob( $dir . '*.wfbkp.php' ) ? glob( $dir . '*.wfbkp.php' ) : array()
		);

		// glob('*.wfbkp') can include '*.wfbkp.php' on some systems; unique + filter.
		$backup_files = array_values(
			array_unique(
				array_filter(
					$backup_files,
					static function ( $file ) {
						$base = basename( (string) $file );
						return (bool) preg_match( '/\.wfbkp(\.php)?$/', $base );
					}
				)
			)
		);

		usort(
			$backup_files,
			static function ( $a, $b ) {
				return filemtime( $b ) - filemtime( $a );
			}
		);

		if ( count( $backup_files ) <= $keep ) {
			return 0;
		}

		$deleted = 0;
		foreach ( array_slice( $backup_files, $keep ) as $file_to_delete ) {
			if ( @unlink( $file_to_delete ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
				++$deleted;
			}
		}
		return $deleted;
	}
}
