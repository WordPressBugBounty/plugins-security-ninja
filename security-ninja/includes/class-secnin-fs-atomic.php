<?php
/**
 * Atomic filesystem helpers for Early Firewall and Auto Fixer snapshots.
 *
 * Free-shipping. Safe to call from WordPress or (with care) standalone tests.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Fs_Atomic
 */
class Secnin_Fs_Atomic {

	/**
	 * Write file contents atomically in the same directory.
	 *
	 * @param string $path     Destination path.
	 * @param string $contents File contents.
	 * @param int    $mode     Optional chmod mode (e.g. 0600).
	 * @return true|\WP_Error|array True on success; array with error keys when WP_Error unavailable.
	 */
	public static function write_file( $path, $contents, $mode = 0600 ) {
		$path = (string) $path;
		if ( '' === $path || false !== strpos( $path, "\0" ) ) {
			return self::error( 'invalid_path', 'Invalid destination path.' );
		}

		$dir = dirname( $path );
		if ( ! is_dir( $dir ) ) {
			if ( ! self::mkdir_p( $dir, 0755 ) ) {
				return self::error( 'mkdir_failed', 'Could not create directory: ' . $dir );
			}
		}

		if ( ! is_writable( $dir ) ) {
			return self::error( 'dir_not_writable', 'Directory is not writable: ' . $dir );
		}

		$tmp = $path . '.' . self::uniq_suffix() . '.tmp';
		$fh  = @fopen( $tmp, 'cb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( false === $fh ) {
			return self::error( 'tmp_open_failed', 'Could not open temporary file.' );
		}

		if ( ! flock( $fh, LOCK_EX ) ) {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return self::error( 'lock_failed', 'Could not lock temporary file.' );
		}

		$written = fwrite( $fh, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		if ( false === $written || (string) $written !== (string) strlen( $contents ) ) {
			flock( $fh, LOCK_UN );
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return self::error( 'write_failed', 'Incomplete write to temporary file.' );
		}

		fflush( $fh );
		flock( $fh, LOCK_UN );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

		if ( $mode > 0 ) {
			@chmod( $tmp, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		}

		if ( ! self::rename_replace( $tmp, $path ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return self::error( 'rename_failed', 'Could not atomically replace destination file.' );
		}

		if ( $mode > 0 ) {
			@chmod( $path, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
		}

		clearstatcache( true, $path );
		$verify = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $verify || ! hash_equals( (string) $contents, (string) $verify ) ) {
			return self::error( 'verify_failed', 'Post-write content verification failed.' );
		}

		return true;
	}

	/**
	 * Read file bytes with optional hash return.
	 *
	 * @param string $path Path.
	 * @return array{ok:bool,contents?:string,hash?:string,error?:string}
	 */
	public static function read_file( $path ) {
		$path = (string) $path;
		if ( '' === $path || ! is_readable( $path ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_readable',
			);
		}
		$contents = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $contents ) {
			return array(
				'ok'    => false,
				'error' => 'read_failed',
			);
		}
		return array(
			'ok'       => true,
			'contents' => $contents,
			'hash'     => hash( 'sha256', $contents ),
		);
	}

	/**
	 * SHA-256 of a file, or empty string.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function file_hash( $path ) {
		$path = (string) $path;
		if ( '' === $path || ! is_readable( $path ) ) {
			return '';
		}
		$hash = @hash_file( 'sha256', $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return is_string( $hash ) ? $hash : '';
	}

	/**
	 * File metadata useful for recovery / ownership checks.
	 *
	 * @param string $path Path.
	 * @return array
	 */
	public static function file_meta( $path ) {
		$path = (string) $path;
		$meta = array(
			'path'       => $path,
			'exists'     => false,
			'readable'   => false,
			'writable'   => false,
			'size'       => 0,
			'mtime'      => 0,
			'perms'      => '',
			'hash'       => '',
			'is_file'    => false,
			'is_link'    => false,
		);
		if ( '' === $path || ! file_exists( $path ) ) {
			return $meta;
		}
		$meta['exists']   = true;
		$meta['readable'] = is_readable( $path );
		$meta['writable'] = is_writable( $path );
		$meta['is_file']  = is_file( $path );
		$meta['is_link']  = is_link( $path );
		$stat             = @stat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( is_array( $stat ) ) {
			$meta['size']  = isset( $stat['size'] ) ? (int) $stat['size'] : 0;
			$meta['mtime'] = isset( $stat['mtime'] ) ? (int) $stat['mtime'] : 0;
			$meta['perms'] = isset( $stat['mode'] ) ? substr( sprintf( '%o', $stat['mode'] ), -4 ) : '';
		}
		if ( $meta['readable'] && $meta['is_file'] ) {
			$meta['hash'] = self::file_hash( $path );
		}
		return $meta;
	}

	/**
	 * Recursively create a directory.
	 *
	 * @param string $dir  Directory.
	 * @param int    $mode Mode.
	 * @return bool
	 */
	public static function mkdir_p( $dir, $mode = 0755 ) {
		$dir = (string) $dir;
		if ( '' === $dir || is_dir( $dir ) ) {
			return is_dir( $dir );
		}
		if ( function_exists( 'wp_mkdir_p' ) ) {
			return (bool) wp_mkdir_p( $dir );
		}
		return (bool) @mkdir( $dir, $mode, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
	}

	/**
	 * Write Apache/IIS denial stubs into a directory.
	 *
	 * @param string $dir Directory.
	 * @return bool
	 */
	public static function protect_directory( $dir ) {
		$dir = rtrim( (string) $dir, '/\\' );
		if ( '' === $dir || ! self::mkdir_p( $dir, 0755 ) ) {
			return false;
		}

		$htaccess = "Order Deny,Allow\nDeny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n";
		$web_config = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n  </system.webServer>\n</configuration>\n";
		$index = "<?php\n// Silence is golden.\n";

		$ok = true === self::write_file( $dir . '/.htaccess', $htaccess, 0644 );
		$ok = ( true === self::write_file( $dir . '/web.config', $web_config, 0644 ) ) && $ok;
		$ok = ( true === self::write_file( $dir . '/index.php', $index, 0644 ) ) && $ok;
		return $ok;
	}

	/**
	 * Relative path from directory $from to file $to, with leading separator for __DIR__ concat.
	 *
	 * @param string $from From directory.
	 * @param string $to   To file.
	 * @return string Path relative to $from, using forward slashes, no leading slash (caller prepends separator).
	 */
	public static function relative_path( $from, $to ) {
		$from = str_replace( '\\', '/', rtrim( (string) $from, '/\\' ) );
		$to   = str_replace( '\\', '/', (string) $to );
		$from_parts = array_values( array_filter( explode( '/', $from ), 'strlen' ) );
		$to_parts   = array_values( array_filter( explode( '/', $to ), 'strlen' ) );

		// Preserve leading empty for absolute Unix paths in implode only via parts.
		$from_raw = explode( '/', $from );
		$to_raw   = explode( '/', $to );
		while ( count( $from_raw ) && count( $to_raw ) && $from_raw[0] === $to_raw[0] ) {
			array_shift( $from_raw );
			array_shift( $to_raw );
		}
		$up = count( $from_raw );
		$rel = str_repeat( '../', $up ) . implode( '/', $to_raw );
		// Ensure path used with __DIR__ . '/' . $rel always works: prefer leading '/'.
		if ( '' === $rel ) {
			return '/';
		}
		if ( '/' !== $rel[0] && 0 !== strpos( $rel, '../' ) ) {
			$rel = '/' . $rel;
		} elseif ( 0 === strpos( $rel, '../' ) ) {
			// Keep as-is for climbing; caller should use __DIR__ . '/' . $rel only when not starting with ../
			// For climbing paths, use __DIR__ . '/' . $rel which normalizes.
			$rel = '/' !== $rel[0] ? $rel : ltrim( $rel, '/' );
		}
		return $rel;
	}

	/**
	 * Build a PHP include expression fragment for root proxy.
	 *
	 * Returns a string suitable for: include_once __DIR__ . $fragment;
	 * where $fragment always starts with '/' or '/../'.
	 *
	 * @param string $from_dir Directory containing the proxy.
	 * @param string $to_file  Absolute target file.
	 * @return string
	 */
	public static function relative_include_suffix( $from_dir, $to_file ) {
		$from = str_replace( '\\', '/', rtrim( (string) $from_dir, '/\\' ) );
		$to   = str_replace( '\\', '/', (string) $to_file );
		$from_parts = explode( '/', $from );
		$to_parts   = explode( '/', $to );
		while ( count( $from_parts ) && count( $to_parts ) && $from_parts[0] === $to_parts[0] ) {
			array_shift( $from_parts );
			array_shift( $to_parts );
		}
		$suffix = str_repeat( '/..', count( $from_parts ) ) . '/' . implode( '/', $to_parts );
		if ( '' === $suffix || '/' !== $suffix[0] ) {
			$suffix = '/' . ltrim( $suffix, '/' );
		}
		return $suffix;
	}

	/**
	 * Rename with Windows-friendly replace.
	 *
	 * @param string $from Source.
	 * @param string $to   Destination.
	 * @return bool
	 */
	private static function rename_replace( $from, $to ) {
		if ( @rename( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
			return true;
		}
		if ( file_exists( $to ) ) {
			@unlink( $to ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			return (bool) @rename( $from, $to ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
		}
		return false;
	}

	/**
	 * Unique temp suffix.
	 *
	 * @return string
	 */
	private static function uniq_suffix() {
		try {
			return bin2hex( random_bytes( 8 ) );
		} catch ( \Exception $e ) {
			return uniqid( 'sn', true );
		}
	}

	/**
	 * Structured error.
	 *
	 * @param string $code    Code.
	 * @param string $message Message.
	 * @return \WP_Error|array
	 */
	private static function error( $code, $message ) {
		if ( class_exists( '\WP_Error' ) ) {
			return new \WP_Error( $code, $message );
		}
		return array(
			'ok'      => false,
			'code'    => $code,
			'message' => $message,
		);
	}

	/**
	 * Whether a write result is success.
	 *
	 * @param mixed $result Result from write_file.
	 * @return bool
	 */
	public static function is_ok( $result ) {
		return true === $result;
	}
}
