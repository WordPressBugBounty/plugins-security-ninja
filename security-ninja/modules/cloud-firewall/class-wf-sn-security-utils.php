<?php
namespace WPSecurityNinja\Plugin;

/**
 * Security utilities for file operations and validation
 *
 * @author Lars Koudal
 * @since v1.0.0
 */
class Wf_Sn_Security_Utils {

	/**
	 * Validate file type based on extension
	 *
	 * @param string $file_path Path to the file
	 * @param array $allowed_extensions Array of allowed file extensions
	 * @return bool True if file type is allowed
	 */
	public static function validate_file_type( $file_path, $allowed_extensions = array( 'php', 'txt', 'html', 'css', 'js' ) ) {
		$extension = pathinfo( $file_path, PATHINFO_EXTENSION );
		return in_array( strtolower( $extension ), $allowed_extensions, true );
	}

	/**
	 * Validate file size
	 *
	 * @param string $file_path Path to the file
	 * @param int $max_size Maximum file size in bytes
	 * @return bool True if file size is within limit
	 */
	public static function validate_file_size( $file_path, $max_size = 1048576 ) {
		if ( ! is_file( $file_path ) ) {
			return false;
		}
		$file_size = filesize( $file_path );
		return false !== $file_size && $file_size <= $max_size;
	}

	/**
	 * Validate file path is within allowed directories
	 *
	 * @param string $file_path Path to the file
	 * @param array $allowed_dirs Array of allowed directory paths
	 * @return bool True if file is within allowed directories
	 */
	public static function validate_file_path( $file_path, $allowed_dirs ) {
		$file_real_path = realpath( $file_path );
		if ( false === $file_real_path ) {
			return false;
		}

		foreach ( $allowed_dirs as $dir ) {
			if ( strpos( $file_real_path, $dir ) === 0 ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Comprehensive file validation
	 *
	 * @param string $file_path Path to the file
	 * @param array $options Validation options
	 * @return array Validation result with 'valid' boolean and 'errors' array
	 */
	public static function validate_file( $file_path, $options = array() ) {
		$defaults = array(
			'check_readable'     => true,
			'check_size'         => true,
			'max_size'           => 1048576, // 1MB default
			'check_type'         => true,
			'allowed_extensions' => array( 'php', 'txt', 'html', 'css', 'js' ),
			'check_mime'         => false,
			'check_path'         => true,
			'allowed_dirs'       => array( ABSPATH ),
		);

		$options = wp_parse_args( $options, $defaults );
		$errors  = array();

		// Check if file exists and is readable
		if ( $options['check_readable'] && ( ! is_file( $file_path ) || ! is_readable( $file_path ) ) ) {
			$errors[] = __( 'File does not exist or is not readable', 'security-ninja' );
		}

		// Check file size
		if ( $options['check_size'] && ! self::validate_file_size( $file_path, $options['max_size'] ) ) {
			$errors[] = __( 'File size exceeds limit', 'security-ninja' );
		}

		// Check file type
		if ( $options['check_type'] && ! self::validate_file_type( $file_path, $options['allowed_extensions'] ) ) {
			$errors[] = __( 'File type not allowed', 'security-ninja' );
		}

		// Check MIME type (optional)
		if ( $options['check_mime'] ) {
			$finfo     = new \finfo( FILEINFO_MIME_TYPE );
			$mime_type = $finfo->file( $file_path );

			$allowed_mimes = array( 'text/plain', 'text/html', 'text/css', 'application/javascript', 'application/x-httpd-php' );
			if ( ! in_array( $mime_type, $allowed_mimes, true ) ) {
				$errors[] = __( 'MIME type not allowed', 'security-ninja' );
			}
		}

		// Check file path
		if ( $options['check_path'] && ! self::validate_file_path( $file_path, $options['allowed_dirs'] ) ) {
			$errors[] = __( 'File path not allowed', 'security-ninja' );
		}

		return array(
			'valid'  => empty( $errors ),
			'errors' => $errors,
		);
	}

	/**
	 * Secure file_get_contents with validation
	 *
	 * @param string $file_path Path to the file
	 * @param array $options Validation options
	 * @return string|false File contents or false on failure
	 */
	public static function secure_file_get_contents( $file_path, $options = array() ) {
		$validation = self::validate_file( $file_path, $options );

		if ( ! $validation['valid'] ) {
			return false;
		}

		return file_get_contents( $file_path );
	}

	/**
	 * Drop a leading PHP block from a file read as an email template.
	 *
	 * includes/email-default.php starts with an ABSPATH guard. The guard is
	 * for direct requests. Reading the file as text would send that PHP in
	 * the message.
	 *
	 * @param string $contents Raw file contents.
	 * @return string Contents with the opening PHP block removed.
	 */
	public static function strip_leading_php_block( $contents ) {
		$trimmed = ltrim( (string) $contents );
		if ( 0 !== strpos( $trimmed, '<?php' ) ) {
			return $trimmed;
		}

		$end = strpos( $trimmed, '?>' );
		if ( false === $end ) {
			return $trimmed;
		}

		return ltrim( substr( $trimmed, $end + 2 ) );
	}

	/**
	 * Load the shared HTML email template and apply placeholders.
	 *
	 * @param array $replacements Placeholder => replacement.
	 * @return string HTML ready to send.
	 */
	public static function render_email_template( $replacements ) {
		$template_path = WF_SN_PLUGIN_DIR . 'includes/email-default.php';
		$html          = self::secure_file_get_contents(
			$template_path,
			array(
				'check_readable'     => true,
				'check_size'         => true,
				'max_size'           => 1024 * 1024,
				'check_type'         => true,
				'allowed_extensions' => array( 'php' ),
				'check_mime'         => false,
				'check_path'         => true,
				'allowed_dirs'       => array( WF_SN_PLUGIN_DIR ),
			)
		);

		if ( false === $html || '' === $html ) {
			return '<p>Email template not found.</p>';
		}

		$html = self::strip_leading_php_block( $html );

		foreach ( $replacements as $needle => $replacement ) {
			$html = str_replace( $needle, (string) $replacement, $html );
		}

		return $html;
	}
}
