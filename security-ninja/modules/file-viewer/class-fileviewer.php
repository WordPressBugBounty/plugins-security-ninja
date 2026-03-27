<?php
/**
 * File Viewer class for Security Ninja plugin.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class FileViewer
 *
 * Handles file viewing functionality for the Security Ninja plugin.
 */
class FileViewer {

	/**
	 * Maximum file size allowed for viewing (in bytes).
	 *
	 * @var int
	 */
	const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

	/**
	 * Whitelist of valid action values accepted by this viewer.
	 *
	 * @var array
	 */
	private static $allowed_actions = array( 'view_file', 'view_diff' );

	/**
	 * Maps action values to their handler methods.
	 *
	 * @var array
	 */
	private static $action_handlers = array(
		'view_file' => 'handle_view_file_action',
		'view_diff' => 'handle_view_diff_action',
	);

	/**
	 * Initialize the FileViewer class.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( self::class, 'register_view_file_page' ) );
		add_action( 'admin_post_sn_view_file', array( self::class, 'view_file_page' ) );
		add_action( 'admin_head', array( self::class, 'hide_admin_interface' ) );
		add_action( 'after_setup_theme', array( self::class, 'remove_admin_bar' ) );
	}

	/**
	 * Register the hidden submenu page for file viewing.
	 *
	 * @return void
	 */
	public static function register_view_file_page() {
		add_submenu_page(
			'options.php', // No parent slug, makes it a hidden page.
			__( 'Security Ninja File Viewer', 'security-ninja' ),
			__( 'Security Ninja File Viewer', 'security-ninja' ),
			'manage_options',
			'sn-view-file',
			array( self::class, 'view_file_page' )
		);
	}

	/**
	 * Remove the admin bar for the file viewing page.
	 *
	 * @return void
	 */
	public static function remove_admin_bar() {
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'sn_view_file' ) ) {
			return;
		}

		if ( ! self::is_viewer_request() ) {
			return;
		}

		add_filter( 'show_admin_bar', '__return_false' );
		remove_all_actions( 'admin_notices' );
	}

	/**
	 * Hide the admin interface for the file viewing page.
	 *
	 * @return void
	 */
	public static function hide_admin_interface() {
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'sn_view_file' ) ) {
			return;
		}

		if ( ! self::is_viewer_request() ) {
			return;
		}
		?>
		<style>
			/* Shared layout */
			#adminmenumain, #wpfooter, #screen-meta, #screen-meta-links, #wp-admin-bar-wp-logo {
				display: none;
			}
			#wpcontent, #wpbody {
				margin-left: 0;
				padding-left: 0;
			}
			.wrap {
				max-width: 90%;
				margin: 0 auto;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				color: #1d2327;
			}
			#file-info {
				display: flex;
				justify-content: space-between;
				align-items: center;
				margin-bottom: 20px;
			}
			#file-info h1 {
				margin: 0;
			}
			#file-info .file-meta {
				font-size: 14px;
				color: #666;
			}

			/* File view styles */
			pre {
				background-color: #f5f5f5;
				border: 1px solid #ccc;
				padding: 20px;
				white-space: pre-wrap;
				word-wrap: break-word;
				overflow-x: auto;
				line-height: 1.4em;
				display: table;
				width: 100%;
				table-layout: fixed;
				font-family: monospace;
			}
			pre span.line {
				display: table-row;
			}
			pre span.line-number {
				display: table-cell;
				width: 50px;
				text-align: right;
				padding-right: 10px;
				color: #888;
				vertical-align: top;
				white-space: nowrap;
			}
			pre span.line-content {
				display: table-cell;
				white-space: pre-wrap;
				word-wrap: break-word;
				word-break: break-all;
				overflow-wrap: break-word;
				max-width: 0;
			}
			.highlighted-line {
				background-color: #ff0;
			}

			/* Diff view styles */
			.diff { overflow-x: auto; }
			.diff table { border-collapse: collapse; width: 100%; font-size: 12px; line-height: 1.25; }
			.diff td, .diff th { 
				border: 0px;
				text-align: left;
				line-height: 1.25 !important;
			 }
			.diff tr { line-height: 1.25 !important; }
			.diff .diff-deletedline { background: #f8d7da; }
			.diff .diff-addedline { background: #d4edda; }

			@media print { .wrap { max-width: 100%; margin: 0; } }
		</style>
		<script>
			document.addEventListener("DOMContentLoaded", function() {
				var highlightedLine = document.querySelector(".highlighted-line");
				if (highlightedLine) {
					highlightedLine.scrollIntoView({ behavior: 'smooth', block: 'center' });
				}
			});
		</script>
		<?php
	}

	/**
	 * Check whether the current request is a valid viewer page request.
	 * Used by remove_admin_bar() and hide_admin_interface() for early
	 * checks before the main page callback runs. Callers verify _wpnonce
	 * before invoking this method.
	 *
	 * @return bool
	 */
	private static function is_viewer_request() {
		if ( ! is_admin() ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- _wpnonce verified by callers; token params validated below.
		if ( ! isset( $_GET['page'], $_GET['file'], $_GET['hash'], $_GET['nonce'], $_GET['action'] ) ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- _wpnonce verified by callers.
		if ( 'sn-view-file' !== $_GET['page'] ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- _wpnonce verified by callers.
		$action = isset( $_GET['action'] ) ? sanitize_text_field( wp_unslash( $_GET['action'] ) ) : '';
		if ( ! in_array( $action, self::$allowed_actions, true ) ) {
			return false;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- _wpnonce verified by callers; token validated by validate_secure_file_token.
		return Wf_Sn_Crypto::validate_secure_file_token(
			isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '',
			isset( $_GET['hash'] ) ? sanitize_text_field( wp_unslash( $_GET['hash'] ) ) : '',
			isset( $_GET['nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['nonce'] ) ) : '',
			$action
		);
	}

	/**
	 * Main page callback -- validates the request then dispatches
	 * to the appropriate action handler.
	 *
	 * @return void
	 */
	public static function view_file_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have sufficient permissions to access this page.' );
		}

		// Verify nonce before accessing $_GET variables
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'sn_view_file' ) ) {
			wp_die( 'Security check failed: Invalid nonce.' );
		}

		$action = isset( $_GET['action'] ) ? sanitize_text_field( wp_unslash( $_GET['action'] ) ) : '';

		if ( ! in_array( $action, self::$allowed_actions, true ) ) {
			wp_die( 'Invalid action.' );
		}

		if ( ! Wf_Sn_Crypto::validate_file_access_request( $action ) ) {
			wp_die( 'Access denied: Invalid or expired file access token.' );
		}

		$handler = isset( self::$action_handlers[ $action ] ) ? self::$action_handlers[ $action ] : null;
		if ( ! $handler || ! is_callable( array( self::class, $handler ) ) ) {
			wp_die( 'Invalid action.' );
		}

		$file_path = isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '';

		call_user_func( array( self::class, $handler ), $file_path );
	}

	/**
	 * Handler for the view_file action.
	 *
	 * @param string $file_path Absolute path to the file.
	 * @return void
	 */
	private static function handle_view_file_action( $file_path ) {
		if ( ! self::is_allowed_file( $file_path ) ) {
			wp_die( 'Access to this file is restricted or the file does not exist.' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request validated (nonce + token) in view_file_page().
		$highlight_line = isset( $_GET['line'] ) ? intval( $_GET['line'] ) : null;
		$file_meta      = self::get_file_meta( $file_path );

		echo '<title>' . esc_html( basename( $file_path ) ) . ' - ' . esc_html__( 'Security Ninja File Viewer', 'security-ninja' ) . '</title>';

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Security Ninja File Viewer', 'security-ninja' ) . '</h1>';
		echo '<div id="file-info">';
		echo '<div class="file-meta">';
		if ( $file_meta ) {
			echo esc_html__( 'File:', 'security-ninja' ) . ' ' . esc_html( $file_meta['path'] ) . ' | ';
			echo esc_html__( 'Size:', 'security-ninja' ) . ' ' . esc_html( $file_meta['size'] ) . ' | ';
			echo esc_html__( 'Last Modified:', 'security-ninja' ) . ' ' . esc_html( $file_meta['last_modified'] ) . ' | ';
			echo esc_html__( 'Permissions:', 'security-ninja' ) . ' ' . esc_html( $file_meta['permissions'] );
		}
		echo '</div>';
		echo '</div>';
		echo wp_kses_post( self::render_file( $file_path, $highlight_line ) );
		echo '</div>';
	}

	/**
	 * Handler for the view_diff action.
	 * Compares the current WordPress core file against the original from WP Trac.
	 *
	 * @param string $file_path Absolute path to the current core file.
	 * @return void
	 */
	private static function handle_view_diff_action( $file_path ) {
		if ( ! is_string( $file_path ) || '' === $file_path ) {
			wp_die( 'Invalid file.' );
		}
		if ( ! Wf_Sn_Cs::is_core_file( $file_path ) ) {
			wp_die( 'Access denied: file is not a WordPress core file.' );
		}
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			wp_die( 'File not found or not readable.' );
		}
		if ( filesize( $file_path ) > self::MAX_FILE_SIZE ) {
			wp_die( 'File is too large to compare.' );
		}

		$relative_path = str_replace( array( ABSPATH, '\\' ), array( '', '/' ), $file_path );
		$relative_path = ltrim( $relative_path, '/' );

		Wf_Sn_Cs::load_utils();
		$original = Wf_Sn_Cs_Utils::get_original_core_file_content( $relative_path );
		if ( is_wp_error( $original ) ) {
			$file_meta = self::get_file_meta( $file_path );
			echo '<div class="wrap">';
			echo '<h1>' . esc_html__( 'Compare file', 'security-ninja' ) . ': ' . esc_html( $relative_path ) . '</h1>';
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The original file is not available for comparison. This can happen if the file is not part of the standard WordPress core for your version, or the comparison source is temporarily unavailable.', 'security-ninja' ) . '</p></div>';
			if ( $file_meta ) {
				echo '<p class="description">' . esc_html__( 'File:', 'security-ninja' ) . ' ' . esc_html( $file_meta['path'] ) . ' | ' . esc_html__( 'Size:', 'security-ninja' ) . ' ' . esc_html( $file_meta['size'] ) . '</p>';
			}
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=wf-sn' ) ) . '" class="button">' . esc_html__( 'Back to Security Ninja', 'security-ninja' ) . '</a></p>';
			echo '</div>';
			return;
		}

		$current = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading local validated file
		if ( false === $current ) {
			wp_die( 'Could not read current file.' );
		}

		$diff = wp_text_diff(
			$original,
			$current,
			array(
				'show_split_view' => true,
				'title_left'      => __( 'Original (WordPress)', 'security-ninja' ),
				'title_right'     => __( 'Current', 'security-ninja' ),
			)
		);
		if ( '' === $diff ) {
			$diff = '<p>' . esc_html__( 'No differences found.', 'security-ninja' ) . '</p>';
		}

		$file_meta = self::get_file_meta( $file_path );

		echo '<title>' . esc_html__( 'Compare file', 'security-ninja' ) . ' - ' . esc_html( $relative_path ) . '</title>';

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Compare file', 'security-ninja' ) . ': ' . esc_html( $relative_path ) . '</h1>';
		echo '<div id="file-info">';
		echo '<div class="file-meta">';
		if ( $file_meta ) {
			echo esc_html__( 'File:', 'security-ninja' ) . ' ' . esc_html( $file_meta['path'] ) . ' | ';
			echo esc_html__( 'Size:', 'security-ninja' ) . ' ' . esc_html( $file_meta['size'] ) . ' | ';
			echo esc_html__( 'Last Modified:', 'security-ninja' ) . ' ' . esc_html( $file_meta['last_modified'] ) . ' | ';
			echo esc_html__( 'Permissions:', 'security-ninja' ) . ' ' . esc_html( $file_meta['permissions'] );
		}
		echo '</div>';
		echo '</div>';
		echo '<div class="diff">' . wp_kses_post( $diff ) . '</div>';
		echo '</div>';
	}

	/**
	 * Check if the given file is allowed to be viewed.
	 *
	 * @param string $file_path The path to the file.
	 * @return bool Whether the file is allowed to be viewed.
	 */
	private static function is_allowed_file( $file_path ) {
		$normalized_path = wp_normalize_path( $file_path );

		// Prevent directory traversal
		if ( strpos( $normalized_path, '..' ) !== false ) {
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', 'Directory traversal attempt: ' . $normalized_path );
			return false;
		}

		// Check file extension
		$allowed_extensions = array( 'php', 'js', 'css', 'txt', 'html', 'htm', 'log', 'inc', 'xml', 'json', 'md', 'yml', 'yaml', 'ini', 'sql' );
		$file_extension     = strtolower( pathinfo( $normalized_path, PATHINFO_EXTENSION ) );
		$allowed_files      = array( 'debug.log', 'error_log', 'php_errorlog' );

		if ( ! in_array( $file_extension, $allowed_extensions, true ) && ! in_array( basename( $normalized_path ), $allowed_files, true ) ) {
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', 'Attempt to view disallowed file type: ' . $file_extension );
			return false;
		}

		// Check if file is within WordPress installation directory
		if ( ! self::is_within_wordpress_installation( $file_path ) ) {
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', 'Attempt to view file outside WordPress installation: ' . $normalized_path );
			return false;
		}

		// Check if file is readable and within size limits
		if ( ! is_readable( $file_path ) ) {
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', 'Attempt to view unreadable file: ' . $normalized_path );
			return false;
		}
		if ( filesize( $file_path ) > self::MAX_FILE_SIZE ) {
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', 'Attempt to view file exceeding size limit: ' . self::MAX_FILE_SIZE );
			return false;
		}

		return true;
	}

	/**
	 * Check if a file can be viewed (has allowed extension and meets requirements)
	 *
	 * @param string $file_path The file path to check
	 * @return bool Whether the file can be viewed
	 */
	public static function can_view_file( $file_path ) {
		// Use the same logic as is_allowed_file but without logging
		$normalized_path = wp_normalize_path( $file_path );

		// Prevent directory traversal
		if ( strpos( $normalized_path, '..' ) !== false ) {
			return false;
		}

		// Check file extension
		$allowed_extensions = array( 'php', 'js', 'css', 'txt', 'html', 'htm', 'log', 'inc', 'xml', 'json', 'md', 'yml', 'yaml', 'ini', 'sql' );
		$file_extension     = strtolower( pathinfo( $normalized_path, PATHINFO_EXTENSION ) );
		$allowed_files      = array( 'debug.log', 'error_log', 'php_errorlog' );

		if ( ! in_array( $file_extension, $allowed_extensions, true ) && ! in_array( basename( $normalized_path ), $allowed_files, true ) ) {
			return false;
		}

		// Check if file is within WordPress installation directory
		if ( ! self::is_within_wordpress_installation( $file_path ) ) {
			return false;
		}

		// Check if file is readable and within size limits
		if ( ! is_readable( $file_path ) ) {
			return false;
		}
		if ( filesize( $file_path ) > self::MAX_FILE_SIZE ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if a file path is within WordPress installation directory
	 *
	 * @param string $file_path The file path to check
	 * @return bool Whether the file is within WordPress installation
	 */
	public static function is_within_wordpress_installation( $file_path ) {
		// Prevent directory traversal attacks
		if ( strpos( $file_path, '..' ) !== false ) {
			return false;
		}

		// Normalize the file path
		$file_path = realpath( $file_path );
		if ( false === $file_path ) {
			return false;
		}

		// Get WordPress root directory
		$wp_root = realpath( ABSPATH );
		if ( false === $wp_root ) {
			return false;
		}

		// Check if the file is within WordPress installation
		return strpos( $file_path, $wp_root ) === 0;
	}

	/**
	 * Get metadata for a given file.
	 *
	 * @param string $file_path The path to the file.
	 * @return array An array containing file metadata.
	 */
	private static function get_file_meta( $file_path ) {
		return array(
			'path'          => $file_path,
			'size'          => size_format( filesize( $file_path ) ),
			'last_modified' => date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), filemtime( $file_path ) ),
			'permissions'   => substr( sprintf( '%o', fileperms( $file_path ) ), -4 ),
		);
	}

	/**
	 * Render the contents of a file.
	 *
	 * @param string $file_path      The path to the file.
	 * @param int    $highlight_line The line number to highlight.
	 * @return string The HTML output of the file contents.
	 */
	private static function render_file( $file_path, $highlight_line ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			/* translators: %s: File path */
			\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', sprintf( esc_html__( 'File not found or not readable: %s', 'security-ninja' ), $file_path ) );
			return '<p>' . esc_html__( 'File not found or not readable.', 'security-ninja' ) . '</p>';
		}

		$output = '<pre>';
		$file   = new \SplFileObject( $file_path );

		$line_count = 0;
		foreach ( $file as $line_num => $line ) {
			++$line_num;
			++$line_count;
			if ( $line_count > 10000 ) { // Limit to 10,000 lines
				$output .= '<span class="line">' . esc_html__( 'File truncated...', 'security-ninja' ) . '</span>';
				break;
			}
			$line_html        = '<span class="line-content">' . esc_html( $line ) . '</span>';
			$line_number_html = '<span class="line-number">' . esc_html( $line_num ) . '</span>';
			$line_class       = ( $line_num === $highlight_line ) ? 'highlighted-line' : '';
			$output          .= '<span class="line ' . esc_attr( $line_class ) . '">' . $line_number_html . $line_html . '</span>';
		}
		$output .= '</pre>';

		return $output;
	}

	/**
	 * Generate a URL for viewing a file.
	 *
	 * @param string $file_path      The path to the file.
	 * @param int    $highlight_line The line number to highlight.
	 * @return string The URL for viewing the file.
	 */
	public static function generate_file_view_url( $file_path, $highlight_line = null ) {
		$additional_params = array();
		if ( $highlight_line ) {
			$additional_params['line'] = $highlight_line;
		}

		$additional_params['_wpnonce'] = wp_create_nonce( 'sn_view_file' );

		return Wf_Sn_Crypto::generate_secure_file_url( $file_path, 'view_file', $additional_params );
	}

	/**
	 * Generate a URL for viewing a file diff (core file vs. original).
	 *
	 * @param string $file_path The absolute path to the core file.
	 * @return string The URL for viewing the diff.
	 */
	public static function generate_diff_view_url( $file_path ) {
		$additional_params = array(
			'_wpnonce' => wp_create_nonce( 'sn_view_file' ),
		);

		return Wf_Sn_Crypto::generate_secure_file_url( $file_path, 'view_diff', $additional_params );
	}
}

FileViewer::init();