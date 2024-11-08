<?php
/**
 * File Viewer class for Security Ninja plugin.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

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
		if ( is_admin() && isset( $_GET['page'] ) && 'sn-view-file' === $_GET['page'] ) {
			add_filter( 'show_admin_bar', '__return_false' );
			remove_all_actions( 'admin_notices' ); // Remove all admin notices.
		}
	}

	/**
	 * Hide the admin interface for the file viewing page.
	 *
	 * @return void
	 */
	public static function hide_admin_interface() {
		if ( is_admin() && isset( $_GET['page'] ) && 'sn-view-file' === $_GET['page'] ) {
			?>
			<style>
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
					font-family: monospace;
				}
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
				}
				pre span.line-content {
					display: table-cell;
					white-space: pre-wrap;
					word-wrap: break-word;
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

				.highlighted-line {
					background-color: #ff0;
				}
			</style>
			<script>
				document.addEventListener("DOMContentLoaded", function() {
					const highlightedLine = document.querySelector(".highlighted-line");
					if (highlightedLine) {
						highlightedLine.scrollIntoView({ behavior: 'smooth', block: 'center' });
					}
				});
			</script>
			<?php
		}
	}

	/**
	 * Display the file viewing page.
	 *
	 * @return void
	 */
	public static function view_file_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'security-ninja' ) );
		}

		if ( ! isset( $_GET['file'], $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'view_file_' . wp_unslash($_GET['file'] ) ) ) {
			wp_die( esc_html__( 'Invalid nonce verification or missing file parameter.', 'security-ninja' ) );
		}

		$file_path = isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '';
		$highlight_line = isset( $_GET['line'] ) ? intval( $_GET['line'] ) : null;

		if ( ! self::is_allowed_file( $file_path ) ) {
			wp_die( esc_html__( 'Access to this file is restricted or the file does not exist.', 'security-ninja' ) . ' ' . esc_html( $file_path ) );
		}

		$file_meta = self::get_file_meta( $file_path );

		// Set the page title based on the file being viewed.
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
	 * Check if the given file is allowed to be viewed.
	 *
	 * @param string $file_path The path to the file.
	 * @return bool Whether the file is allowed to be viewed.
	 */
	private static function is_allowed_file( $file_path ) {
		$allowed_dirs    = array(
			ABSPATH . 'wp-content/',
			ABSPATH . 'wp-admin/',
			ABSPATH . 'wp-includes/',
			ABSPATH,
		);
		$normalized_path = wp_normalize_path( $file_path );

		// Prevent directory traversal
		if ( strpos( $normalized_path, '..' ) !== false ) {
			wf_sn_el_modules::log_event( 'File Viewer', 'Directory traversal attempt: ' . $normalized_path );
			return false;
		}

		// Check file extension
		$allowed_extensions = array( 'php', 'js', 'css', 'txt', 'html', 'htm', 'log', 'inc', 'xml', 'json', 'md', 'yml', 'yaml', 'ini', 'sql' );
		$file_extension     = strtolower( pathinfo( $normalized_path, PATHINFO_EXTENSION ) );
		$allowed_files      = array( 'debug.log', 'error_log' );

		if ( ! in_array( $file_extension, $allowed_extensions, true ) && ! in_array( basename( $normalized_path ), $allowed_files, true ) ) {
			wf_sn_el_modules::log_event( 'File Viewer', 'Attempt to view disallowed file type: ' . $file_extension );
			return false;
		}

		foreach ( $allowed_dirs as $dir ) {
			$normalized_dir = wp_normalize_path( $dir );
			if ( strpos( $normalized_path, $normalized_dir ) === 0 ) {
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
		}
		/* translators: %s: Normalized file path */
		\WPSecurityNinja\Plugin\wf_sn_el_modules::log_event( 'File Viewer', sprintf( esc_html__( 'Attempt to view file outside allowed directories: %s', 'security-ninja' ), $normalized_path ) );
		return false;
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
			'last_modified' => gmdate( 'F d Y H:i:s', filemtime( $file_path ) ),
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
		$url = admin_url( 'admin.php?page=sn-view-file' );
		$url = add_query_arg( 'file', urlencode( $file_path ), $url );
		if ( $highlight_line ) {
			$url = add_query_arg( 'line', intval( $highlight_line ), $url );
		}
		$url = add_query_arg( '_wpnonce', wp_create_nonce( 'view_file_' . $file_path ), $url );

		return esc_url( $url );
	}
}

FileViewer::init();