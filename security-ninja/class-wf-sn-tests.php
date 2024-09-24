<?php
/*
* Security Ninja
* Test functions
*/

namespace WPSecurityNinja\Plugin;

// this is an include only WP file
if (!defined('ABSPATH')) {
	die;
}

class Wf_Sn_Tests extends WF_SN
{

	public static $security_tests;

	public static function return_security_tests()
	{
		return array(
			'ver_check'                 => array(
				'title'   => __('Check if WordPress core is up to date.', 'security-ninja'),
				'score'   => 5,
			),

			'core_updates_check'        => array(
				'title'   => __('Check if automatic WordPress core updates are enabled.', 'security-ninja'),
				'score'   => 5,
			),

			// Plugins

			'plugins_ver_check'         => array(
				'title'   => __('Check if plugins are up to date.', 'security-ninja'),
				'score'   => 5,
			),

			'deactivated_plugins'       => array(
				'title'   => __('Check if there are deactivated plugins.', 'security-ninja'),
				'score'   => 3,
			),

			'old_plugins'               => array(
				'title'       => __('Check if active plugins have been updated in the last 12 months.', 'security-ninja'),
				'score'       => 3,
			),

			'incompatible_plugins'      => array(
				'title'       => __('Check if active plugins are compatible with your version of WP.', 'security-ninja'),
				'score'       => 3,
			),

			// themes

			'themes_ver_check'          => array(
				'title'   => __('Check if themes are up to date.', 'security-ninja'),
				'score'   => 5,
			),

			'deactivated_themes'        => array(
				'title'   => __('Check if there are unnecessary themes.', 'security-ninja'),
				'score'   => 3,
			),

			// WP header
			'wp_header_meta'            => array(
				'title'       => __('Check if full WordPress version info is revealed in page\'s meta data.', 'security-ninja'),
				'score'       => 3,
			),

			'wlw_meta'                  => array(
				'title'       => __('Check if Windows Live Writer link is present in the header data.', 'security-ninja'),
				'score'       => 1,
			),

			// server related
			'php_ver'                   => array(
				'title'       => __('Check the PHP version.', 'security-ninja'),
				'score'       => 4,
			),

			// database
			'mysql_ver'                 => array(
				'title'       => __('Check the MySQL version.', 'security-ninja'),
				'score'       => 4,
			),

			'db_table_prefix_check'     => array(
				'title'   => __('Check if database table prefix is the default one (wp_).', 'security-ninja'),
				'score'   => 3,
			),

			// server headers
			'php_headers'               => array(
				'title'       => __('Check if server response headers contain detailed PHP version info.', 'security-ninja'),
				'score'       => 2,
			),

			'expose_php_check'          => array(
				'title'   => __('Check if expose_php PHP directive is turned off.', 'security-ninja'),
				'score'   => 1,
			),

			// users
			'user_exists'               => array(
				'title'   => __('Check if user with username "admin" exists.', 'security-ninja'),
				'score'   => 4,
			),

			'anyone_can_register'       => array(
				'title'   => __('Check if "anyone can register" option is enabled.', 'security-ninja'),
				'score'   => 3,
			),

			'id1_user_check'            => array(
				'title'   => __('Check if user with ID "1" exists.', 'security-ninja'),
				'score'   => 1,
			),

			// login
			'check_failed_login_info'   => array(
				'title'   => __('Check for display of unnecessary information on failed login attempts.', 'security-ninja'),
				'score'   => 3,
			),

			// wp-config file checks
			'config_chmod'              => array(
				'title'       => __('Check if wp-config.php file has the right permissions (chmod) set.', 'security-ninja'),
				'score'       => 5,
			),

			'config_location'           => array(
				'title'   => __('Check if wp-config.php is present on the default location.', 'security-ninja'),
				'score'   => 2,
			),

			'db_password_check'         => array(
				'title'   => __('Check the strength of WordPress database password.', 'security-ninja'),
				'score'   => 5,
			),

			'salt_keys_check'           => array(
				'title'   => __('Check if security keys and salts have proper values.', 'security-ninja'),
				'score'   => 3,
			),

			'salt_keys_age_check'       => array(
				'title'       => __('Check the age of security keys and salts.', 'security-ninja'),
				'score'       => 1,
			),

			'debug_check'               => array(
				'title'   => __('Check if general debug mode is enabled.', 'security-ninja'),
				'score'   => 4,
			),

			'debug_log_file_check'      => array(
				'title'       => __('Check if WordPress debug.log file exists.', 'security-ninja'),
				'score'       => 4,
			),

			'db_debug_check'            => array(
				'title'   => __('Check if database debug mode is enabled.', 'security-ninja'),
				'score'   => 4,
			),

			'script_debug_check'        => array(
				'title'   => __('Check if JavaScript debug mode is enabled.', 'security-ninja'),
				'score'   => 4,
			),

			'display_errors_check'      => array(
				'title'   => __('Check if display_errors PHP directive is turned off.', 'security-ninja'),
				'score'   => 4,
			),

			'blog_site_url_check'       => array(
				'title'   => __('Check if WordPress installation address is the same as the site address.', 'security-ninja'),
				'score'   => 2,
			),

			// server settings and PHP checks
			'register_globals_check'    => array(
				'title'   => __('Check if register_globals PHP directive is turned off.', 'security-ninja'),
				'score'   => 5,
			),

			'safe_mode_check'           => array(
				'title'   => __('Check if PHP safe mode is disabled.', 'security-ninja'),
				'score'   => 5,
			),

			'allow_url_include_check'   => array(
				'title'   => __('Check if allow_url_include PHP directive is turned off.', 'security-ninja'),
				'score'   => 5,
			),

			// WordPress features
			'file_editor'               => array(
				'title'   => __('Check if plugins/themes file editor is enabled.', 'security-ninja'),
				'score'   => 2,
			),

			'uploads_browsable'         => array(
				'title'       => __('Check if uploads folder is browsable by browsers.', 'security-ninja'),
				'score'       => 2,
			),

			'application_passwords'     => array(
				'title'       => __('Check if Application Passwords are enabled.', 'security-ninja'),
				'score'       => 2,
			),

			'mysql_external'            => array(
				'title'       => __('Check if MySQL server is connectable from outside with the WP user.', 'security-ninja'),
				'score'       => 2,
			),

			'rpc_meta'                  => array(
				'title'       => __('Check if EditURI (XML-RPC) link is present in the header data.', 'security-ninja'),
				'score'       => 1,
			),

			'tim_thumb'                 => array(
				'title'       => __('Check if Timthumb script is used in the active theme.', 'security-ninja'),
				'score'       => 5,
			),

			'shellshock_6271'           => array(
				'title'       => __('Check if the server is vulnerable to the Shellshock bug #6271.', 'security-ninja'),
				'score'       => 4,
			),

			'shellshock_7169'           => array(
				'title'       => __('Check if the server is vulnerable to the Shellshock bug #7169.', 'security-ninja'),
				'score'       => 4,
			),

			'admin_ssl'                 => array(
				'title'       => __('Check if admin interface is delivered via SSL', 'security-ninja'),
				'score'       => 3,
			),

			'mysql_permissions'         => array(
				'title'       => __('Check if MySQL account used by WordPress has too many permissions', 'security-ninja'),
				'score'       => 2,
			),

			'usernames_enumeration'     => array(
				'title'   => __('Check if the list of usernames can be fetched by looping through user IDs', 'security-ninja'),
				'score'   => 3,
			),

			'rest_api_links'            => array(
				'title'       => __('Check if the REST API links are shown in code', 'security-ninja'),
				'score'       => 2,
			),

			'x_content_type_options'    => array(
				'title'   => __('Check if server response headers contain X-Content-Type-Options.', 'security-ninja'),
				'score'   => 4,
			),

			'x_frame_options'           => array(
				'title'   => __('Check if server response headers contain X-Frame-Options.', 'security-ninja'),
				'score'   => 4,
			),

			'strict_transport_security' => array(
				'title'   => __('Check if server response headers contain Strict-Transport-Security.', 'security-ninja'),
				'score'   => 4,
			),

			'referrer_policy'           => array(
				'title'   => __('Check if server response headers contain Referrer-Policy.', 'security-ninja'),
				'score'   => 4,
			),

			'feature_policy'            => array(
				'title'   => __('Check if server response headers contain Permissions-Policy.', 'security-ninja'),
				'score'   => 4,
			),

			'content_security_policy'   => array(
				'title'       => __('Check if server response headers contain Content-Security-Policy.', 'security-ninja'),
				'score'       => 4,
			),

			'rest_api_enabled'          => array(
				'title'       => __('Check if the REST API is enabled.', 'security-ninja'),
				'score'       => 2,
			),

			'dangerous_files'           => array(
				'title'   => __('Check for unwanted files in your root folder you should remove.', 'security-ninja'),
				'score'   => 3,

			),
		);
	}

	/**
	 * rest_api_enabled.
	 *
	 * @author  Lars Koudal
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0    Monday, January 25th, 2021.
	 * @version v1.0.1    Wednesday, December 20th, 2023.
	 * @access  public static
	 * @return  void
	 */
	public static function rest_api_enabled()
	{
		$return = array();

		$url = get_rest_url();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		// Check if the REST API URL was retrieved successfully
		if (!$url) {
			return array(
				'status'  => 10,
				'msg' => __('REST API URL not found.', 'security-ninja'),
				'sslverify'   => !$is_local,

			);
		}

		$response = wp_remote_get($url, array('redirection' => 0));

		// Check if the request was successful
		if (is_wp_error($response)) {
			return array(
				'status'  => 10,
				'msg' => esc_html($response->get_error_message()),
			);
		}

		// Check the response code
		$response_code = wp_remote_retrieve_response_code($response);
		if (200 === $response_code) {
			return array(
				'status'  => 5,
				'msg' => __('REST API is accessible.', 'security-ninja'),
			);
		} else {
			return array(
				'status'  => 10,
				'msg' => sprintf(__('REST API is not accessible. Response Code: %s', 'security-ninja'), esc_html($response_code)),
			);
		}
	}


	/**
	 * Scan for dangerous files in root
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function dangerous_files()
	{
		// @todo - fix case Insensitive files - glob no fun
		// @todo - maybe run in subfolders also? worth it?

		$return = array();

		$dangerous_files = array(
			'wp-config.php.old'      => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php_bak'      => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php~'         => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php-'         => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php--'        => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php---'       => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php.bkp'      => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'wp-config.php_revision' => __('Common name for config file backup - can contain critical information', 'security-ninja'),
			'php_errorlog'           => __('Can contain server details or errors that can be exploited.', 'security-ninja'),
			'php_mail.log'           => __('Can contain user details or errors that can be exploited.', 'security-ninja'),
			'.htaccess.sg'           => __('.htaccess backup files on SiteGround - Can show server details or configurations that should not be public.', 'security-ninja'),
			'.htaccess_swift_backup' => __('.htaccess backup file by Swift Performance - Can show server details or configurations that should not be public.', 'security-ninja'),
			'*.sql'                  => __('.sql files should not be kept on your server - they may contain sensitive data.', 'security-ninja'),
			'phpinfo.php'            => __('Displays all details about PHP on your website, should only exist briefly during development.', 'security-ninja'),
			'info.php'               => __('Should only exist briefly during development and not on a live site.', 'security-ninja'),
			'test.php'               => __('Should only exist briefly during development and not on a live site.', 'security-ninja'),
			'*.bak'                  => __('Copies of old files could contain important info about your server.', 'security-ninja'),
			'license.txt'            => __('Default license.txt file', 'security-ninja'),
			'readme.html'            => __('Default readme.html', 'security-ninja'),
		);
		$return['status']  = 10;
		$return['msg'] = '<dl>';

		foreach ($dangerous_files as $key => $explanation) {
			// If its a wildcard search
			if (false !== strpos($key, '*.')) {
				$files = glob(ABSPATH . $key);
				if ((is_array($files)) && (count($files) > 0)) {
					foreach ($files as $f) {
						$display_name       = str_replace(ABSPATH, '', $f);
						$return['msg'] .= '<dt><strong>' . $display_name . '</strong></dt><dd>' . $explanation . '</dd>';
					}
					$return['status'] = 0;
				}
			} else {
				$check = file_exists(ABSPATH . $key);
				if ($check) {
					$return['msg'] .= '<dt><strong>' . $key . '</strong></dt><dd>' . $explanation . '</dd>';
					$return['status']   = 0;
				}
			}
		}

		$return['msg'] .= '</dl>';

		return $return;
	}

	/**
	 * Checks if the website is SSL or not
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Thursday, April 8th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function check_server_ssl()
	{
		$is_https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'
			|| isset($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] === 'https'
			|| isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https';

		if ($is_https) {
			return array(
				'status' => 10,
				'msg' => __('The server is using HTTPS. This is the recommended configuration.', 'security-ninja'),
			);
		} else {
			return array(
				'status' => 0,
				'msg' => __('The server is not using HTTPS. It is recommended to use HTTPS to enhance security.', 'security-ninja'),
			);
		}
	}

	/**
	 * Checks if admin is using SSL
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function admin_ssl()
	{
		$return = array();

		if (false === stripos(get_admin_url(), 'https')) {
			$return['status'] = 0;
			$return['msg'] = __('You should set your Settings -> General URLs to start with https://', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Admin URLs are set to start with https.', 'security-ninja');
		}

		$force_ssl_admin = force_ssl_admin();
		if (!$force_ssl_admin) {
			$return['status'] = 0;
			$return['msg'] = __('Admin pages are not secured by SSL. It is recommended to force SSL in admin pages.', 'security-ninja');
		} elseif ($return['status'] !== 0) {
			// Only update the message if the previous check didn't already set the status to 0
			$return['status'] = 10;
			$return['msg'] = __('Great, admin pages are secured by SSL.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * check if Timthumb is used
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function tim_thumb()
	{
		$return = array();
		$theme = wp_get_theme();
		$theme_name_version = $theme->get('Name') . ' v' . $theme->get('Version'); // Use get() method for properties
		$scan_result = self::tim_thumb_scan(get_theme_root());
		if (is_wp_error($scan_result)) {
			$return['status'] = 5; // Indicate an error
			$return['msg'] = __('An error occurred during the TimThumb scan.', 'security-ninja');
		} elseif ($scan_result && isset($scan_result['status']) && 0 === $scan_result['status']) {
			$return['status'] = 0; // Indicate a potential issue
			$return['msg'] = sprintf(__('TimThumb file found in theme: %s. Please remove or replace it.', 'security-ninja'), $theme_name_version);
		} else {
			$return['status'] = 10; // No issue found
			$return['msg'] = sprintf(__('No TimThumb file found in theme: %s. Your theme is safe.', 'security-ninja'), $theme_name_version);
		}

		return $return;
	}



	/**
	 * scan all PHP files and look for timtumb script
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @version v1.0.1  Saturday, November 18th, 2023.
	 * @access  public static
	 * @param   mixed $path
	 * @return  integer
	 */
	public static function tim_thumb_scan($path)
	{
		global $wp_filesystem;

		// Setup the WordPress filesystem, if not already set up
		if (empty($wp_filesystem)) {
			include_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		// Array to hold all the PHP files we want to scan
		$php_files = array();

		// Scan the directory for PHP files
		$files = $wp_filesystem->dirlist($path);
		if (!$files) {
			return array(
				'status' => 5,
				'msg'    => __('Failed to list directory contents.', 'security-ninja'),
			);
		}

		foreach ($files as $file => $fileinfo) {
			if ('php' === pathinfo($file, PATHINFO_EXTENSION)) {
				$php_files[] = trailingslashit($path) . $file;
			}

			if ('d' === $fileinfo['type']) {
				$sub_files = $wp_filesystem->dirlist(trailingslashit($path) . $file);
				foreach ($sub_files as $sub_file => $sub_fileinfo) {
					if ('php' === pathinfo($sub_file, PATHINFO_EXTENSION)) {
						$php_files[] = trailingslashit($path) . trailingslashit($file) . $sub_file;
					}
				}
			}
		}

		foreach ($php_files as $php_file) {
			$content = $wp_filesystem->get_contents($php_file);
			if (false === $content) {
				return array(
					'status' => 5,
					'msg'    => __('Failed to read file contents.', 'security-ninja'),
				);
			}

			// Define multiple unique identifiers for TimThumb
			$timThumbIdentifiers = array(
				'TimThumb script created by Tim McDaniels',
				'CACHE_MAX_FILE_AGE', // Example of a unique constant in TimThumb
				'TIMTHUMB_VERSION',   // Example of a unique version identifier
			);

			// Check for the presence of all unique identifiers
			$foundIdentifiers = 0;
			foreach ($timThumbIdentifiers as $identifier) {
				if (false !== stripos($content, $identifier)) {
					$foundIdentifiers++;
				}
			}

			// If multiple identifiers are found, it's likely a TimThumb script
			if ($foundIdentifiers >= 2) { // Adjust the threshold as needed
				return array(
					'status' => 0,
					'msg'    => __('TimThumb script detected.', 'security-ninja'),
				);
			}
		}

		return array(
			'status' => 10,
			'msg'    => __('No TimThumb scripts detected.', 'security-ninja'),
		);
	}





	/**
	 * check if user with DB ID 1 exists
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function id1_user_check()
	{
		$return = array();

		$user_data = get_userdata(1);
		if ($user_data) {
			$return['status'] = 0;
			$return['msg'] = sprintf(__('The user with ID 1 exists, and the username is %s.', 'security-ninja'), esc_html($user_data->user_login));
		} else {
			$return['status'] = 10;
			$return['msg'] = __('No user exists with ID 1.', 'security-ninja');
		}

		return $return;
	}




	/**
	 * check if wp-config is present on the default location
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function config_location()
	{
		$return = array();
		$tested_file = ABSPATH . 'wp-config.php';
		$check = file_exists($tested_file);

		$return['details'] = sprintf(__('Looked for file here: %s', 'security-ninja'), esc_html(ABSPATH));
		if ($check) {
			$return['status'] = 0;
			$return['msg'] = __('wp-config.php file found in the WordPress root directory.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('wp-config.php file not found in the WordPress root directory. It is recommended to place wp-config.php in the root directory for standard WordPress installations.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * check if the WP MySQL user can connect from an external host
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function mysql_external()
	{
		$return = array();
		global $wpdb;

		$current_user = $wpdb->get_var('SELECT CURRENT_USER();');
		if (false === $current_user) {
			$return['status'] = 5;
			$return['msg'] = __('Unable to determine the MySQL current user.', 'security-ninja');
		} elseif (strpos($current_user, '@%') !== false) {
			$return['status'] = 0;
			$return['msg'] = __('MySQL current user can connect from any host, which might be a security risk.', 'security-ninja');
		} elseif (strpos($current_user, '@127.0.0.1') !== false || stripos($current_user, '@localhost') !== false) {
			$return['status'] = 10;
			$return['msg'] = __('MySQL current user is restricted to localhost, which is a secure configuration.', 'security-ninja');
		} else {
			$return['status'] = 5;
			$return['msg'] = sprintf(__('Unexpected MySQL current user host: %s', 'security-ninja'), esc_html($current_user));
		}

		return $return;
	}





	/**
	 * check if the WP MySQL user has too many permissions granted
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function mysql_permissions()
	{
		$return = array(
			'status' => 10,
			'msg'    => __('Database permissions are set correctly.', 'security-ninja'),
		);

		global $wpdb;

		$grants = $wpdb->get_results('SHOW GRANTS', ARRAY_N);

		if (is_wp_error($grants)) {
			$return['status'] = 0;
			$return['msg']    = __('Failed to retrieve database permissions.', 'security-ninja');
			return $return;
		}

		foreach ($grants as $grant) {
			if (false !== stripos($grant[0], 'GRANT ALL PRIVILEGES')) {
				$return['status'] = 5;
				$return['msg']    = __('Database permissions are too permissive.', 'security-ninja');
				break;
			}
		}

		return $return;
	}





	/**
	 * check if WLW link ispresent in header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function wlw_meta()
	{
		$return = array();

		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
				add_query_arg('secnin-test', rand(), get_home_url()),
				array(
						'timeout'     => 25,
						'redirection' => 2,
						'sslverify'   => !$is_local,
				)
		);
		if (is_wp_error($response)) {
			$return['status'] = 5;
			$return['msg'] = __('Failed to retrieve the home page for analysis.', 'security-ninja');
		} else {
			$html = wp_remote_retrieve_body($response);

			if (!empty($html)) {
				$return['status'] = 10;
				$start = strpos($html, '<head');
				$end = strpos($html, '</head>', $start);
				$head_content = substr($html, $start, $end - $start + strlen('</head>')); // Correctly include the closing </head>

				preg_match_all('#<link\s+[^>]*>#si', $head_content, $matches);
				$meta_tags = $matches[0];
				$wlw_manifest_found = false;

				foreach ($meta_tags as $meta_tag) {
					if (false !== stripos($meta_tag, 'wlwmanifest')) {
						$wlw_manifest_found = true;
						break;
					}
				}

				if ($wlw_manifest_found) {
					$return['status'] = 0;
					$return['msg'] = __('The wlwmanifest link is present. It is recommended to remove it if not needed.', 'security-ninja');
				} else {
					$return['msg'] = __('The wlwmanifest link is not present. This is the recommended configuration.', 'security-ninja');
				}
			} else {
				$return['status'] = 5;
				$return['msg'] = __('Unable to retrieve the home page content.', 'security-ninja');
			}
		}

		return $return;
	}




	/**
	 * check if RPC link ispresent in header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function rpc_meta()
	{ // @todo ? mixed with edit-uri
		$return = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$request = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,

				)
		);

		if (is_wp_error($request)) {
			$return['status'] = 5;
			$return['msg'] = __('Failed to retrieve the home page for analysis.', 'security-ninja');
		} else {
			$html = wp_remote_retrieve_body($request);

			if (!empty($html)) {
				$return['status'] = 10;
				// Correctly extract content within <head> tags
				$start = strpos($html, '<head');
				$end = strpos($html, '</head>', $start);
				$head_content = substr($html, $start, $end - $start + strlen('</head>'));
				// Find all link tags
				preg_match_all('#<link\s+[^>]*>#si', $head_content, $matches);
				$meta_tags = $matches[0];
				$edit_uri_found = false;

				foreach ($meta_tags as $meta_tag) {
					if (false !== stripos($meta_tag, 'EditURI')) {
						$edit_uri_found = true;
						break;
					}
				}

				if ($edit_uri_found) {
					$return['status'] = 0;
					$return['msg'] = __('The EditURI link is present. It is recommended to remove it if not needed.', 'security-ninja');
				} else {
					$return['msg'] = __('The EditURI link is not present. This is the recommended configuration.', 'security-ninja');
				}
			} else {
				$return['status'] = 5;
				$return['msg'] = __('Unable to retrieve the home page content.', 'security-ninja');
			}
		}

		return $return;
	}



	/**
	 * check if register_globals is off
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function register_globals_check()
	{
		$return = array();
		$ini_option_name = 'register_globals';
		$register_globals = (bool) ini_get($ini_option_name);

		if ($register_globals) {
			$return['status'] = 0;
			$return['msg'] = __('register_globals is enabled. This is a security risk.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('register_globals is disabled. This is the recommended configuration.', 'security-ninja');
		}

		return $return;
	}





	/**
	 * check if display_errors is off
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function display_errors_check()
	{
		$return = array();

		$display_errors = (bool) ini_get('display_errors');
		if ($display_errors) {
			$return['status'] = 0;
			$return['msg'] = __('display_errors is enabled. This can reveal sensitive information and is a security risk.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('display_errors is disabled. This is the recommended configuration for production environments to prevent revealing sensitive information.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * Tests for Application Passwords feature is enabled.
	 *
	 * @author Lars Koudal
	 * @since  v0.0.1
	 * @access public static
	 * @global
	 * @return mixed
	 */
	public static function application_passwords()
	{
		$return = array();

		if (!function_exists('wp_is_application_passwords_available')) {
			$return['status'] = 0;
			$return['msg'] = __('The application passwords feature is not available in your WordPress installation.', 'security-ninja');
			return $return;
		}

		if (!wp_is_application_passwords_available()) {
			$return['status'] = 10;
			$return['msg'] = __('Application passwords are not available. This is the recommended configuration.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg'] = __('Application passwords are available. Consider disabling this feature if not needed to enhance security.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * is theme/plugin editor disabled?
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function file_editor()
	{
		$return = array();

		if (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) {
			$return['status'] = 10;
			$return['msg'] = __('File editing is correctly disabled on this site.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg'] = __('File editing is not disabled on this site. It is recommended to set DISALLOW_FILE_EDIT to true in your wp-config.php file for security reasons.', 'security-ninja');
		}

		return $return;
	}

	/**
	 * check if expose_php is off
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function expose_php_check()
	{
		$return = array();

		$expose_php_setting = ini_get('expose_php');

		if ($expose_php_setting === false) {
			$return['status'] = 5; // Indicate an error or unexpected result
			$return['msg'] = __('Unable to determine the "expose_php" setting. Please check your configuration.', 'security-ninja');
		} elseif ($expose_php_setting) {
			$return['status'] = 0; // Not the recommended setting
			$return['msg'] = __('Warning: "expose_php" is enabled. It is recommended to disable "expose_php" to hide PHP version info from headers for security reasons.', 'security-ninja');
		} else {
			$return['status'] = 10; // Recommended setting
			$return['msg'] = __('"expose_php" is disabled. Your PHP version info is not exposed in headers, which is the recommended setting.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * check if allow_url_include is off
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function allow_url_include_check()
	{
		$return = array(
			'status' => 10, // Assume the recommended setting by default
			'msg' => '',
		);

		// Check if allow_url_include is enabled
		if (ini_get('allow_url_include')) {
			$return['status'] = 0; // Not OK
			$return['msg'] = __('Warning: allow_url_include is enabled. It is recommended to disable this setting for security reasons.', 'security-ninja');
		} else {
			$return['msg'] = __('allow_url_include is disabled - Recommended setting.', 'security-ninja');
		}

		return $return;
	}
	/**
	 * check if safe mode is off
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function safe_mode_check()
	{
		$return = array();
		$safeModeEnabled = ini_get('safe_mode');

		if ($safeModeEnabled === false) {
			$return['status'] = 10;
			$return['msg'] = __('Safe Mode is disabled, which is the recommended setting.', 'security-ninja');
		} elseif ($safeModeEnabled === '') {
			$return['status'] = 10;
			$return['msg'] = __('Safe Mode is not applicable in PHP versions 5.3.0 and above.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg'] = __('Safe Mode is enabled. It is recommended to disable Safe Mode if possible.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * check if anyone can register on the site
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function anyone_can_register()
	{
		$return = array();
		$can_register = get_option('users_can_register');

		// Check if the option retrieval has encountered any errors
		if (is_wp_error($can_register)) {
			$return['status'] = 5; // Error status
			$return['msg'] = __('An error occurred while checking the registration setting.', 'security-ninja');
		} elseif ($can_register) {
			$return['status'] = 0;
			$return['msg'] = __('Anyone can register on the site.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Only administrators can add new users.', 'security-ninja');
		}

		return $return;
	}

	/**
	 * check REST api is enabled
	 *
	 * @author	Unknown
	 * @since	v0.0.1
	 * @version	v1.0.0	Wednesday, December 16th, 2020.	
	 * @version	v1.0.1	Tuesday, June 11th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function rest_api_links()
	{
		$return = array();

		// Collect the priorities of REST API link outputs to determine their presence.
		$collected_prios = intval(has_action('xmlrpc_rsd_apis', 'rest_output_rsd')) +
			intval(has_action('wp_head', 'rest_output_link_wp_head')) +
			intval(has_action('template_redirect', 'rest_output_link_header'));

		if ($collected_prios > 0) {
			$return['status'] = 5;
			$return['msg'] = __('REST API links are present in the site headers, which could expose sensitive information.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('REST API links are not present in the site headers.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * check WP version
	 *
	 * @author	Unknown
	 * @since	v0.0.1
	 * @version	v1.0.0	Wednesday, December 16th, 2020.	
	 * @version	v1.0.1	Tuesday, June 11th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function ver_check()
	{
		$return = array();

		if (!function_exists('get_preferred_from_update_core')) {
			include_once ABSPATH . 'wp-admin/includes/update.php';
		}

		// Ensure wp_version_check() is called to check for the latest version.
		wp_version_check();

		// Attempt to retrieve the latest core update information.
		$latest_core_update = get_preferred_from_update_core();

		// Check for errors or if an upgrade is available.
		if (is_wp_error($latest_core_update)) {
			$return['status'] = 5;
			$return['msg'] = __('An error occurred while checking the WordPress version.', 'security-ninja');
		} elseif (isset($latest_core_update->response) && 'upgrade' === $latest_core_update->response) {
			$return['status'] = 0;
			$return['msg'] = __('A WordPress core update is available.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Your WordPress version is up to date.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * check if debug.log file is accessible.
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function debug_log_file_check()
	{
		$return = array();

		$url = trailingslashit(content_url()) . 'debug.log';

		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));
		
		$response = wp_remote_get(
				$url,
				array(
						'redirection' => 0,
						'sslverify'   => !$is_local,
				)
		);

		if (is_wp_error($response)) {
			$return['status'] = 5;
			$return['msg'] = __('An error occurred while checking the debug.log file.', 'security-ninja');
		} elseif (200 === wp_remote_retrieve_response_code($response)) {
			$return['status'] = 0;
			$return['msg'] = __('The debug.log file is accessible.', 'security-ninja');
		} elseif (404 === wp_remote_retrieve_response_code($response)) {
			$return['status'] = 10;
			$return['msg'] = __('The debug.log file does not exist or is not accessible.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Unexpected HTTP response code received.', 'security-ninja');
		}

		return $return;
	}





	/**
	 * core updates should be enabled onlz for minor updates
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function core_updates_check()
	{
		$return = array();

		// Check if automatic updates are explicitly enabled or disabled
		if (defined('WP_AUTO_UPDATE_CORE')) {
			if (WP_AUTO_UPDATE_CORE === false) {
				$return['status'] = 0;
				$return['msg'] = __('Automatic core updates are explicitly disabled.', 'security-ninja');
			} elseif (WP_AUTO_UPDATE_CORE === true || WP_AUTO_UPDATE_CORE === 'minor') {
				$return['status'] = 10;
				$return['msg'] = __('Automatic core updates are enabled.', 'security-ninja');
			} else {
				$return['status'] = 0;
				$return['msg'] = __('Automatic core updates setting is unrecognized.', 'security-ninja');
			}
			return $return;
		}

		// Check if the automatic updater is disabled
		if (defined('AUTOMATIC_UPDATER_DISABLED') && AUTOMATIC_UPDATER_DISABLED) {
			$return['status'] = 0;
			$return['msg'] = __('Automatic updates are disabled by AUTOMATIC_UPDATER_DISABLED.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Automatic updates are not explicitly disabled.', 'security-ninja');
		}

		return $return;
	}




	/**
	 * check if certain username exists
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @param   string $username Default: 'admin'
	 * @return  mixed
	 */
	public static function user_exists($username = 'admin')
	{
		$return = array();

		if (username_exists($username)) {
			$return['status'] = 0;
			$return['msg'] = sprintf(__('User "%s" exists.', 'security-ninja'), $username);
		} else {
			$return['status'] = 10;
			$return['msg'] = sprintf(__('User "%s" does not exist.', 'security-ninja'), $username);
		}

		return $return;
	}




	/**
	 * check if plugins are up to date
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function plugins_ver_check()
	{
		$return = array();

		// Force a plugin update check
		wp_update_plugins();

		// Retrieve the updated plugin update information
		$current = get_site_transient('update_plugins');

		// Count the number of plugins with updates available
		$plugin_update_cnt = isset($current->response) && is_array($current->response) ? count($current->response) : 0;

		// Construct the message based on the number of updates available
		if ($plugin_update_cnt > 0) {
			$return['status'] = 0;
			$return['msg'] = sprintf(_n('There is %s plugin update available.', 'There are %s plugin updates available.', $plugin_update_cnt, 'security-ninja'), number_format_i18n($plugin_update_cnt));
		} else {
			$return['status'] = 10;
			$return['msg'] = __('All plugins are up to date.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * check if there are deactivated plugins
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function deactivated_plugins()
	{
		$return = array();

		$all_plugins = get_plugins();
		$active_plugins = get_option('active_plugins', array());

		// For multisite, merge network activated plugins
		$network_active_plugins = is_multisite() ? array_keys(get_site_option('active_sitewide_plugins', array())) : array();
		$active_plugins = array_unique(array_merge($active_plugins, $network_active_plugins));

		// Calculate deactivated plugins
		$deactivated_plugins_count = count($all_plugins) - count($active_plugins);

		// Messages
		$total_plugins_text = sprintf(_n('There is %s plugin in total.', 'There are %s plugins in total.', count($all_plugins), 'security-ninja'), number_format_i18n(count($all_plugins)));
		$active_plugins_text = sprintf(_n('%s is active.', '%s are active.', count($active_plugins), 'security-ninja'), number_format_i18n(count($active_plugins)));
		$deactivated_plugins_text = sprintf(_n('%s is deactivated.', '%s are deactivated.', $deactivated_plugins_count, 'security-ninja'), number_format_i18n($deactivated_plugins_count));

		// Construct message based on site type
		if (is_multisite()) {
			$network_active_text = sprintf(_n('%s is network activated.', '%s are network activated.', count($network_active_plugins), 'security-ninja'), number_format_i18n(count($network_active_plugins)));
			$site_active_plugins_count = count(array_diff($active_plugins, $network_active_plugins));
			$site_active_text = sprintf(_n('%s is activated on this site.', '%s are activated on this site.', $site_active_plugins_count, 'security-ninja'), number_format_i18n($site_active_plugins_count));
			$return['msg'] = implode(' ', array($total_plugins_text, $active_plugins_text, $network_active_text, $site_active_text, $deactivated_plugins_text));
		} else {
			$return['msg'] = implode(' ', array($total_plugins_text, $active_plugins_text, $deactivated_plugins_text));
		}

		// Status based on deactivated plugins count
		$return['status'] = $deactivated_plugins_count > 0 ? 0 : 10;

		return $return;
	}






	/**
	 * check if there are deactivated themes
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @version v1.0.1  Monday, February 28th, 2022.
	 * @access  public static
	 * @return  mixed
	 */
	public static function deactivated_themes()
	{
		$return = array();
		$all_themes = wp_get_themes();
		$wp_themes_to_keep = array(
			'twentytwentyfour',
			'twentytwentythree',
			'twentytwentytwo',
			'twentytwentyone',
			'twentytwenty',
			'twentynineteen',
			'twentyseventeen',
			'twentysixteen',
			'twentyfifteen',
			'twentyfourteen',
			'twentythirteen',
			'twentytwelve',
			'twentyeleven',
			'twentyten',
		);

		$get_template = get_template();
		$get_stylesheet = get_stylesheet();

		unset($all_themes[$get_template], $all_themes[$get_stylesheet]);

		$newest_wp_found = false;
		foreach ($wp_themes_to_keep as $theme_slug) {
			if (!$newest_wp_found && isset($all_themes[$theme_slug])) {
				unset($all_themes[$theme_slug]);
				$newest_wp_found = true;
			}
		}

		$themes_to_remove = array_diff_key($all_themes, array_flip($wp_themes_to_keep));
		$theme_names = array_map(function ($theme) {
			return $theme->get('Name');
		}, $themes_to_remove);

		if (count($themes_to_remove) > 0) {
			$return['status'] = 0;
			$return['msg'] = sprintf(__('Safe to remove %d themes: %s', 'security-ninja'), count($themes_to_remove), implode(', ', $theme_names));
		} else {
			$return['status'] = 10;
			$return['msg'] = __('All unnecessary themes are already removed.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * check themes versions
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function themes_ver_check()
	{
		$return = array();

		// Attempt to retrieve the current theme updates
		$current = get_site_transient('update_themes');

		if (!is_object($current)) {
			$current = new \stdClass();
		}

		// Force a theme update check
		wp_update_themes();

		// Retrieve the updated transient
		$current = get_site_transient('update_themes');

		if (isset($current->response) && is_array($current->response)) {
			$theme_update_cnt = count($current->response);
		} else {
			$theme_update_cnt = 0;
		}

		if ($theme_update_cnt > 0) {
			$return['status'] = 0;
			$return['msg'] = sprintf(__('There are %d themes with available updates.', 'security-ninja'), $theme_update_cnt);
		} else {
			$return['status'] = 10;
			$return['msg'] = __('All themes are up to date.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * check DB table prefix
	 *
	 * @author	Unknown
	 * @author	Lars Koudal
	 * @since	v0.0.1
	 * @version	v1.0.0	Wednesday, December 16th, 2020.	
	 * @version	v1.0.1	Monday, June 10th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function db_table_prefix_check()
	{
		global $wpdb;
		$return = array();

		if ('wp_' === $wpdb->prefix || 'wordpress_' === $wpdb->prefix || 'wp3_' === $wpdb->prefix) {
			$return['status'] = 0;
			$return['msg'] = __('Using a default database prefix is a security risk.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Your database prefix is customized. This is the recommended configuration.', 'security-ninja');
		}

		return $return;
	}

	/**
	 * check if global WP debugging is enabled
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function debug_check()
	{
		$return = array();

		if (defined('WP_DEBUG') && WP_DEBUG) {
			$return['status'] = 0;
			$return['msg'] = __('WP_DEBUG is enabled. While this is helpful for development, it should be disabled on a live site.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('WP_DEBUG is disabled. This is the recommended configuration for production sites.', 'security-ninja');
		}

		return $return;
	}

	/**
	 * check if global WP JS debugging is enabled
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function script_debug_check()
	{
		$return = array();

		if (defined('SCRIPT_DEBUG') && SCRIPT_DEBUG) {
			$return['status'] = 0;
			$return['msg'] = __('SCRIPT_DEBUG is enabled. While this is helpful for development, it should be disabled on a live site to improve performance and security.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('SCRIPT_DEBUG is disabled. This is the recommended configuration for production sites.', 'security-ninja');
		}

		return $return;
	}

	/**
	 * check if DB debugging is enabled
	 *
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Wednesday, December 16th, 2020.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function db_debug_check()
	{
		global $wpdb;
		$return = array();

		if (true === $wpdb->show_errors) {
			$return['status'] = 0;
			$return['msg'] = __('Database debugging is enabled. This can reveal sensitive information and is a security risk.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Database debugging is disabled. This is the recommended configuration.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * Check if wp-config.php has the right chmod
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function config_chmod()
	{
		$return = array();
		include_once ABSPATH . 'wp-admin/includes/file.php';

		WP_Filesystem();
		global $wp_filesystem;

		$tested_file = ABSPATH . 'wp-config.php';
		if (!file_exists($tested_file)) {
			// Move up one folder if wp-config.php is not in the ABSPATH directory
			$tested_file = trailingslashit(dirname(ABSPATH)) . 'wp-config.php';
		}

		$mode = $wp_filesystem->getchmod($tested_file);

		$return['details'] = 'Tested file: ' . $tested_file;

		$good_modes = array('400', '440', '0400', '0440', '660', '0660', '664', '0664');

		if (!$mode) {
			$return['status'] = 5;
			$return['msg'] = __('Unable to determine the file permissions.', 'security-ninja');
		} elseif (!in_array($mode, $good_modes, true)) {
			$return['status'] = 0;
			$return['msg'] = sprintf(__('Current file permissions are %s, which are not secure.', 'security-ninja'), $mode);
		} else {
			$return['status'] = 10;
			$return['msg'] = sprintf(__('Current file permissions are %s. This is a secure configuration.', 'security-ninja'), $mode);
		}

		return $return;
	}





	/**
	 * check for unnecessary information on failed login
	 *
	 * @author  Lars Koudal
	 * @author  Unknown
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @version v1.0.1  Saturday, February 4th, 2023.
	 * @access  public static
	 * @return  mixed
	 */
	public static function check_failed_login_info()
	{
		$return = array();

		$params = array(
			'log' => 'sn-test_3453344355',
			'pwd' => 'sn-test_2344323335',
		);

		if (!class_exists('WP_Http')) {
			include_once ABSPATH . WPINC . '/class-http.php';
		}


		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$http     = new \WP_Http();
		$response = $http->request(
			wp_login_url(),
			array(
				'method'      => 'POST',
				'body'        => $params,
				'redirection' => 0,
				'timeout'     => 45,
				'sslverify'   => !$is_local,
			)
		);

		if (is_wp_error($response)) {
			$return['status'] = 0;
			$return['msg']    = __('Failed to make a request to the login page.', 'security-ninja');
		} elseif (isset($response['body']) && stripos($response['body'], 'invalid username') !== false) {
			$return['status'] = 0;
			$return['msg']    = __('Failed login detected with the provided test credentials.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg']    = __('No failed login detected with the provided test credentials.', 'security-ninja');
		}

		return $return;
	}





	/**
	 * helper function
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @param   mixed $username
	 * @param   mixed $password
	 * @return  void
	 */
	public static function try_login($username, $password)
	{
		$user = apply_filters('authenticate', null, $username, $password);

		if (isset($user->ID) && !empty($user->ID)) {
			return true;
		} else {
			return false;
		}
	}





	/**
	 * bruteforce user login
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function bruteforce_login()
	{
		$return = array();
		$max_users_attack = 5;
		$passwords_file_path = WF_SN_PLUGIN_DIR . 'includes/brute-force-dictionary.txt';

		// Check if the dictionary file exists and is readable
		if (!file_exists($passwords_file_path) || !is_readable($passwords_file_path)) {
			$return['status'] = 0;
			$return['msg']    = __('The brute-force dictionary file is missing or not readable.', 'security-ninja');
			return $return;
		}

		$passwords = file($passwords_file_path, FILE_IGNORE_NEW_LINES);

		$bad_usernames = array();

		if (!$max_users_attack) {
			$return['status'] = 5;
			$return['msg']    = __('Maximum users attack value is not set.', 'security-ninja');
			return $return;
		}

		$roles = array('administrator', 'editor', 'author', 'contributor', 'subscriber');
		$users = array();

		foreach ($roles as $role) {
			$users = array_merge($users, get_users(array('role' => $role)));
			if (count($users) >= $max_users_attack) {
				break;
			}
		}

		$i = 0;
		foreach ($users as $user) {
			if (++$i > $max_users_attack) {
				break;
			}

			$passwords[] = $user->user_login; // Adding username to the list of passwords to check for simple password

			foreach ($passwords as $password) {
				if (self::try_login($user->user_login, $password)) {
					$bad_usernames[] = $user->user_login;
					break;
				}
			}
		}

		if (empty($bad_usernames)) {
			$return['status'] = 10;
			$return['msg']    = __('No vulnerable accounts found.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg']    = sprintf(__('Vulnerable accounts: %s', 'security-ninja'), implode(', ', $bad_usernames));
		}

		return $return;
	}


	/**
	 * Test for Strict-Transport-Security in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function strict_transport_security() {
    $return = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

    // Make a remote request to the home URL with a random query parameter
    $response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
        array(
            'timeout'     => 25,
            'redirection' => 2,
						'sslverify'   => !$is_local,

        )
    );

    // Check for errors in the response
    if ( is_wp_error( $response ) ) {
        $error_message = $response->get_error_message();
        $return['status'] = 0;
        $return['msg']    = sprintf( esc_html__( 'Failed to retrieve the site headers. Error: %s', 'security-ninja' ), esc_html( $error_message ) );
        return $return;
    }

    // Access the headers directly from the response array
    $raw_headers = isset( $response['headers'] ) ? $response['headers'] : array();

    // Convert headers to an array and make them case-insensitive
    if (is_object($raw_headers))	{
        $headers = $raw_headers->getAll();
    } else {
        $headers = (array) $raw_headers;
    }

    // Convert headers to lower case keys
    $headers = array_change_key_case( $headers, CASE_LOWER );

    // Check for the Strict-Transport-Security header
    if ( isset( $headers['strict-transport-security'] ) ) {
        $hsts_values = $headers['strict-transport-security'];
        if ( is_array( $hsts_values ) ) {
            $return['status'] = 0;
            $return['msg']    = __( 'Error, multiple Strict-Transport-Security headers found. You should only have one.', 'security-ninja' );
        } else {
            $return['status']  = 10;
            $return['msg']     = __( 'Great, Strict-Transport-Security has been set.', 'security-ninja' );
            $return['details'] = '"' . esc_html( $hsts_values ) . '"';
        }
    } else {
        $total_headers = count( $headers );
        $return['status'] = 0;
        $return['msg']    = sprintf( __( 'Strict-Transport-Security header is not set. Detected %d headers in total. Ensure your server is configured to send the HSTS header.', 'security-ninja' ), $total_headers );
    }

    return $return;
}



	/**
	 * Test for Content Security Policy in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function referrer_policy()
	{
		$result = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,
				)
		);

		if (is_wp_error($response)) {
			$error_message = $response->get_error_message();
			$return['status'] = 0;
			$return['msg']    = sprintf(esc_html__('Failed to retrieve the site headers. Error: %s', 'security-ninja'), esc_html($error_message));
			return $return;
		}

   // Access the headers directly from the response array
	 $raw_headers = isset($response['headers']) ? $response['headers'] : array();

	 // Convert headers to an array and make them case-insensitive
	 if (is_object($raw_headers)) {
			 $headers = $raw_headers->getAll();
	 } else {
			 $headers = (array) $raw_headers;
	 }

	 $headers = array_change_key_case($headers, CASE_LOWER); // Convert headers to lowercase

		if (isset($headers['referrer-policy'])) {
			$referrer_policy_values = $headers['referrer-policy'];
			if (is_array($referrer_policy_values)) {
				$result['status'] = 0;
				$result['msg']    = esc_html__('Error, multiple Referrer-Policy headers found. You should only have one.', 'security-ninja');
			} else {
				$result['status']  = 10;
				$result['msg']     = esc_html__('Great, Referrer-Policy has been set.', 'security-ninja');
				$result['details'] = '"' . esc_html($referrer_policy_values) . '"';
			}
		} else {
			$total_headers = count($headers);
			$result['status'] = 0;
			$result['msg']    = sprintf(__('Referrer-Policy header is not set. Detected %d headers in total.', 'security-ninja'), $total_headers);
		}

		return $result;
	}


	/**
	 * Test for Feature Policy in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function feature_policy()
	{
		$result = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,

			)
		);

		if (is_wp_error($response)) {
			$error_message = $response->get_error_message();
			$return['status'] = 0;
			$return['msg']    = sprintf(esc_html__('Failed to retrieve the site headers. Error: %s', 'security-ninja'), esc_html($error_message));
			return $return;
		}

   // Access the headers directly from the response array
	 $raw_headers = isset($response['headers']) ? $response['headers'] : array();

	 // Convert headers to an array and make them case-insensitive
	 if (is_object($raw_headers)) {
			 $headers = $raw_headers->getAll();
	 } else {
			 $headers = (array) $raw_headers;
	 }

	 $headers = array_change_key_case($headers, CASE_LOWER); // Convert headers to lowercase

		if (isset($headers['permissions-policy'])) {
			if (is_array($headers['permissions-policy'])) {
				$result['status'] = 0;
				$result['msg']    = esc_html__('Error, multiple Permissions-Policy headers found. You should only have one.', 'security-ninja');
			} else {
				$result['status']  = 10;
				$result['msg']     = esc_html__('Great, Permissions-Policy has been set.', 'security-ninja');
				$result['details'] = '"' . esc_html($headers['permissions-policy']) . '"';
			}
		} else {
			$total_headers = count($headers);
			$result['status'] = 0;
			$result['msg']    = esc_html__('Permissions-Policy header is not set.', 'security-ninja') . ' ' . sprintf(esc_html__('Detected %d headers in total.', 'security-ninja'), $total_headers);
		}

		return $result;
	}


	/**
	 * Test for Content Security Policy in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function content_security_policy()
	{
		$return = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,

				)
		);

		if (is_wp_error($response)) {
			$return['status'] = 0;
			$return['msg'] = __('Failed to retrieve the home page headers.', 'security-ninja');
			return $return;
		}
   // Access the headers directly from the response array
	 $raw_headers = isset($response['headers']) ? $response['headers'] : array();

	 // Convert headers to an array and make them case-insensitive
	 if (is_object($raw_headers)) {
			 $headers = $raw_headers->getAll();
	 } else {
			 $headers = (array) $raw_headers;
	 }

	 $headers = array_change_key_case($headers, CASE_LOWER); // Convert headers to lowercase

		$csp = isset($headers['content-security-policy']) ? $headers['content-security-policy'] : false;
		$csp_ro = isset($headers['content-security-policy-report-only']) ? $headers['content-security-policy-report-only'] : false;

		if ($csp && is_array($csp)) {
			$return['status'] = 0;
			$return['msg'] = __('Multiple Content Security Policy headers found. You should only have one.', 'security-ninja');
		} elseif ($csp) {
			$return['status'] = 10;
			$return['msg'] = __('Great, Content Security Policy has been set.', 'security-ninja');
			$return['details'] = '"' . implode('", "', (array) $csp) . '"';
		}

		if ($csp_ro && is_array($csp_ro)) {
			$return['status'] = 0;
			$return['msg'] .= __(' Multiple Content Security Policy Report-Only headers found. You should only have one.', 'security-ninja');
		} elseif ($csp_ro) {
			$status = $csp ? 10 : 5; // If CSP is set, maintain its status; otherwise, set to report-only status
			$return['status'] = $status;
			$return['msg'] = $csp ? $return['msg'] : __('Content Security Policy is set to report-only mode.', 'security-ninja');
			$return['details'] = isset($return['details']) ? $return['details'] . ' ' : '';
			$return['details'] .= '"' . implode('", "', (array) $csp_ro) . '"';
		}

		if (!$csp && !$csp_ro) {
			$total_headers = count($headers);
			$return['status'] = 0;
			$return['msg']    = sprintf(__('Content-Security-Policy header is not set. Detected %d headers in total.', 'security-ninja'), $total_headers);
		}

		return $return;
	}



	/**
	 * Test for X-Frame-Options in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function x_frame_options()
	{
		$return_array = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,
			)
		);

		if (is_wp_error($response)) {
			$error_message = $response->get_error_message();
			$return_array['status'] = 0;
			$return_array['msg']    = sprintf(esc_html__('Failed to retrieve the site headers. Error: %s', 'security-ninja'), esc_html($error_message));
			return $return_array;
		}

   // Access the headers directly from the response array
	 $raw_headers = isset($response['headers']) ? $response['headers'] : array();

	 // Convert headers to an array and make them case-insensitive
	 if (is_object($raw_headers)) {
			 $headers = $raw_headers->getAll();
	 } else {
			 $headers = (array) $raw_headers;
	 }

	 $headers = array_change_key_case($headers, CASE_LOWER); // Convert headers to lowercase

		if (isset($headers['x-frame-options'])) {
			$x_frame_options = $headers['x-frame-options'];
			if (is_array($x_frame_options)) {
				// Header is set multiple times
				$return_array['status'] = 0;
				$return_array['msg'] = __('X-Frame-Options header is set multiple times. This should be set only once.', 'security-ninja');
				$return_array['details'] = '"' . implode('", "', $x_frame_options) . '"';
			} else {
				$return_array['status'] = 10;
				$return_array['msg'] = __('X-Frame-Options header is properly set.', 'security-ninja');
				$return_array['details'] = '"' . $x_frame_options . '"';
			}
		} else {
			$total_headers = count($headers);
			$return_array['status'] = 0;
			$return_array['msg']    = sprintf(__('X-Frame-Options header is not set. Detected %d headers in total. This can make your site vulnerable to clickjacking attacks.', 'security-ninja'), $total_headers);
		}

		return $return_array;
	}





	/**
	 * Test for X-Content-Type-Options in http header
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function x_content_type_options()
	{
		$return = array();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$response = wp_remote_get(
			add_query_arg('secnin-test', rand(), get_home_url()),
			array(
				'timeout'     => 25,
				'redirection' => 2,
				'sslverify'   => !$is_local,
			)
		);

		if (is_wp_error($response)) {
			$error_message = $response->get_error_message();
			$return['status'] = 0;
			$return['msg']    = sprintf(esc_html__('Failed to retrieve the site headers. Error: %s', 'security-ninja'), esc_html($error_message));
			return $return;
		}

   // Access the headers directly from the response array
	 $raw_headers = isset($response['headers']) ? $response['headers'] : array();

	 // Convert headers to an array and make them case-insensitive
	 if (is_object($raw_headers)) {
			 $headers = $raw_headers->getAll();
	 } else {
			 $headers = (array) $raw_headers;
	 }

	 $headers = array_change_key_case($headers, CASE_LOWER); // Convert headers to lowercase


		if (isset($headers['x-content-type-options'])) {
			$x_content_type_options = $headers['x-content-type-options'];
			if (is_array($x_content_type_options)) {
				// Header is set multiple times
				$return['status'] = 0;
				$return['msg'] = __('X-Content-Type-Options header is set multiple times. This should be set only once.', 'security-ninja');
				$return['details'] = '"' . implode('", "', $x_content_type_options) . '"';
			} else {
				$return['status'] = 10;
				$return['msg'] = __('X-Content-Type-Options header is properly set.', 'security-ninja');
				$return['details'] = '"' . $x_content_type_options . '"';
			}
		} else {
			$total_headers = count($headers);
			$return['status'] = 0;
			$return['msg']    = sprintf(__('X-Content-Type-Options header is not set. Detected %d headers in total. This can make your site vulnerable to MIME type sniffing attacks.', 'security-ninja'), $total_headers);
		}

		return $return;
	}

	/**
	 * Check if PHP headers contain sensitive information.
	 *
	 * @since   0.0.1
	 * @version 1.0.2  Tuesday, April 30th, 2024.
	 *
	 * @return array Test result with status and message.
	 */
	public static function php_headers()
	{
		$return = array(
			'status' => 10,
			'msg'    => __('Great, no sensitive information exposed in headers.', 'security-ninja')
		);

		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));
		
		$response = wp_remote_get(
			add_query_arg('secnin-test', wp_rand(), home_url()),
			array(
				'timeout'     => 30,
				'redirection' => 2,
				'sslverify'   => !$is_local,
			)
		);

		if (is_wp_error($response)) {
			$return['status'] = 0;
			$return['msg']    = sprintf(__('Error: Unable to get the response. %s', 'security-ninja'), $response->get_error_message());
			return $return;
		}

		if (wp_remote_retrieve_response_code($response) !== 200) {
			$return['status'] = 0;
			$return['msg']    = sprintf(__('Error: Unexpected response code: %d', 'security-ninja'), wp_remote_retrieve_response_code($response));
			return $return;
		}

		$raw_headers = wp_remote_retrieve_headers($response);
		$headers = array();

		if (is_object($raw_headers)) {
			$headers = $raw_headers->getAll();
		} elseif (is_array($raw_headers)) {
			$headers = $raw_headers;
		}

		$headers = array_change_key_case($headers, CASE_LOWER);

		$php_version = phpversion();
		$sensitive_headers = array('server', 'x-powered-by', 'x-debug-token', 'x-debug-token-link');
		$sensitive_found = false;
		$sensitive_details = array();

		foreach ($headers as $header_name => $header_value) {
			if (in_array(strtolower($header_name), $sensitive_headers, true)) {
				if (is_array($header_value)) {
					$header_value = implode(', ', $header_value);
				}
				if (stripos($header_value, 'php') !== false || 
					stripos($header_value, $php_version) !== false || 
					stripos($header_value, 'debug') !== false) {
					$sensitive_found = true;
					$sensitive_details[] = $header_name . ': ' . $header_value;
				}
			}
		}

		if ($sensitive_found) {
			$return['status'] = 0;
			$return['msg']    = sprintf(__('Sensitive information exposed in headers: %s', 'security-ninja'), implode('; ', $sensitive_details));
		}

		return $return;
	}





	/**
	 * check for WP version in meta tags
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function wp_header_meta()
	{
		$return = array();

		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));
		
		$response = wp_remote_get(
				add_query_arg('secnin-test', rand(), get_home_url()),
				array(
						'timeout'     => 25,
						'redirection' => 2,
						'sslverify'   => !$is_local,
				)
		);
		if (is_wp_error($response)) {
			$error_message = $response->get_error_message();
			$return['status'] = 0;
			$return['msg']    = sprintf(esc_html__('Failed to retrieve the site headers. Error: %s', 'security-ninja'), esc_html($error_message));
			return $return;
		}

		$html = wp_remote_retrieve_body($response);

		if ($html) {
			$return['status'] = 10;
			// Extract content in <head> tags
			$start = strpos($html, '<head');
			$end   = strpos($html, '</head>', $start);
			$html  = substr($html, $start, $end - $start + strlen('</head>'));
			// Find all Meta Tags
			preg_match_all('#<meta([^>]*)>#si', $html, $matches);
			$meta_tags = $matches[0];

			foreach ($meta_tags as $meta_tag) {
				if (
					stripos($meta_tag, 'generator') !== false
					&& stripos($meta_tag, get_bloginfo('version')) !== false
				) {
					$return['status'] = 0;
					$return['msg'] = __('The WordPress version is exposed in the meta generator tag, which is a security risk.', 'security-ninja');
					break;
				}
			}

			if ($return['status'] === 10) {
				$return['msg'] = __('The WordPress version is not exposed in the meta generator tag.', 'security-ninja');
			}
		} else {
			// Error
			$return['status'] = 5;
			$return['msg'] = __('Failed to retrieve the site content.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * compare WP Blog Url with WP Site Url
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function blog_site_url_check()
	{
		$return = array();

		$site_url = home_url(); // Retrieves the URL for the site
		$wp_url   = site_url(); // Retrieves the URL for the WordPress installation

		if ($site_url === $wp_url) {
			$return['status'] = 10;
			$return['msg']    = __('The Site Address (URL) and WordPress Address (URL) are the same.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg']    = __('The Site Address (URL) and WordPress Address (URL) are different.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * brute force attack on password
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @param   mixed $password
	 * @return  void
	 */
	public static function dictionary_attack($password)
	{
		$dictionary = file(WF_SN_PLUGIN_DIR . 'includes/brute-force-dictionary.txt', FILE_IGNORE_NEW_LINES);

		if (in_array($password, $dictionary, true)) {
			return true;
		} else {
			return false;
		}
	}



	/**
	 * check database password
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function db_password_check()
	{
		$return = array();
		$password = DB_PASSWORD;

		if (empty($password)) {
			$return['status'] = 0;
			$return['msg']    = __('The database password is empty.', 'security-ninja');
		} elseif (self::dictionary_attack($password)) {
			$return['status'] = 0;
			$return['msg']    = __('The database password is a simple word from the dictionary.', 'security-ninja');
		} elseif (strlen($password) < 6) {
			$return['status'] = 0;
			$return['msg']    = sprintf(__('The database password length is only %d characters.', 'security-ninja'), strlen($password));
		} elseif (count(count_chars($password, 1)) < 5) {
			$return['status'] = 0;
			$return['msg']    = __('The database password is too simple.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg']    = __('The database password is strong.', 'security-ninja');
		}

		return $return;
	}


	/**
	 * unique config keys check
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function salt_keys_check()
	{
		$return = array();
		$ok = true;
		$bad_keys = array(); // Initialize the array to store keys that are not set properly
		$keys = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		foreach ($keys as $key) {
			if (defined($key)) {
				$constant = constant($key);
				if ('put your unique phrase here' === trim($constant) || strlen($constant) < 50) {
					$bad_keys[] = $key;
					$ok = false;
				}
			} else {
				// If the key is not defined, it's considered bad
				$bad_keys[] = $key;
				$ok = false;
			}
		} // foreach

		if ($ok) {
			$return['status'] = 10;
			$return['msg'] = __('All security keys and salts are properly set.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg'] = sprintf(
				__('The following keys are not properly set: %s. Please update them for enhanced security.', 'security-ninja'),
				implode(', ', $bad_keys)
			);
		}

		return $return;
	}




	/**
	 * check if wp-config.php has the right chmod
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function salt_keys_age_check()
	{
		$return = array();

		// Define the path for wp-config.php
		$wp_config_path = file_exists(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php' : ABSPATH . '../wp-config.php';

		// Check if wp-config.php exists in the defined path
		if (!file_exists($wp_config_path)) {
			$return['status'] = 5;
			$return['msg']    = __('Unable to locate wp-config.php.', 'security-ninja');
			return $return;
		}

		// Get the last modification time of wp-config.php
		$age = filemtime($wp_config_path);

		// Check if there was an error retrieving the file modification time
		if (false === $age) {
			$return['status'] = 5;
			$return['msg']    = __('Failed to retrieve the last modification time of wp-config.php.', 'security-ninja');
			return $return;
		}

		// Calculate the difference in time from the last modification
		$diff = time() - $age;

		// Check if the difference is greater than 93 days
		if ($diff > DAY_IN_SECONDS * 93) {
			$return['status'] = 0;
			$return['msg']    = __('The salts in wp-config.php are older than 93 days. Consider refreshing them for enhanced security.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg']    = __('The salts in wp-config.php are up to date.', 'security-ninja');
		}

		return $return;
	}



	/**
	 * uploads_browsable.
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function uploads_browsable()
	{
		$return     = array();
		$upload_dir = wp_upload_dir();
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		$args     = array(
			'method'      => 'GET',
			'timeout'     => 5,
			'redirection' => 0,
			'httpversion' => 1.0,
			'blocking'    => true,
			'headers'     => array(),
			'body'        => null,
			'cookies'     => array(),
			'sslverify'   => !$is_local,

		);
		$response = wp_remote_get(rtrim($upload_dir['baseurl'], '/') . '/?nocache=' . wp_rand(), $args);

		if (is_wp_error($response)) {
			$return['status'] = 5;
			$return['msg']    = $upload_dir['baseurl'] . '/';
		} elseif ('200' === $response['response']['code'] && false !== stripos($response['body'], 'index')) {
			$return['status'] = 0;
			$return['msg']    = $upload_dir['baseurl'] . '/';
		} else {
			$return['status'] = 10;
		}

		return $return;
	}



	/**
	 * shellshock_6271.
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function shellshock_6271()
	{
		$return = array();

		// Check if proc_open is allowed
		if (!function_exists('proc_open')) {
			$return['status'] = 10;
			$return['msg']    = __('The PHP module proc_open is not allowed. This is a good sign.', 'security-ninja');
			return $return;
		}

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$return['status'] = 10;
			$return['msg']    = __('Shellshock not applicable on Windows servers.', 'security-ninja');
			return $return;
		}

		$env = array('SHELL_SHOCK_TEST' => '() { :;}; echo VULNERABLE');

		$desc = array(
			0 => array('pipe', 'r'),
			1 => array('pipe', 'w'),
			2 => array('pipe', 'w'),
		);

		$process = @proc_open('bash -c "echo Test"', $desc, $pipes, null, $env);
		if (!is_resource($process) || !isset($pipes[1])) {
			$return['status'] = 5;
			$return['msg']    = __('Unable to execute bash command.', 'security-ninja');
			return $return;
		}
		$output = stream_get_contents($pipes[1]);
		proc_close($process);

		if (strpos($output, 'VULNERABLE') === false) {
			$return['status'] = 10;
			$return['msg']    = __('Server is not vulnerable to Shellshock.', 'security-ninja');
		} else {
			$return['status'] = 0;
			$return['msg']    = __('Server is vulnerable to Shellshock!', 'security-ninja');
		}

		return $return;
	}



	/**
	 * shellshock_7169.
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @global
	 * @return  mixed
	 */
	public static function shellshock_7169()
	{
		$return = array();

		// Check if proc_open is allowed
		if (!function_exists('proc_open')) {
			$return['status'] = 10;
			$return['msg']    = __('The PHP module proc_open is not allowed. This is a good sign.', 'security-ninja');
			return $return;
		}

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$return['status'] = 10;
			$return['msg']    = __('Shellshock not applicable on Windows servers.', 'security-ninja');
			return $return;
		}

		$desc = array(
			0 => array('pipe', 'r'),
			1 => array('pipe', 'w'),
			2 => array('pipe', 'w'),
		);

		$process = @proc_open("rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir());
		if (!is_resource($process)) {
			$return['status'] = 5;
			$return['msg']    = __('Unable to initiate a process for testing.', 'security-ninja');
			return $return;
		}

		$output = stream_get_contents($pipes[1]);
		proc_close($process);

		$current_year = gmdate('Y');

		if (trim($output) === $current_year) {
			$return['status'] = 0;
			$return['msg']    = __('Server is vulnerable to Shellshock.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg']    = __('Server is not vulnerable to Shellshock.', 'security-ninja');
		}

		return $return;
	}





	/**
	 * check if any active plugin hasn't been updated in last 365 days
	 * Note: This function stores details about plugins and stores it in an option for later use in incompatible_plugins() - This test needs to be run before incompatible_plugins().
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function old_plugins()
	{
		$return = array();
		$good = array();
		$bad = array();
		$wf_sn_active_plugins = array();
		$active_plugins = get_option('active_plugins', array());

		foreach ($active_plugins as $plugin_path) {
			if (empty($plugin_path)) {
				continue;
			}

			$plugin_slug = dirname($plugin_path);

			if (empty($plugin_slug)) {
				continue;
			}

			$response = wp_remote_get(esc_url_raw('https://api.wordpress.org/plugins/info/1.1/?action=plugin_information&request[slug]=' . $plugin_slug), array('timeout' => 5));

			if (is_wp_error($response)) {
				continue;
			}

			if (wp_remote_retrieve_response_code($response) !== 200) {
				continue;
			}

			$details = json_decode(wp_remote_retrieve_body($response), true);

			if (empty($details) || !isset($details['last_updated'])) {
				continue;
			}

			$wf_sn_active_plugins[$plugin_path] = $details;
			$updated = strtotime($details['last_updated']);

			if ($updated + 365 * DAY_IN_SECONDS < time()) {
				$bad[$plugin_path] = true;
			} else {
				$good[$plugin_path] = true;
			}
		}

		update_option('wf_sn_active_plugins', $wf_sn_active_plugins, false);

		if (empty($bad) && empty($good)) {
			$return['status'] = 5;
			$return['msg'] = __('No plugins found.', 'security-ninja');
		} elseif (empty($bad)) {
			$return['status'] = 10;
			$return['msg'] = __('All plugins are up to date.', 'security-ninja');
		} else {
			$plugins = get_plugins();
			$bad_plugins_names = array();
			foreach ($bad as $plugin_path => $tmp) {
				$bad_plugins_names[] = $plugins[$plugin_path]['Name'];
			}
			$return['msg'] = implode(', ', $bad_plugins_names);
			$return['status'] = 0;
			$return['msg'] = sprintf(__('The following plugins are outdated: %s', 'security-ninja'), $return['msg']);
		}

		return $return;
	}




	/**
	 * check if any active plugins are not compatible with current ver of WP
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Monday, January 25th, 2021.
	 * @access  public static
	 * @return  mixed
	 */
	public static function incompatible_plugins()
	{
		global $wp_version;

		$return            = array();
		$return['details'] = '';
		$good              = array();
		$bad               = array();

		$wf_sn_active_plugins = array();

		$active_plugins = get_option('active_plugins', array());

		foreach ($active_plugins as $plugin_path) {
			$plugin = explode('/', $plugin_path);

			if (empty($plugin) || empty($plugin_path)) {
				continue;
			}
			if (isset($plugin[0])) {
				$plugin = sanitize_text_field($plugin[0]);
			}

			$response = wp_remote_get('https://api.wordpress.org/plugins/info/1.1/?action=plugin_information&request%5Bslug%5D=' . urlencode($plugin), array('timeout' => 5));
			if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200 && wp_remote_retrieve_body($response)) {
				$details = wp_remote_retrieve_body($response);
				$details = json_decode($details, true);
				if (empty($details)) {
					// No details detected
					continue;
				}
				$wf_sn_active_plugins[$plugin_path] = $details;
				$updated                              = strtotime($details['last_updated']);
				if ($updated + 365 * DAY_IN_SECONDS < time()) {
					$bad[$plugin_path] = true;
				} else {
					$good[$plugin_path] = true;
				}
			}
		} // foreach active plugin

		if (empty($wf_sn_active_plugins)) {
			// No active plugins stored from the old_plugins() test
			return array('status' => 0, 'msg' => esc_html__('No active plugins to check.', 'security-ninja'));
		}

		$all_plugins = get_plugins();

		foreach ($wf_sn_active_plugins as $plugin_path => $plugin) {

			if (version_compare($wp_version, $plugin['tested'], '>')) {
				$bad[$plugin_path] = $plugin;
			} else {
				$good[$plugin_path] = $plugin;
			}
		}

		if (empty($bad)) {
			$return['status'] = 10;
			$return['msg']    = esc_html__('All plugins are compatible with your version of WordPress.', 'security-ninja');
		} else {
			$plugins = get_plugins();
			foreach ($bad as $plugin_path => $tmp) {
				$plugin_name = esc_html($tmp['name']);
				if ('' !== $return['details']) {
					// add comma if not empty
					$return['details'] .= ', ';
				}
				$return['details'] .= $plugin_name . ' <small>(' . esc_html__('tested up to', 'security-ninja') . ' ' . esc_html($tmp['tested']) . ')</small>';
			}
			$return['msg'] = esc_html__('The following plugins may not be compatible with your version of WordPress:', 'security-ninja') . ' ' . implode(', ', array_map(function ($item) {
				return esc_html($item['name']);
			}, $bad));
			$return['status'] = 0;
		}
		return $return;
	}





	/**
	 * check if PHP is up-to-date
	 *
	 * @author	Lars Koudal
	 * @author	Unknown
	 * @since	v0.0.1
	 * @version	v1.0.0	Monday, January 25th, 2021.	
	 * @version	v1.0.1	Tuesday, June 11th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function php_ver()
	{
		if (version_compare(PHP_VERSION, '5.6', '<')) {
			$return = array(
				'status' => 0,
				'msg' => sprintf(__('Current PHP version: %s. This version is outdated and not recommended for use. Please upgrade to a newer version of PHP for improved performance and security.', 'security-ninja'), PHP_VERSION)
			);
		} elseif (version_compare(PHP_VERSION, '7.4', '<=')) {
			$return = array(
				'status' => 5,
				'msg' => sprintf(__('Current PHP version: %s. This version is below the recommended PHP version. Consider upgrading to PHP 7.4 or higher for better performance and security.', 'security-ninja'), PHP_VERSION)
			);
		} else {
			$return = array(
				'status' => 10,
				'msg' => sprintf(__('Current PHP version: %s. Your PHP version is okay.', 'security-ninja'), PHP_VERSION)
			);
		}

		return $return;
	}



	/**
	 * check if mysql is up-to-date
	 *
	 * @author	Lars Koudal
	 * @author	Unknown
	 * @since	v0.0.1
	 * @version	v1.0.0	Monday, January 25th, 2021.	
	 * @version	v1.0.1	Tuesday, June 11th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function mysql_ver()
	{
			global $wpdb;
	
			$mysql_version = $wpdb->get_var('SELECT VERSION()');
	
			if (version_compare($mysql_version, '5.0', '<')) {
					$return = array(
							'status' => 0,
							'msg' => sprintf(__('Your MySQL version %s is outdated. Consider updating to a newer version for better performance and security.', 'security-ninja'), $mysql_version),
					);
			} elseif (version_compare($mysql_version, '5.6', '<')) {
					$return = array(
							'status' => 5,
							'msg' => sprintf(__('Your MySQL version %s is below the recommended version. Updating is recommended.', 'security-ninja'), $mysql_version),
					);
			} elseif (version_compare($mysql_version, '8.0', '<')) {
					$return = array(
							'status' => 7,
							'msg' => sprintf(__('Your MySQL version %s is below the optimal version. Consider updating to MySQL 8.0 or greater for best performance and security.', 'security-ninja'), $mysql_version),
					);
			} else {
					$return = array(
							'status' => 10,
							'msg' => sprintf(__('Your MySQL version %s meets the recommended version for optimal performance and security.', 'security-ninja'), $mysql_version),
					);
			}
	
			return $return;
	}

	/**
	 * Try getting usernames from user IDs
	 *
	 * @author	Lars Koudal
	 * @author	Unknown
	 * @since	v0.0.1
	 * @version	v1.0.0	Monday, January 25th, 2021.	
	 * @version	v1.0.1	Tuesday, June 11th, 2024.
	 * @access	public static
	 * @return	mixed
	 */
	public static function usernames_enumeration()
	{
		$users   = get_users('number=10');
		$success = false;
		$url     = home_url() . '/?author=';
		$args = [];
		$is_local = in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'));

		if ($is_local) {
			$args['sslverify'] = false;
			$args['redirection'] = 0;

		}

		foreach ($users as $user) {
			$response      = wp_remote_get($url . $user->ID, $args);
			$response_code = wp_remote_retrieve_response_code($response);
			if (301 === $response_code) {
				$success = true;
				break;
			}
		} // foreach

		if ($success) {
			$return['status'] = 0;
			$return['msg'] = __('Username enumeration test passed.', 'security-ninja');
		} else {
			$return['status'] = 10;
			$return['msg'] = __('Username enumeration test failed.', 'security-ninja');
		}

		return $return;
	}
}
