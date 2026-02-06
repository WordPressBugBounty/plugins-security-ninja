<?php
namespace WPSecurityNinja\Plugin;

if (!defined('ABSPATH')) {
	exit;
}

define('WF_SN_SETTINGS_OPTIONS_KEY', 'wf_sn_settings');

/**
 * Class Wf_Sn_Settings
 *
 * Centralized settings module for Security Ninja plugin.
 * This module will eventually consolidate all plugin settings into a single option field.
 *
 * IMPORTANT REMINDER FOR INTEGRATION:
 * When this module is integrated and migration is activated, remember to update the
 * import/export functionality to use this centralized settings module instead of the
 * individual option keys. The import/export page should be updated to work with
 * the single 'wf_sn_settings' option key.
 *
 * @package WPSecurityNinja\Plugin
 */
class Wf_Sn_Settings
{

	/**
	 * Cached settings array
	 *
	 * @var array|null
	 */
	private static $settings = null;

	/**
	 * Valid module names
	 *
	 * @var array
	 */
	private static $valid_modules = array(
		'main',
		'whitelabel',
		'events_logger',
		'cloud_firewall',
		'vulnerabilities',
		'scheduled_scanner',
		'rest_api',
		'crypto',
		'data',
	);

	/**
	 * Initialize the settings module
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @return  void
	 */
	public static function init()
	{
		// NOTE: This module is prepared but not actively initialized yet.
		// When ready, uncomment the following line to activate:
		// self::$settings = self::get_all_settings();
	}

	/**
	 * Get all settings
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @return  array Complete settings array
	 */
	public static function get_all_settings()
	{
		if (!is_null(self::$settings)) {
			return self::$settings;
		}

		$settings = get_option(WF_SN_SETTINGS_OPTIONS_KEY, array());

		if (!is_array($settings)) {
			$settings = array();
		}

		// Merge with defaults to ensure all keys exist
		$defaults = self::get_defaults();
		$settings = self::array_merge_recursive_distinct($defaults, $settings);

		self::$settings = $settings;
		return $settings;
	}

	/**
	 * Get settings for a specific module
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module Module name
	 * @return  array|false Module settings or false if module doesn't exist
	 */
	public static function get_module_settings($module)
	{
		if (!self::validate_module($module)) {
			return false;
		}

		$all_settings = self::get_all_settings();
		return isset($all_settings[$module]) ? $all_settings[$module] : self::get_module_defaults($module);
	}

	/**
	 * Get a specific setting value
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module Module name
	 * @param   string $key    Setting key
	 * @param   mixed  $default Default value if setting doesn't exist
	 * @return  mixed Setting value or default
	 */
	public static function get_setting($module, $key, $default = null)
	{
		if (!self::validate_module($module)) {
			return $default;
		}

		$module_settings = self::get_module_settings($module);
		return isset($module_settings[$key]) ? $module_settings[$key] : $default;
	}

	/**
	 * Set a specific setting value
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module Module name
	 * @param   string $key    Setting key
	 * @param   mixed  $value  Setting value
	 * @return  bool True on success, false on failure
	 */
	public static function set_setting($module, $key, $value)
	{
		if (!self::validate_module($module)) {
			return false;
		}

		$all_settings = self::get_all_settings();
		$all_settings[$module][$key] = $value;

		return self::save_settings($all_settings);
	}

	/**
	 * Set entire module settings
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module   Module name
	 * @param   array  $settings Module settings array
	 * @return  bool True on success, false on failure
	 */
	public static function set_module_settings($module, $settings)
	{
		if (!self::validate_module($module)) {
			return false;
		}

		if (!is_array($settings)) {
			return false;
		}

		$all_settings = self::get_all_settings();
		$all_settings[$module] = $settings;

		return self::save_settings($all_settings);
	}

	/**
	 * Save settings to database
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  private static
	 * @param   array $settings Settings array to save
	 * @return  bool True on success, false on failure
	 */
	private static function save_settings($settings)
	{
		$sanitized = self::sanitize_settings($settings);
		$result = update_option(WF_SN_SETTINGS_OPTIONS_KEY, $sanitized, false);
		
		if ($result) {
			self::$settings = $sanitized;
		}
		
		return $result;
	}

	/**
	 * Get all default values
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @return  array Complete defaults array
	 */
	public static function get_defaults()
	{
		return array(
			'main' => self::get_module_defaults('main'),
			'whitelabel' => self::get_module_defaults('whitelabel'),
			'events_logger' => self::get_module_defaults('events_logger'),
			'cloud_firewall' => self::get_module_defaults('cloud_firewall'),
			'vulnerabilities' => self::get_module_defaults('vulnerabilities'),
			'scheduled_scanner' => self::get_module_defaults('scheduled_scanner'),
			'rest_api' => self::get_module_defaults('rest_api'),
			'crypto' => self::get_module_defaults('crypto'),
			'data' => self::get_module_defaults('data'),
		);
	}

	/**
	 * Get default values for a specific module
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module Module name
	 * @return  array Module defaults
	 */
	public static function get_module_defaults($module)
	{
		switch ($module) {
			case 'main':
				return array(
					'license_key' => '',
					'license_active' => false,
					'license_expires' => '',
					'license_type' => '',
					'license_hide' => false,
					'first_version' => '',
					'first_install' => '',
					'remove_settings_deactivate' => 0,
				);

			case 'whitelabel':
				return array(
					'wl_active' => '0',
					'wl_newname' => 'Security Ninja',
					'wl_newdesc' => '',
					'wl_newauthor' => '',
					'wl_newurl' => 'https://wpsecurityninja.com/',
					'wl_newiconurl' => '',
					'wl_newmenuiconurl' => '',
				);

			case 'events_logger':
				return array(
					'active' => 0,
					'retention' => '',
					'email_reports' => '',
					'email_to' => '',
					'webhook_active' => 0,
					'webhook_url' => '',
					'webhook_events' => array(),
					'webhook_firewall_events' => 0,
					'webhook_user_logins' => 0,
					'webhook_updates' => 0,
					'email_modules' => array(),
					'notify_new_admin' => 0,
					'new_admin_notification_email' => '',
					'remove_settings_deactivate' => '',
				);

			case 'cloud_firewall':
				return array(
					'active' => false,
					'globalbannetwork' => true,
					'global' => false,
					'filterqueries' => true,
					'trackvisits' => true,
					'trackvisits_howlong' => 7,
					'usecloud' => true,
					'protect_login_form' => true,
					'hide_login_errors' => true,
					'failed_login_email_warning' => false,
					'blocked_countries' => array(),
					'countryblock_loginonly' => false,
					'blacklist' => array(),
					'whitelist' => array(),
					'whitelist_managewp' => true,
					'whitelist_wprocket' => false,
					'whitelist_uptimia' => false,
					'whitelist_uptimerobot' => false,
					'max_login_attempts' => 5,
					'max_login_attempts_time' => 5,
					'bruteforce_ban_time' => 120,
					'login_msg' => 'Warning: Multiple failed login attempts will get you locked out temporarily.',
					'login_error_msg' => 'Something went wrong',
					'message' => 'You are not allowed to visit this website.',
					'redirect_url' => '',
					'blockadminlogin' => 0,
					'change_login_url' => 0,
					'new_login_url' => 'my-login',
					'unblock_url' => '',
					'2fa_enabled' => false,
					'2fa_enabled_timestamp' => '',
					'2fa_required_roles' => array('administrator', 'editor'),
					'2fa_methods' => array('app'),
					'2fa_grace_period' => 14,
					'2fa_backup_codes_enabled' => true,
					'2fa_intro' => 'Secure your account with two-factor authentication.',
					'2fa_enter_code' => 'Enter the code from your 2FA app to continue logging in.',
					'404guard_enabled' => true,
					'404guard_threshold' => 10,
					'404guard_window' => 300,
					'404guard_block_time' => 600,
					'woo_rate_limiting_enabled' => false,
					'woo_checkout_rate_limit' => 3,
					'woo_checkout_window' => 300,
					'woo_add_to_cart_limit' => 10,
					'woo_add_to_cart_window' => 60,
					'woo_order_rate_limit' => 2,
					'woo_order_window' => 600,
					'woo_coupon_protection_enabled' => false,
					'woo_coupon_failed_attempts' => 3,
					'woo_coupon_window' => 180,
					'woo_coupon_ban_time' => 900,
				);

			case 'vulnerabilities':
				return array(
					'enable_vulns' => true,
					'enable_outdated' => false,
					'enable_admin_notification' => true,
					'enable_email_notice' => false,
					'email_notice_recipient' => '',
					'ignored_plugin_slugs' => '',
				);

			case 'scheduled_scanner':
				return array(
					'main_setting' => '0',
					'scan_schedule' => 'twicedaily',
					'email_report' => 2,
					'email_to' => get_bloginfo('admin_email'),
				);

			case 'rest_api':
				return array(
					'allowed_origins' => array('https://wpsecuritydashboard.com'),
					'access_logs' => array(),
				);

			case 'crypto':
				return array(
					'encryption_key' => '',
					'site_id' => '',
				);

			case 'data':
				return array(
					'banned_ips' => array(),
					'cf_ips' => array(),
					'cf_blocked_count' => 0,
					'ms_results' => array(),
					'vu_last_update' => '',
				);

			default:
				return array();
		}
	}

	/**
	 * Sanitize settings before saving
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   array $settings Settings array to sanitize
	 * @return  array Sanitized settings array
	 */
	public static function sanitize_settings($settings)
	{
		if (!is_array($settings)) {
			return array();
		}

		$sanitized = array();

		foreach ($settings as $module => $module_settings) {
			if (!self::validate_module($module)) {
				continue;
			}

			if (!is_array($module_settings)) {
				continue;
			}

			$sanitized[$module] = array();

			foreach ($module_settings as $key => $value) {
				// Sanitize based on value type
				if (is_array($value)) {
					$sanitized[$module][$key] = array_map('sanitize_text_field', $value);
				} elseif (is_bool($value)) {
					$sanitized[$module][$key] = (bool) $value;
				} elseif (is_int($value)) {
					$sanitized[$module][$key] = intval($value);
				} elseif (is_string($value)) {
					$sanitized[$module][$key] = sanitize_text_field($value);
				} else {
					$sanitized[$module][$key] = $value;
				}
			}
		}

		return $sanitized;
	}

	/**
	 * Validate module name
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @param   string $module Module name to validate
	 * @return  bool True if valid, false otherwise
	 */
	public static function validate_module($module)
	{
		return in_array($module, self::$valid_modules, true);
	}

	/**
	 * Check if migration has been completed
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @return  bool True if migrated, false otherwise
	 */
	public static function is_migrated()
	{
		return (bool) get_option('wf_sn_settings_migrated', false);
	}

	/**
	 * Migrate settings from old option keys to new centralized structure
	 *
	 * IMPORTANT: This method is prepared but NOT activated yet.
	 * When ready to migrate, this method should be called once to convert all existing
	 * settings from individual option keys to the new centralized structure.
	 *
	 * Migration mapping:
	 * - wf_sn_options → main
	 * - wf_sn_wl → whitelabel
	 * - wf_sn_el → events_logger
	 * - wf_sn_cf → cloud_firewall
	 * - wf_sn_vu_settings_group → vulnerabilities
	 * - wf_sn_ss → scheduled_scanner
	 * - wf_sn_api_allowed_origins → rest_api.allowed_origins
	 * - wf_sn_api_access_logs → rest_api.access_logs
	 * - wf_sn_encryption_key → crypto.encryption_key
	 * - wf_sn_site_id → crypto.site_id
	 * - wf_sn_banned_ips → data.banned_ips
	 * - wf_sn_cf_ips → data.cf_ips
	 * - wf_sn_cf_blocked_count → data.cf_blocked_count
	 * - wf_sn_ms_results → data.ms_results
	 * - wf_sn_vu_last_update → data.vu_last_update
	 *
	 * After migration:
	 * - All old option keys will be deleted
	 * - Migration flag will be set to prevent re-migration
	 * - Users will experience seamless transition with no data loss
	 *
	 * REMINDER: When activating migration, also update the import/export functionality
	 * to use this centralized settings module (wf_sn_settings) instead of individual
	 * option keys. The import/export page should be updated accordingly.
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  public static
	 * @return  bool True on success, false on failure
	 */
	public static function migrate_from_old_options()
	{
		// Check if already migrated
		if (self::is_migrated()) {
			return true;
		}

		$new_settings = self::get_defaults();

		// Migrate main plugin settings
		$main_options = get_option('wf_sn_options', array());
		if (!empty($main_options) && is_array($main_options)) {
			$new_settings['main'] = array_merge($new_settings['main'], $main_options);
		}

		// Migrate whitelabel settings
		$wl_options = get_option('wf_sn_wl', array());
		if (!empty($wl_options) && is_array($wl_options)) {
			$new_settings['whitelabel'] = array_merge($new_settings['whitelabel'], $wl_options);
		}

		// Migrate events logger settings
		$el_options = get_option('wf_sn_el', array());
		if (!empty($el_options) && is_array($el_options)) {
			$new_settings['events_logger'] = array_merge($new_settings['events_logger'], $el_options);
		}

		// Migrate cloud firewall settings
		$cf_options = get_option('wf_sn_cf', array());
		if (!empty($cf_options) && is_array($cf_options)) {
			$new_settings['cloud_firewall'] = array_merge($new_settings['cloud_firewall'], $cf_options);
		}

		// Migrate vulnerabilities settings
		$vu_options = get_option('wf_sn_vu_settings_group', array());
		if (!empty($vu_options) && is_array($vu_options)) {
			$new_settings['vulnerabilities'] = array_merge($new_settings['vulnerabilities'], $vu_options);
		}

		// Migrate scheduled scanner settings
		$ss_options = get_option('wf_sn_ss', array());
		if (!empty($ss_options) && is_array($ss_options)) {
			$new_settings['scheduled_scanner'] = array_merge($new_settings['scheduled_scanner'], $ss_options);
		}

		// Migrate REST API settings
		$api_origins = get_option('wf_sn_api_allowed_origins', array());
		if (!empty($api_origins)) {
			$new_settings['rest_api']['allowed_origins'] = is_array($api_origins) ? $api_origins : array($api_origins);
		}

		$api_logs = get_option('wf_sn_api_access_logs', array());
		if (!empty($api_logs) && is_array($api_logs)) {
			$new_settings['rest_api']['access_logs'] = $api_logs;
		}

		// Migrate crypto settings
		$encryption_key = get_option('wf_sn_encryption_key', '');
		if (!empty($encryption_key)) {
			$new_settings['crypto']['encryption_key'] = $encryption_key;
		}

		$site_id = get_option('wf_sn_site_id', '');
		if (!empty($site_id)) {
			$new_settings['crypto']['site_id'] = $site_id;
		}

		// Migrate data settings
		$banned_ips = get_option('wf_sn_banned_ips', array());
		if (!empty($banned_ips) && is_array($banned_ips)) {
			$new_settings['data']['banned_ips'] = $banned_ips;
		}

		$cf_ips = get_option('wf_sn_cf_ips', array());
		if (!empty($cf_ips) && is_array($cf_ips)) {
			$new_settings['data']['cf_ips'] = $cf_ips;
		}

		$cf_blocked_count = get_option('wf_sn_cf_blocked_count', 0);
		if (!empty($cf_blocked_count)) {
			$new_settings['data']['cf_blocked_count'] = intval($cf_blocked_count);
		}

		$ms_results = get_option('wf_sn_ms_results', array());
		if (!empty($ms_results) && is_array($ms_results)) {
			$new_settings['data']['ms_results'] = $ms_results;
		}

		$vu_last_update = get_option('wf_sn_vu_last_update', '');
		if (!empty($vu_last_update)) {
			$new_settings['data']['vu_last_update'] = $vu_last_update;
		}

		// Sanitize and save new settings
		$sanitized = self::sanitize_settings($new_settings);
		$saved = update_option(WF_SN_SETTINGS_OPTIONS_KEY, $sanitized, false);

		if (!$saved) {
			return false;
		}

		// Delete old option keys
		delete_option('wf_sn_options');
		delete_option('wf_sn_wl');
		delete_option('wf_sn_el');
		delete_option('wf_sn_cf');
		delete_option('wf_sn_vu_settings_group');
		delete_option('wf_sn_ss');
		delete_option('wf_sn_api_allowed_origins');
		delete_option('wf_sn_api_access_logs');
		delete_option('wf_sn_encryption_key');
		delete_option('wf_sn_site_id');
		delete_option('wf_sn_banned_ips');
		delete_option('wf_sn_cf_ips');
		delete_option('wf_sn_cf_blocked_count');
		delete_option('wf_sn_ms_results');
		delete_option('wf_sn_vu_last_update');

		// Set migration flag
		update_option('wf_sn_settings_migrated', true, false);

		// Clear cache
		self::$settings = null;

		return true;
	}

	/**
	 * Recursive array merge that preserves distinct values
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, January 7th, 2025.
	 * @access  private static
	 * @param   array $array1 First array
	 * @param   array $array2 Second array (takes precedence)
	 * @return  array Merged array
	 */
	private static function array_merge_recursive_distinct($array1, $array2)
	{
		$merged = $array1;

		foreach ($array2 as $key => $value) {
			if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
				$merged[$key] = self::array_merge_recursive_distinct($merged[$key], $value);
			} else {
				$merged[$key] = $value;
			}
		}

		return $merged;
	}
}

// NOTE: The module is prepared but not actively initialized yet.
// When ready to use, uncomment the following line:
// add_action('plugins_loaded', array(__NAMESPACE__ . '\Wf_Sn_Settings', 'init'));

