<?php
/**
 * Temporary-login link detection helpers.
 *
 * Free-shipping. Loaded on demand from wf_sn_cf wrappers.
 *
 * @package WPSecurityNinja\Plugin
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Cf_Temp_Login
 */
class Wf_Sn_Cf_Temp_Login {

	/**
	 * Return parameter rules only for temporary-login plugins active now.
	 *
	 * @return array
	 */
	public static function get_active_parameter_rules() {
		$default_params = array(
			array(
				'param'       => 'wtlwp_token',
				'plugin_file' => 'temporary-login-without-password/temporary-login-without-password.php',
			),
			array(
				'param'       => 'one_time_login_token',
				'plugin_file' => 'one-time-login/one-time-login.php',
			),
			array(
				'param'       => 'magic-login',
				'plugin_file' => 'magic-login/plugin.php',
				'requires'    => array( 'user_id', 'token' ),
			),
			array(
				'param'       => 'll',
				'plugin_file' => 'login-links/login-links.php',
				'prefix'      => true,
			),
		);
		$params         = apply_filters( 'securityninja_temporary_login_params', $default_params );
		if ( ! is_array( $params ) || empty( $params ) ) {
			return array();
		}
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$active = array();
		foreach ( $params as $param_config ) {
			if ( ! is_array( $param_config ) || empty( $param_config['param'] ) || empty( $param_config['plugin_file'] ) ) {
				continue;
			}
			if ( is_plugin_active( $param_config['plugin_file'] ) ) {
				$active[] = $param_config;
			}
		}
		return $active;
	}

	/**
	 * Check if current request is a temporary login link from a supported plugin.
	 *
	 * Detects temporary login links from plugins like "Temporary Login Without Password",
	 * "One Time Login", "Magic Login", and "Login Links". Only bypasses checks if the
	 * corresponding plugin is active to prevent abuse.
	 *
	 * @author  Lars Koudal
	 * @since   5.270
	 * @return  bool True if temporary login link detected and plugin is active, false otherwise.
	 */
	public static function is_temporary_login_link() {
		// Allow filter to override detection entirely
		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? $_SERVER['QUERY_STRING'] : '';

		$is_temporary_login = apply_filters( 'securityninja_is_temporary_login_link', null, $request_uri, $query_string );

		// If filter explicitly returns true/false, use that
		if ( $is_temporary_login === true ) {
			// Log detection for audit purposes
			$current_user_ip = wf_sn_cf::get_user_ip();
			wf_sn_el_modules::log_event(
				'security_ninja',
				'temporary_login_link_detected',
				__( 'Temporary login link detected (filter override)', 'security-ninja' ),
				array(
					'ip'          => $current_user_ip,
					'request_uri' => $request_uri,
				)
			);
			return true;
		}

		if ( $is_temporary_login === false ) {
			return false;
		}

		$params = self::get_active_parameter_rules();
		if ( empty( $params ) ) {
			return false;
		}

		foreach ( $params as $param_config ) {
			if ( ! is_array( $param_config ) || empty( $param_config['param'] ) || empty( $param_config['plugin_file'] ) ) {
				continue;
			}

			$param_name  = $param_config['param'];
			$plugin_file = $param_config['plugin_file'];
			$requires    = isset( $param_config['requires'] ) && is_array( $param_config['requires'] ) ? $param_config['requires'] : array();
			$is_prefix   = isset( $param_config['prefix'] ) && $param_config['prefix'] === true;

			// Check for prefix pattern (e.g., Login Links uses 'll' + token)
			if ( $is_prefix ) {
				foreach ( $_GET as $key => $value ) {
					if ( strpos( $key, $param_name ) === 0 && strlen( $key ) > strlen( $param_name ) ) {
						// Found parameter starting with prefix
						$current_user_ip = wf_sn_cf::get_user_ip();
						wf_sn_el_modules::log_event(
							'security_ninja',
							'temporary_login_link_detected',
							sprintf( __( 'Temporary login link detected: %1$s (plugin: %2$s)', 'security-ninja' ), esc_html( $key ), esc_html( $plugin_file ) ),
							array(
								'ip'     => $current_user_ip,
								'param'  => $key,
								'plugin' => $plugin_file,
							)
						);
						return true;
					}
				}
				continue;
			}

			// Check for simple parameter
			if ( isset( $_GET[ $param_name ] ) ) {
				// If requires additional parameters, check they exist
				if ( ! empty( $requires ) ) {
					$all_required_present = true;
					foreach ( $requires as $required_param ) {
						if ( ! isset( $_GET[ $required_param ] ) ) {
							$all_required_present = false;
							break;
						}
					}
					if ( ! $all_required_present ) {
						continue;
					}
				}

				// Found matching parameter and plugin is active
				$current_user_ip = wf_sn_cf::get_user_ip();
				wf_sn_el_modules::log_event(
					'security_ninja',
					'temporary_login_link_detected',
					sprintf( __( 'Temporary login link detected: %1$s (plugin: %2$s)', 'security-ninja' ), esc_html( $param_name ), esc_html( $plugin_file ) ),
					array(
						'ip'     => $current_user_ip,
						'param'  => $param_name,
						'plugin' => $plugin_file,
					)
				);
				return true;
			}
		}

		return false;
	}


/**
	 * Get the name of the temporary login plugin used in current request, if any.
	 *
	 * Returns the plugin name if a temporary login link is detected, false otherwise.
	 * Used for logging purposes to identify which plugin was used for login.
	 * Checks both current query parameters and HTTP referrer as fallback.
	 *
	 * @author  Lars Koudal
	 * @since   5.270
	 * @return  string|false Plugin name if temporary login detected, false otherwise.
	 */
	public static function get_temporary_login_plugin_name() {
		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? $_SERVER['QUERY_STRING'] : '';
		$http_referer = isset( $_SERVER['HTTP_REFERER'] ) ? $_SERVER['HTTP_REFERER'] : '';

		// Check filter override first
		$is_temporary_login = apply_filters( 'securityninja_is_temporary_login_link', null, $request_uri, $query_string );
		if ( $is_temporary_login === true ) {
			return __( 'Temporary Login (filter override)', 'security-ninja' );
		}

		if ( $is_temporary_login === false ) {
			return false;
		}

		// Map plugin files to readable names
		$plugin_names = array(
			'temporary-login-without-password/temporary-login-without-password.php' => 'Temporary Login Without Password',
			'one-time-login/one-time-login.php' => 'One Time Login',
			'magic-login/plugin.php'            => 'Magic Login',
			'login-links/login-links.php'       => 'Login Links',
		);

		$default_params = array(
			array(
				'param'       => 'wtlwp_token',
				'plugin_file' => 'temporary-login-without-password/temporary-login-without-password.php',
			),
			array(
				'param'       => 'one_time_login_token',
				'plugin_file' => 'one-time-login/one-time-login.php',
			),
			array(
				'param'       => 'magic-login',
				'plugin_file' => 'magic-login/plugin.php',
				'requires'    => array( 'user_id', 'token' ),
			),
			array(
				'param'       => 'll',
				'plugin_file' => 'login-links/login-links.php',
				'prefix'      => true,
			),
		);

		$params = apply_filters( 'securityninja_temporary_login_params', $default_params );

		if ( ! is_array( $params ) || empty( $params ) ) {
			return false;
		}

		// Ensure plugin.php is loaded for is_plugin_active()
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// Check current query parameters first
		foreach ( $params as $param_config ) {
			if ( ! is_array( $param_config ) || empty( $param_config['param'] ) || empty( $param_config['plugin_file'] ) ) {
				continue;
			}

			$param_name  = $param_config['param'];
			$plugin_file = $param_config['plugin_file'];
			$requires    = isset( $param_config['requires'] ) && is_array( $param_config['requires'] ) ? $param_config['requires'] : array();
			$is_prefix   = isset( $param_config['prefix'] ) && $param_config['prefix'] === true;

			// Check if plugin is active
			if ( ! is_plugin_active( $plugin_file ) ) {
				continue;
			}

			// Check for prefix pattern
			if ( $is_prefix ) {
				foreach ( $_GET as $key => $value ) {
					if ( strpos( $key, $param_name ) === 0 && strlen( $key ) > strlen( $param_name ) ) {
						return isset( $plugin_names[ $plugin_file ] ) ? $plugin_names[ $plugin_file ] : $plugin_file;
					}
				}
				// Also check referrer as fallback
				if ( ! empty( $http_referer ) && strpos( $http_referer, $param_name ) !== false ) {
					return isset( $plugin_names[ $plugin_file ] ) ? $plugin_names[ $plugin_file ] : $plugin_file;
				}
				continue;
			}

			// Check for simple parameter
			if ( isset( $_GET[ $param_name ] ) ) {
				// If requires additional parameters, check they exist
				if ( ! empty( $requires ) ) {
					$all_required_present = true;
					foreach ( $requires as $required_param ) {
						if ( ! isset( $_GET[ $required_param ] ) ) {
							$all_required_present = false;
							break;
						}
					}
					if ( ! $all_required_present ) {
						continue;
					}
				}

				return isset( $plugin_names[ $plugin_file ] ) ? $plugin_names[ $plugin_file ] : $plugin_file;
			}

			// Fallback: check referrer URL for parameter
			if ( ! empty( $http_referer ) ) {
				$referer_has_param = false;
				if ( $is_prefix ) {
					// For prefix patterns, check if referrer contains the prefix
					if ( strpos( $http_referer, $param_name ) !== false ) {
						$referer_has_param = true;
					}
				} elseif ( strpos( $http_referer, $param_name . '=' ) !== false || strpos( $http_referer, $param_name . '&' ) !== false ) {
					// For simple parameters, check if referrer contains param= or param&
					$referer_has_param = true;
				}

				if ( $referer_has_param ) {
					// If requires additional parameters, check referrer for them too
					if ( ! empty( $requires ) ) {
						$all_required_present = true;
						foreach ( $requires as $required_param ) {
							if ( strpos( $http_referer, $required_param . '=' ) === false && strpos( $http_referer, $required_param . '&' ) === false ) {
								$all_required_present = false;
								break;
							}
						}
						if ( ! $all_required_present ) {
							continue;
						}
					}

					return isset( $plugin_names[ $plugin_file ] ) ? $plugin_names[ $plugin_file ] : $plugin_file;
				}
			}
		}

		return false;
	}


}
