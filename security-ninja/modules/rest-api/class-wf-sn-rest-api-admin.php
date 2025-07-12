<?php

namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Security Ninja REST API Admin Class
 * 
 * Provides admin interface for REST API settings
 * 
 * @author Lars Koudal
 * @since v5.242
 * @version v1.0.0
 */
class Wf_Sn_Rest_Api_Admin {
    /**
     * Initialize the admin interface
     */
    public static function init() {
        add_action( 'admin_init', array(__CLASS__, 'handle_token_regeneration') );
        add_action( 'admin_init', array(__CLASS__, 'handle_connection_test') );
        add_action( 'admin_notices', array(__CLASS__, 'admin_notices') );
        add_action( 'admin_menu', array(__CLASS__, 'add_rest_api_submenu'), 20 );
        add_action( 'admin_head', array(__CLASS__, 'hide_rest_api_submenu_css') );
        add_action( 'load-toplevel_page_wf-sn', array(__CLASS__, 'handle_rest_api_page') );
    }

    /**
     * Handle token regeneration
     */
    public static function handle_token_regeneration() {
        if ( isset( $_POST['regenerate_token'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'regenerate_api_token' ) ) {
            if ( !current_user_can( 'manage_options' ) ) {
                wp_die( __( 'You do not have sufficient permissions to perform this action.', 'security-ninja' ) );
            }
            // Generate a new JWT token
            $new_token = self::generate_new_api_token();
            wp_redirect( add_query_arg( array(
                'token_regenerated' => '1',
                'api'               => '1',
            ), admin_url( 'admin.php?page=wf-sn-rest-api' ) ) );
            exit;
        }
    }

    /**
     * Generate a new API token
     * 
     * @return string
     */
    private static function generate_new_api_token() {
        // This method will be called from the REST API class
        return \WPSecurityNinja\Plugin\Wf_Sn_Rest_Api::generate_api_token();
    }

    /**
     * Add REST API submenu with proper URL
     */
    public static function add_rest_api_submenu() {
        add_submenu_page(
            'wf-sn',
            __( 'REST API', 'security-ninja' ),
            __( 'REST API', 'security-ninja' ),
            'manage_options',
            'wf-sn-rest-api',
            array(__CLASS__, 'render_admin_page')
        );
    }

    /**
     * Handle REST API page access
     */
    public static function handle_rest_api_page() {
        // Check if this is a REST API page request
        if ( isset( $_GET['page'] ) && $_GET['page'] === 'wf-sn-rest-api' ) {
            // Only allow access if api=1 parameter is present
            if ( !isset( $_GET['api'] ) || '1' !== $_GET['api'] ) {
                wp_die( __( 'Access denied. REST API page requires api=1 parameter.', 'security-ninja' ) );
            }
        }
    }

    /**
     * Hide the REST API submenu with CSS unless api=1 parameter is present
     */
    public static function hide_rest_api_submenu_css() {
        // Only hide if api=1 parameter is not present
        if ( !isset( $_GET['api'] ) || '1' !== $_GET['api'] ) {
            ?>
            <style type="text/css">
                /* Hide REST API submenu item */
                #adminmenu .wp-submenu a[href*="wf-sn-rest-api"] {
                    display: none !important;
                }
            </style>
            <?php 
        } else {
            // Show the menu item when api=1 is present
            ?>
            <style type="text/css">
                /* Show REST API submenu item */
                #adminmenu .wp-submenu a[href*="wf-sn-rest-api"] {
                    display: block !important;
                }
            </style>
            <?php 
        }
    }

    /**
     * Handle connection test to wpsecurityninja.com
     */
    public static function handle_connection_test() {
        if ( isset( $_POST['test_connection'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'test_api_connection' ) ) {
            if ( !current_user_can( 'manage_options' ) ) {
                wp_die( __( 'You do not have sufficient permissions to perform this action.', 'security-ninja' ) );
            }
            $result = self::test_connection_to_wpsecuritydashboard();
            // Store the result in a transient for display
            set_transient( 'wf_sn_connection_test_result', $result, 60 );
            wp_redirect( add_query_arg( array(
                'connection_tested' => '1',
                'api'               => '1',
            ), admin_url( 'admin.php?page=wf-sn-rest-api' ) ) );
            exit;
        }
    }

    /**
     * Test connection to wpsecuritydashboard.com/api/hello/
     * 
     * @return array
     */
    private static function test_connection_to_wpsecuritydashboard() {
        // Generate a fresh token for the test
        $api_token = self::generate_new_api_token();
        if ( empty( $api_token ) ) {
            return array(
                'success' => false,
                'message' => __( 'Failed to generate API token.', 'security-ninja' ),
                'details' => '',
            );
        }
        // Prepare site information for validation
        $site_info = array(
            'site_url'       => home_url(),
            'site_name'      => get_bloginfo( 'name' ),
            'wp_version'     => get_bloginfo( 'version' ),
            'plugin_version' => ( class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ? Wf_Sn::get_plugin_version() : 'Unknown' ),
            'api_token'      => $api_token,
            'timestamp'      => time(),
            'user_id'        => get_current_user_id(),
            'user_email'     => wp_get_current_user()->user_email,
        );
        // Create a simple signature for validation
        $signature = hash_hmac( 'sha256', json_encode( $site_info ), $api_token );
        $request_data = array(
            'site_info' => $site_info,
            'signature' => $signature,
            'test_type' => 'connection_validation',
        );
        // Make the request to wpsecurityninja.com
        $response = wp_remote_post( 'https://wpsecuritydashboard.com/api/hello/', array(
            'timeout'   => 30,
            'headers'   => array(
                'Content-Type'          => 'application/json',
                'User-Agent'            => 'Security-Ninja-Plugin/' . (( class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ? Wf_Sn::get_plugin_version() : 'Unknown' )),
                'X-Security-Ninja-Test' => 'true',
            ),
            'body'      => json_encode( $request_data ),
            'sslverify' => true,
        ) );
        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $response_headers = wp_remote_retrieve_headers( $response );
        if ( is_wp_error( $response ) ) {
            return array(
                'success' => false,
                'message' => __( 'Connection failed: ', 'security-ninja' ) . $response->get_error_message(),
                'details' => $response->get_error_code(),
            );
        }
        if ( $response_code !== 200 ) {
            return array(
                'success' => false,
                'message' => sprintf( __( 'Server returned error code %d', 'security-ninja' ), $response_code ),
                'details' => $response_body,
            );
        }
        // Try to parse the response
        $response_data = json_decode( $response_body, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            return array(
                'success' => false,
                'message' => __( 'Invalid response format from server', 'security-ninja' ),
                'details' => $response_body,
            );
        }
        return array(
            'success'       => true,
            'message'       => __( 'Connection test successful!', 'security-ninja' ),
            'details'       => $response_data,
            'response_code' => $response_code,
        );
    }

    /**
     * Display admin notices
     */
    public static function admin_notices() {
        // Check if we're on the REST API page and token was regenerated
        if ( isset( $_GET['page'] ) && $_GET['page'] === 'wf-sn-rest-api' && isset( $_GET['token_regenerated'] ) ) {
            echo '<div class="notice notice-success secnin-notice is-dismissible"><p>' . esc_html__( 'API token has been regenerated successfully.', 'security-ninja' ) . '</p></div>';
        }
        // Check if we're on the REST API page and connection was tested
        if ( isset( $_GET['page'] ) && $_GET['page'] === 'wf-sn-rest-api' && isset( $_GET['connection_tested'] ) ) {
            $result = get_transient( 'wf_sn_connection_test_result' );
            if ( $result ) {
                $notice_class = ( $result['success'] ? 'notice-success' : 'notice-error' );
                $message = esc_html( $result['message'] );
                if ( !empty( $result['details'] ) && is_array( $result['details'] ) ) {
                    $details = '<br><strong>' . esc_html__( 'Server Response:', 'security-ninja' ) . '</strong><br>';
                    $details .= '<pre style="background: #f9f9f9; padding: 10px; margin: 10px 0; overflow: auto;">';
                    $details .= esc_html( json_encode( $result['details'], JSON_PRETTY_PRINT ) );
                    $details .= '</pre>';
                    $message .= $details;
                } elseif ( !empty( $result['details'] ) && is_string( $result['details'] ) ) {
                    $message .= '<br><strong>' . esc_html__( 'Details:', 'security-ninja' ) . '</strong> ' . esc_html( $result['details'] );
                }
                echo '<div class="notice ' . $notice_class . ' secnin-notice is-dismissible"><p>' . $message . '</p></div>';
                delete_transient( 'wf_sn_connection_test_result' );
            }
        }
    }

    /**
     * Render the admin page
     */
    public static function render_admin_page() {
        // Access control is handled by handle_rest_api_page()
        // This method will only be called if api=1 parameter is present
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( __( 'You do not have sufficient permissions to access this page.', 'security-ninja' ) );
        }
        // Get the current API token for display
        $api_token = \WPSecurityNinja\Plugin\Wf_Sn_Rest_Api::get_current_api_token();
        ?>
        <div class="wrap">
            <?php 
        // Show the Security Ninja topbar for consistency
        if ( class_exists( __NAMESPACE__ . '\\Wf_Sn' ) ) {
            Wf_Sn::show_topbar();
        }
        ?>
            <div class="secnin_content_wrapper">
                <div class="secnin_content_cell" id="secnin_content_top">
                    <div class="notice notice-success"><p>
                        <strong><?php 
        echo esc_html__( 'Security Status:', 'security-ninja' );
        ?></strong> 
                        <?php 
        echo esc_html__( 'Your API is using the latest secure JWT-based token system.', 'security-ninja' );
        ?>
                    </p></div>
            
            <div class="sncard">
                <h2><?php 
        echo esc_html__( 'API Configuration', 'security-ninja' );
        ?></h2>
                <p><?php 
        echo esc_html__( 'The Security Ninja REST API allows external dashboards to interact with your security plugin securely.', 'security-ninja' );
        ?></p>
                
                <h3><?php 
        echo esc_html__( 'API Endpoints', 'security-ninja' );
        ?></h3>
                
                <?php 
        if ( !\WPSecurityNinja\Plugin\Wf_Sn_Rest_Api::ENABLE_ALL_ENDPOINTS ) {
            ?>
                <div class="notice notice-warning">
                    <p><strong><?php 
            echo esc_html__( 'Temporary Endpoint Restriction:', 'security-ninja' );
            ?></strong> 
                    <?php 
            echo esc_html__( 'Only the /info endpoint is currently active. Other endpoints are temporarily disabled.', 'security-ninja' );
            ?></p>
                </div>
                <?php 
        }
        ?>
                
                <table class="widefat">
                    <thead>
                        <tr>
                            <th><?php 
        echo esc_html__( 'Endpoint', 'security-ninja' );
        ?></th>
                            <th><?php 
        echo esc_html__( 'Method', 'security-ninja' );
        ?></th>
                            <th><?php 
        echo esc_html__( 'Description', 'security-ninja' );
        ?></th>
                            <th><?php 
        echo esc_html__( 'Status', 'security-ninja' );
        ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/info</code></td>
                            <td>GET</td>
                            <td><?php 
        echo esc_html__( 'Get site information and security status', 'security-ninja' );
        ?></td>
                            <td><span class="dashicons dashicons-yes" style="color: green;"></span> <?php 
        echo esc_html__( 'Active', 'security-ninja' );
        ?></td>
                        </tr>
                        <?php 
        if ( \WPSecurityNinja\Plugin\Wf_Sn_Rest_Api::ENABLE_ALL_ENDPOINTS ) {
            ?>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/scan</code></td>
                            <td>POST</td>
                            <td><?php 
            echo esc_html__( 'Trigger a security scan', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-yes" style="color: green;"></span> <?php 
            echo esc_html__( 'Active', 'security-ninja' );
            ?></td>
                        </tr>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/config</code></td>
                            <td>POST</td>
                            <td><?php 
            echo esc_html__( 'Update plugin configuration', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-yes" style="color: green;"></span> <?php 
            echo esc_html__( 'Active', 'security-ninja' );
            ?></td>
                        </tr>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/results</code></td>
                            <td>GET</td>
                            <td><?php 
            echo esc_html__( 'Get scan results', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-yes" style="color: green;"></span> <?php 
            echo esc_html__( 'Active', 'security-ninja' );
            ?></td>
                        </tr>
                        <?php 
            ?>
                        <?php 
        } else {
            ?>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/scan</code></td>
                            <td>POST</td>
                            <td><?php 
            echo esc_html__( 'Trigger a security scan', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-no" style="color: red;"></span> <?php 
            echo esc_html__( 'Temporarily Disabled', 'security-ninja' );
            ?></td>
                        </tr>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/config</code></td>
                            <td>POST</td>
                            <td><?php 
            echo esc_html__( 'Update plugin configuration', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-no" style="color: red;"></span> <?php 
            echo esc_html__( 'Temporarily Disabled', 'security-ninja' );
            ?></td>
                        </tr>
                        <tr>
                            <td><code>/wp-json/wp-security-ninja/v1/results</code></td>
                            <td>GET</td>
                            <td><?php 
            echo esc_html__( 'Get scan results', 'security-ninja' );
            ?></td>
                            <td><span class="dashicons dashicons-no" style="color: red;"></span> <?php 
            echo esc_html__( 'Temporarily Disabled', 'security-ninja' );
            ?></td>
                        </tr>
                        <?php 
            ?>
                        <?php 
        }
        ?>
                    </tbody>
                </table>

                <h3><?php 
        echo esc_html__( 'Authentication', 'security-ninja' );
        ?></h3>
                <p><?php 
        echo esc_html__( 'All API requests must include the following headers:', 'security-ninja' );
        ?></p>
                <ul>
                    <li><strong>Authorization:</strong> <code>Bearer YOUR_API_TOKEN</code></li>
                    <li><strong>X-Dashboard-Request:</strong> <code>true</code></li>
                </ul>

                <h3><?php 
        echo esc_html__( 'API Token', 'security-ninja' );
        ?></h3>
                <p><?php 
        echo esc_html__( 'Your API token for authentication:', 'security-ninja' );
        ?></p>
                <div class="api-token-container">
                    <input type="text" 
                           id="api-token" 
                           value="<?php 
        echo esc_attr( $api_token );
        ?>" 
                           readonly 
                           class="regular-text"
                           style="font-family: monospace; background-color: #f9f9f9;">
                    <button type="button" 
                            onclick="copyToClipboard('api-token')" 
                            class="button">
                        <?php 
        echo esc_html__( 'Copy Token', 'security-ninja' );
        ?>
                    </button>
                </div>

                <form method="post" style="margin-top: 10px;">
                    <?php 
        wp_nonce_field( 'regenerate_api_token' );
        ?>
                    <input type="submit" 
                           name="regenerate_token" 
                           value="<?php 
        echo esc_attr__( 'Regenerate Token', 'security-ninja' );
        ?>" 
                           class="button button-secondary"
                           onclick="return confirm('<?php 
        echo esc_js( __( 'Are you sure you want to regenerate the API token? This will invalidate the current token.', 'security-ninja' ) );
        ?>')">
                </form>

                <h3><?php 
        echo esc_html__( 'Connection Test', 'security-ninja' );
        ?></h3>
                <p><?php 
        echo esc_html__( 'Test your connection to wpsecuritydashboard.com to validate your API configuration:', 'security-ninja' );
        ?></p>
                <form method="post" style="margin-top: 10px;">
                    <?php 
        wp_nonce_field( 'test_api_connection' );
        ?>
                    <input type="submit" 
                           name="test_connection" 
                           value="<?php 
        echo esc_attr__( 'Test Connection', 'security-ninja' );
        ?>" 
                           class="button button-primary">
                </form>

                <h3><?php 
        echo esc_html__( 'Example Usage', 'security-ninja' );
        ?></h3>
                <p><?php 
        echo esc_html__( 'Here\'s an example of how to use the API:', 'security-ninja' );
        ?></p>
                <pre><code>curl -X GET "<?php 
        echo esc_url( get_rest_url( null, 'wp-security-ninja/v1/info' ) );
        ?>" \
  -H "Authorization: Bearer <?php 
        echo esc_html( $api_token );
        ?>" \
  -H "X-Dashboard-Request: true"</code></pre>

                <h3><?php 
        echo esc_html__( 'Security Notes', 'security-ninja' );
        ?></h3>
                <ul>
                    <li><?php 
        echo esc_html__( 'Keep your API token secure and do not share it publicly.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'API tokens are JWT-based with cryptographically secure signatures.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'Tokens are automatically generated and validated using HMAC-SHA256.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'All API requests are logged for security purposes (premium feature).', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'The API uses WordPress REST API security measures and input validation.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'Connection tests to wpsecuritydashboard.com include site information and a secure signature for validation.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'The connection test validates your API token and site configuration with our servers.', 'security-ninja' );
        ?></li>
                    <li><?php 
        echo esc_html__( 'Encryption keys are automatically generated and stored securely in the database.', 'security-ninja' );
        ?></li>
                </ul>
            </div>
                </div>
            </div>
        </div>

        <script>
        function copyToClipboard(elementId) {
            var element = document.getElementById(elementId);
            element.select();
            element.setSelectionRange(0, 99999); // For mobile devices
            
            try {
                document.execCommand('copy');
                alert('<?php 
        echo esc_js( __( 'API token copied to clipboard!', 'security-ninja' ) );
        ?>');
            } catch (err) {
                console.error('Failed to copy: ', err);
                alert('<?php 
        echo esc_js( __( 'Failed to copy token. Please copy it manually.', 'security-ninja' ) );
        ?>');
            }
        }
        </script>
        <?php 
    }

}

// Initialize the admin interface
Wf_Sn_Rest_Api_Admin::init();