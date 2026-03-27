<?php

namespace WPSecurityNinja\Plugin;

use wf_sn_cf;
class wf_sn_el_modules extends wf_sn_el {
    static $deleted_user = null;

    /**
     * Strip sensitive fields from raw_data so they are never stored or displayed.
     * Recursively removes credential-like keys from arrays (e.g. hook args).
     *
     * @param array|null $data Raw data array (possibly nested).
     * @return array|null Sanitized array.
     */
    private static function strip_sensitive_data( $data ) {
        $keys_to_strip = array(
            'user_pass',
            'user_activation_key',
            'password',
            'user_password',
            'passwd',
            'secret',
            'token',
            'api_key',
            'auth_key',
            'private_key',
            'consumer_secret',
            'consumer_key',
            'access_token',
            'refresh_token'
        );
        if ( !is_array( $data ) ) {
            return $data;
        }
        foreach ( $keys_to_strip as $key ) {
            unset($data[$key]);
        }
        foreach ( $data as $k => $v ) {
            if ( is_array( $v ) ) {
                $data[$k] = self::strip_sensitive_data( $v );
            }
        }
        return $data;
    }

    /**
     * Write event to database
     * @param  [type] $module                   [description]
     * @param  [type] $action                   [description]
     * @param  string $description      [description]
     * @param  [type] $raw_data             [description]
     * @param  [type] $user_id              [description]
     * @param  [type] $ip                           [description]
     * @return [integer]                            [inserted id in database]
     */
    public static function log_event(
        $module,
        $action,
        $description = '',
        $raw_data = null,
        $user_id = null,
        $ip = null
    ) {
        if ( empty( $description ) ) {
            $description = esc_html__( 'No details available.', 'security-ninja' );
        }
        global $wpdb;
        // If this is a REST request, do not attempt to determine user_id
        if ( null === $user_id ) {
            $user_id = get_current_user_id();
        }
        if ( !is_array( $description ) ) {
            $description = array($description);
        }
        if ( is_array( $raw_data ) ) {
            $raw_data = self::strip_sensitive_data( $raw_data );
        }
        if ( !$ip ) {
            $ip = call_user_func( __NAMESPACE__ . '\\Wf_sn_cf::get_user_ip' );
        }
        foreach ( $description as $desc ) {
            $ua = '';
            if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
                $ua = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
            }
            $table_name = $wpdb->prefix . 'wf_sn_el';
            $insert_result = $wpdb->insert( $table_name, array(
                'timestamp'   => current_time( 'mysql' ),
                'ip'          => $ip,
                'user_agent'  => $ua,
                'user_id'     => absint( $user_id ),
                'module'      => $module,
                'action'      => $action,
                'description' => $desc,
                'raw_data'    => serialize( $raw_data ),
            ), array(
                '%s',
                '%s',
                '%s',
                '%d',
                '%s',
                '%s',
                '%s',
                '%s'
            ) );
            if ( false === $insert_result && !empty( $wpdb->last_error ) && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
                error_log( 'Security Ninja Event Logger: insert failed – ' . $wpdb->last_error );
            }
        }
        if ( !function_exists( 'secnin_fs' ) || !is_object( secnin_fs() ) ) {
            return $wpdb->insert_id;
        }
        return $wpdb->insert_id;
    }

    /**
     * users related events
     *
     * @author  Unknown
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @version v1.0.1  Sunday, May 5th, 2024.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_users( $action_name, $params ) {
        $desc = '';
        $user_id = null;
        $raw_data = null;
        if ( $params ) {
            $raw_data = $params;
        }
        if ( !class_exists( __NAMESPACE__ . '\\Wf_sn_cf' ) ) {
            require_once WF_SN_PLUGIN_DIR . 'modules/cloud-firewall/cloud-firewall.php';
        }
        // @todo - move this out
        $raw_data['ip'] = \WPSecurityNinja\Plugin\Wf_sn_cf::get_user_ip();
        $ua_string = '';
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $ua_string = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] );
            if ( !isset( $raw_data['user_agent'] ) ) {
                $raw_data['user_agent'] = $ua_string;
            }
        }
        switch ( $action_name ) {
            case 'wp_login_failed':
                $desc = sprintf( 
                    /* translators: %s: username that failed to login */
                    esc_html__( 'Failed login attempt with username %s', 'security-ninja' ),
                    esc_html( $params[1] )
                 );
                break;
            // Successful login
            case 'set_logged_in_cookie':
                $user_id_param = ( isset( $params[4] ) ? $params[4] : null );
                $user = ( null !== $user_id_param && '' !== $user_id_param ? get_user_by( 'id', $user_id_param ) : false );
                if ( !$user || !$user->exists() ) {
                    return;
                }
                $desc = sprintf( 
                    /* translators: %s: user's display name */
                    esc_html__( '%s logged in.', 'security-ninja' ),
                    esc_html( $user->display_name )
                 );
                $user_id = $user->ID;
                $allowed_keys = array('ip', 'user_agent');
                $raw_data = array_intersect_key( $raw_data, array_flip( $allowed_keys ) );
                break;
            case 'clear_auth_cookie':
                $user = wp_get_current_user();
                if ( empty( $user ) || !$user->exists() ) {
                    return;
                }
                $desc = sprintf( 
                    /* translators: %s: user's display name */
                    esc_html__( '%s logged out.', 'security-ninja' ),
                    esc_html( $user->display_name )
                 );
                break;
            case 'user_register':
                $user = get_user_by( 'id', $params[1] );
                $desc = sprintf( 
                    /* translators: %s: user's display name */
                    esc_html__( 'New user registered - %s.', 'security-ninja' ),
                    esc_html( $user->display_name )
                 );
                break;
            case 'profile_update':
                $user = get_user_by( 'id', $params[1] );
                $desc = sprintf( 
                    /* translators: %s: user's display name */
                    esc_html__( '%s\'s profile was updated.', 'security-ninja' ),
                    esc_html( $user->display_name )
                 );
                break;
            case 'retrieve_password':
                $desc = sprintf( 
                    /* translators: %s: user's login name */
                    esc_html__( '%s\'s password was requested to be reset.', 'security-ninja' ),
                    esc_html( $params[1] )
                 );
                $user = get_user_by( 'login', $params[1] );
                break;
            case 'password_reset':
                $desc = sprintf( 
                    /* translators: %s: user's login name */
                    esc_html__( '%s\'s password was reset.', 'security-ninja' ),
                    esc_html( $params[1]->data->user_login )
                 );
                $user = get_user_by( 'login', $params[1]->data->user_login );
                break;
            case 'delete_user':
                self::$deleted_user = get_user_by( 'id', $params[1] );
                break;
            case 'deleted_user':
                if ( !self::$deleted_user ) {
                    return;
                }
                $desc = sprintf( 
                    /* translators: %s: user's display name */
                    esc_html__( '%s\'s account was deleted.', 'security-ninja' ),
                    esc_html( self::$deleted_user->display_name )
                 );
                self::$deleted_user = null;
                break;
            case 'set_user_role':
                if ( !isset( $params[3][0] ) || !$params[3][0] ) {
                    return;
                }
                $user = get_user_by( 'id', $params[1] );
                $desc = sprintf(
                    /* translators: 1: user's display name, 2: old role, 3: new role */
                    esc_html__( '%1$s\'s role was changed from %2$s to %3$s.', 'security-ninja' ),
                    esc_html( $user->display_name ),
                    esc_html( $params[3][0] ),
                    esc_html( $params[2] )
                );
                break;
            case 'add_user_role':
                $user_id = ( isset( $params[1] ) ? (int) $params[1] : 0 );
                $role = ( isset( $params[2] ) ? $params[2] : '' );
                $user = ( $user_id ? get_user_by( 'id', $user_id ) : false );
                $user_name = ( $user && $user->display_name ? $user->display_name : sprintf( 
                    /* translators: %d: user ID */
                    esc_html__( 'User #%d', 'security-ninja' ),
                    $user_id
                 ) );
                $desc = sprintf( 
                    /* translators: %1$s: role name, %2$s: user display name */
                    esc_html__( 'Role %1$s added to %2$s.', 'security-ninja' ),
                    esc_html( $role ),
                    esc_html( $user_name )
                 );
                break;
            case 'remove_user_role':
                $user_id = ( isset( $params[1] ) ? (int) $params[1] : 0 );
                $role = ( isset( $params[2] ) ? $params[2] : '' );
                $user = ( $user_id ? get_user_by( 'id', $user_id ) : false );
                $user_name = ( $user && $user->display_name ? $user->display_name : sprintf( 
                    /* translators: %d: user ID */
                    esc_html__( 'User #%d', 'security-ninja' ),
                    $user_id
                 ) );
                $desc = sprintf( 
                    /* translators: %1$s: role name, %2$s: user display name */
                    esc_html__( 'Role %1$s removed from %2$s.', 'security-ninja' ),
                    esc_html( $role ),
                    esc_html( $user_name )
                 );
                break;
            default:
                $desc = sprintf( 
                    /* translators: %s: action name */
                    esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ),
                    esc_html( $action_name )
                 );
                break;
        }
        self::log_event(
            'users',
            $action_name,
            $desc,
            $raw_data,
            $user_id
        );
    }

    /**
     * menus related events
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_menus( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'wp_create_nav_menu':
                $desc = sprintf( 
                    /* translators: %s: menu name */
                    esc_html__( 'Menu %s created.', 'security-ninja' ),
                    esc_html( $params[2]['menu-name'] )
                 );
                break;
            case 'wp_update_nav_menu':
                if ( !isset( $params[2] ) ) {
                    return;
                }
                $desc = sprintf( 
                    /* translators: %s: menu name */
                    esc_html__( 'Menu %s updated.', 'security-ninja' ),
                    esc_html( $params[2]['menu-name'] )
                 );
                break;
            case 'delete_nav_menu':
                $desc = sprintf( 
                    /* translators: %s: menu name */
                    esc_html__( 'Menu %s deleted.', 'security-ninja' ),
                    esc_html( $params[3]->name )
                 );
                break;
            default:
                $desc = sprintf( 
                    /* translators: %s: action name */
                    esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ),
                    esc_html( $action_name )
                 );
        }
        self::log_event(
            'menus',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * parse_action_file_editor.
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_file_editor( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'wp_redirect':
                if ( strpos( $params[1], 'plugin-editor.php?' ) !== false ) {
                    list( $url, $query ) = explode( '?', $params[1] );
                    $query = wp_parse_args( $query );
                    $plugin = get_plugin_data( WP_PLUGIN_DIR . '/' . sanitize_text_field( $query['file'] ) );
                    if ( empty( $plugin['Name'] ) ) {
                        return;
                    }
                    $desc = sprintf( 
                        /* translators: 1: file path, 2: plugin name */
                        esc_html__( 'File %1$s in plugin %2$s edited.', 'security-ninja' ),
                        esc_html( $query['file'] ),
                        esc_html( $plugin['Name'] )
                     );
                } elseif ( strpos( $params[1], 'theme-editor.php?' ) !== false ) {
                    list( $url, $query ) = explode( '?', $params[1] );
                    $query = wp_parse_args( $query );
                    $theme = wp_get_theme( sanitize_text_field( $query['theme'] ) );
                    if ( !$theme->exists() || $theme->errors() && 'theme_no_stylesheet' === $theme->errors()->get_error_code() ) {
                        return;
                    }
                    $desc = sprintf( 
                        /* translators: 1: file path, 2: theme name */
                        esc_html__( 'File %1$s in theme %2$s edited.', 'security-ninja' ),
                        esc_html( $query['file'] ),
                        esc_html( $theme->get( 'Name' ) )
                     );
                } else {
                    return;
                }
                break;
            default:
                $desc = sprintf( 
                    /* translators: %s: action name */
                    esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ),
                    esc_html( $action_name )
                 );
        }
        self::log_event(
            'file_editor',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * taxonomies related events
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_taxonomies( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        global $wp_taxonomies;
        switch ( $action_name ) {
            case 'created_term':
                $term = get_term( $params[1], sanitize_text_field( $params[3] ) );
                if ( $term && !is_wp_error( $term ) ) {
                    $desc = sprintf( 
                        /* translators: 1: term name, 2: taxonomy label */
                        esc_html__( '%1$s in %2$s created.', 'security-ninja' ),
                        esc_html( $term->name ),
                        esc_html( $wp_taxonomies[$params[3]]->labels->name )
                     );
                }
                break;
            case 'delete_term':
                if ( $params[4] && !is_wp_error( $params[4] ) ) {
                    $desc = sprintf( 
                        /* translators: 1: term name, 2: taxonomy label */
                        esc_html__( '%1$s in %2$s deleted.', 'security-ninja' ),
                        esc_html( $params[4]->name ),
                        esc_html( $wp_taxonomies[$params[3]]->labels->name )
                     );
                }
                break;
            case 'edited_term':
                $term = get_term( $params[1], sanitize_text_field( $params[3] ) );
                if ( $term && !is_wp_error( $term ) ) {
                    $desc = sprintf( 
                        /* translators: 1: term name, 2: taxonomy label */
                        esc_html__( '%1$s in %2$s updated.', 'security-ninja' ),
                        esc_html( $term->name ),
                        esc_html( $wp_taxonomies[$params[3]]->labels->name )
                     );
                }
                break;
            default:
                $desc = sprintf( 
                    /* translators: %s: action name */
                    esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ),
                    esc_html( $action_name )
                 );
        }
        self::log_event(
            'taxonomies',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * media related events
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_media( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'add_attachment':
                $media = get_post( $params[1] );
                if ( $media && !is_wp_error( $media ) ) {
                    $desc = sprintf( 
                        /* translators: %s: media attachment title */
                        esc_html__( 'Added media %s.', 'security-ninja' ),
                        esc_html( $media->post_title )
                     );
                }
                break;
            case 'edit_attachment':
                $media = get_post( $params[1] );
                if ( $media && !is_wp_error( $media ) ) {
                    $desc = sprintf( 
                        /* translators: %s: media attachment title */
                        esc_html__( 'Updated media %s.', 'security-ninja' ),
                        esc_html( $media->post_title )
                     );
                }
                break;
            case 'delete_attachment':
                $media = get_post( $params[1] );
                if ( $media && !is_wp_error( $media ) ) {
                    $desc = sprintf( 
                        /* translators: %s: media attachment title */
                        esc_html__( 'Deleted media %s.', 'security-ninja' ),
                        esc_html( $media->post_title )
                     );
                }
                break;
            case 'wp_save_image_editor_file':
                $media = get_post( $params[5] );
                if ( $media && !is_wp_error( $media ) ) {
                    $desc = sprintf( 
                        /* translators: %s: image attachment title */
                        esc_html__( 'Edited image %s.', 'security-ninja' ),
                        esc_html( $media->post_title )
                     );
                }
                break;
            default:
                $desc = sprintf( 
                    /* translators: %s: action name */
                    esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ),
                    esc_html( $action_name )
                 );
        }
        self::log_event(
            'media',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * posts related events
     *
     * @author  Unknown
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @version v1.0.1  Wednesday, May 15th, 2024.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    static function parse_action_posts( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'edit_post':
                // Logged via publish_post / trash_post / untrash_post as appropriate.
                return;
            case 'publish_post':
                $post = get_post( $params[0] );
                if ( !$post || !post_type_exists( $post->post_type ) ) {
                    return;
                }
                if ( in_array( $post->post_type, array('nav_menu_item', 'attachment', 'revision'), true ) ) {
                    return;
                }
                $post_type = get_post_type_object( $post->post_type );
                $type = strtolower( $post_type->labels->singular_name );
                $title = ( empty( $post->post_title ) ? __( 'No title', 'security-ninja' ) : $post->post_title );
                /* translators: 1: post title, 2: post type singular name */
                $desc = sprintf( esc_html__( '"%1$s" %2$s published.', 'security-ninja' ), esc_html( $title ), esc_html( $type ) );
                break;
            case 'trash_post':
                /* translators: %s: post title */
                $desc = sprintf( esc_html__( 'Trashed "%s".', 'security-ninja' ), esc_html( $params[2]->post_title ) );
                break;
            case 'untrash_post':
                $post = get_post( $params[0] );
                if ( !$post || !post_type_exists( $post->post_type ) ) {
                    return;
                }
                if ( in_array( $post->post_type, array('nav_menu_item', 'attachment', 'revision'), true ) ) {
                    return;
                }
                $post_type = get_post_type_object( $post->post_type );
                $type = strtolower( $post_type->labels->singular_name );
                $title = ( empty( $post->post_title ) ? __( 'No title', 'security-ninja' ) : $post->post_title );
                /* translators: 1: post title, 2: post type singular name */
                $desc = sprintf( esc_html__( '"%1$s" %2$s restored from trash.', 'security-ninja' ), esc_html( $title ), esc_html( $type ) );
                break;
            case 'deleted_post':
                $post = get_post( $params[1] );
                if ( $post && post_type_exists( $post->post_type ) ) {
                    $post_type = get_post_type_object( $post->post_type );
                    $type = strtolower( $post_type->labels->singular_name );
                } else {
                    $type = 'post';
                }
                if ( in_array( $type, array('nav_menu_item', 'attachment', 'revision'), true ) ) {
                    return;
                }
                /* translators: 1: post title, 2: post type singular name */
                $desc = sprintf( esc_html__( '%1$s %2$s deleted from trash.', 'security-ninja' ), esc_html( $post->post_title ), esc_html( $type ) );
                break;
            default:
                /* translators: %s: action or filter name */
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        if ( $desc ) {
            self::log_event(
                'posts',
                $action_name,
                $desc,
                $raw_data
            );
        }
    }

    static function parse_action_widgets( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        global $wp_registered_sidebars, $wp_widget_factory;
        switch ( $action_name ) {
            case 'update_option_sidebars_widgets':
                if ( did_action( 'after_switch_theme' ) ) {
                    return;
                }
                $delete_widget = ( isset( $_POST['delete_widget'] ) ? sanitize_text_field( wp_unslash( $_POST['delete_widget'] ) ) : '' );
                if ( $delete_widget ) {
                    $sidebar_key = ( isset( $_POST['sidebar'] ) ? sanitize_text_field( wp_unslash( $_POST['sidebar'] ) ) : '' );
                    $name = ( isset( $wp_registered_sidebars[$sidebar_key]['name'] ) ? $wp_registered_sidebars[$sidebar_key]['name'] : __( 'Unnamed', 'security-ninja' ) );
                    $ids = array_combine( wp_list_pluck( $wp_widget_factory->widgets, 'id_base' ), array_keys( $wp_widget_factory->widgets ) );
                    $widget_id = ( isset( $_POST['the-widget-id'] ) ? sanitize_text_field( wp_unslash( $_POST['the-widget-id'] ) ) : '' );
                    $id_base = ( preg_match( '#(.*)-(\\d+)$#', $widget_id, $matches ) ? $matches[1] : null );
                    $widget = ( null !== $id_base && isset( $ids[$id_base] ) && isset( $wp_widget_factory->widgets[$ids[$id_base]]->name ) ? $wp_widget_factory->widgets[$ids[$id_base]]->name : __( 'Unknown widget', 'security-ninja' ) );
                    /* translators: 1: widget name, 2: sidebar name */
                    $desc = sprintf( esc_html__( '%1$s widget was removed from %2$s sidebar.', 'security-ninja' ), esc_html( $widget ), esc_html( $name ) );
                } else {
                    return;
                }
                break;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'widgets',
            $action_name,
            $desc,
            $raw_data
        );
    }

    static function parse_action_installer( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'activate_plugin':
            case 'activated_plugin':
                $plugin_path = ( isset( $params[1] ) && is_string( $params[1] ) && '' !== $params[1] ? $params[1] : '' );
                if ( '' !== $plugin_path && function_exists( 'get_plugin_data' ) ) {
                    $plugin = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_path, false, false );
                    $label = ( !empty( $plugin['Name'] ) ? $plugin['Name'] : $plugin_path );
                } else {
                    $label = ( '' !== $plugin_path ? $plugin_path : esc_html__( 'Unknown plugin', 'security-ninja' ) );
                }
                /* translators: %s: plugin name or path */
                $desc = sprintf( esc_html__( 'Plugin %s activated.', 'security-ninja' ), esc_html( $label ) );
                break;
            case 'deactivate_plugin':
            case 'deactivated_plugin':
                $plugin_path = ( isset( $params[1] ) && is_string( $params[1] ) && '' !== $params[1] ? $params[1] : '' );
                if ( '' !== $plugin_path && function_exists( 'get_plugin_data' ) ) {
                    $plugin = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_path, false, false );
                    $label = ( !empty( $plugin['Name'] ) ? $plugin['Name'] : $plugin_path );
                } else {
                    $label = ( '' !== $plugin_path ? $plugin_path : esc_html__( 'Unknown plugin', 'security-ninja' ) );
                }
                /* translators: %s: plugin name or path */
                $desc = sprintf( esc_html__( 'Plugin %s deactivated.', 'security-ninja' ), esc_html( $label ) );
                break;
            case 'switch_theme':
                /* translators: %s: theme name */
                $desc = sprintf( esc_html__( 'Theme %s activated.', 'security-ninja' ), esc_html( $params[1] ) );
                break;
            case '_core_updated_successfully':
                /* translators: %s: WordPress version */
                $desc = sprintf( esc_html__( 'WordPress core updated to v%s.', 'security-ninja' ), esc_html( $params[1] ) );
                $raw_data = array(
                    'type'    => 'wordpress',
                    'version' => esc_attr( $params[1] ),
                );
                break;
            case 'upgrader_process_complete':
                $hook_action = ( isset( $params[2]['action'] ) ? $params[2]['action'] : '' );
                $hook_type = ( isset( $params[2]['type'] ) ? $params[2]['type'] : '' );
                if ( 'install' !== $hook_action && 'update' !== $hook_action || 'plugin' !== $hook_type && 'theme' !== $hook_type ) {
                    return;
                }
                if ( 'install' === $hook_action ) {
                    if ( 'plugin' === $hook_type ) {
                        $desc = esc_html__( 'Plugin installed.', 'security-ninja' );
                        $raw_data = array(
                            'type'   => 'plugin',
                            'action' => 'install',
                        );
                    } else {
                        $desc = esc_html__( 'Theme installed.', 'security-ninja' );
                        $raw_data = array(
                            'type'   => 'theme',
                            'action' => 'install',
                        );
                    }
                    break;
                }
                // action === 'update'
                if ( 'theme' === $hook_type && isset( $params[2]['themes'] ) && 'update' === $hook_action && isset( $params[2]['bulk'] ) && $params[2]['bulk'] ) {
                    $desc = array();
                    foreach ( $params[2]['themes'] as $theme_name ) {
                        $theme = wp_get_theme( $theme_name );
                        if ( !$theme->exists() || $theme->errors() && 'theme_no_stylesheet' === $theme->errors()->get_error_code() ) {
                            return;
                        }
                        /* translators: %s: theme name */
                        $desc[] = sprintf( esc_html__( 'Theme %s updated.', 'security-ninja' ), esc_html( $theme->get( 'Name' ) ) );
                        $raw_data = array(
                            'type' => 'theme',
                            'name' => esc_html( $theme->get( 'Name' ) ),
                        );
                    }
                    break;
                }
                if ( $hook_type == 'theme' && isset( $params[2]['theme'] ) && $hook_action == 'update' ) {
                    $theme = wp_get_theme( $params[2]['theme'] );
                    if ( !$theme->exists() || $theme->errors() && 'theme_no_stylesheet' === $theme->errors()->get_error_code() ) {
                        return;
                    }
                    $desc = sprintf( esc_html__( 'Theme %s updated.', 'security-ninja' ), esc_html( $theme->get( 'Name' ) ) );
                    $raw_data = array(
                        'type' => 'theme',
                        'name' => esc_html( $theme->get( 'Name' ) ),
                    );
                    break;
                }
                // Multiple plugins
                if ( isset( $params[2]['plugins'] ) && is_array( $params[2]['plugins'] ) ) {
                    $desc = array();
                    foreach ( $params[2]['plugins'] as $plugin_file ) {
                        $plugin = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file );
                        if ( !$plugin['Name'] ) {
                            return;
                        }
                        $raw_data = array(
                            'type' => 'plugin',
                            'name' => esc_html( $plugin['Name'] ),
                        );
                        $desc[] = sprintf( esc_html__( 'Plugin %s updated.', 'security-ninja' ), esc_html( $plugin['Name'] ) );
                    }
                } elseif ( isset( $params[2]['plugin'] ) ) {
                    $plugin = get_plugin_data( WP_PLUGIN_DIR . '/' . $params[2]['plugin'] );
                    if ( !$plugin['Name'] ) {
                        return;
                    }
                    $raw_data = array(
                        'type' => 'plugin',
                        'name' => esc_html( $plugin['Name'] ),
                    );
                    $desc = sprintf( esc_html__( 'Plugin %s updated.', 'security-ninja' ), esc_html( $plugin['Name'] ) );
                } else {
                    $desc = esc_html__( 'Unknown plugin updated.', 'security-ninja' );
                }
                break;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'installer',
            $action_name,
            $desc,
            $raw_data
        );
    }

    static function parse_action_comments( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'comment_duplicate_trigger':
                $post_title = ( ($post = get_post( $params[1]['comment_post_ID'] )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Duplicate comment by %1$s prevented on %2$s.', 'security-ninja' ), esc_html( $params[1]['comment_author_email'] ), esc_html( $post_title ) );
                break;
            case 'comment_flood_trigger':
                $post_title = ( ($post = get_post( $params[1]['comment_post_ID'] )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $email = ( isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '' );
                $desc = sprintf( esc_html__( 'Comment flooding by %1$s prevented on %2$s.', 'security-ninja' ), esc_html( $email ), esc_html( $post_title ) );
                break;
            case 'wp_insert_comment':
                $post_title = ( ($post = get_post( $params[2]->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                if ( $params[2]->comment_parent ) {
                    $desc = sprintf( esc_html__( 'New comment reply by %1$s created on %2$s.', 'security-ninja' ), esc_html( $params[2]->comment_author_email ), esc_html( $post_title ) );
                } else {
                    $desc = sprintf( esc_html__( 'New comment by %1$s created on %2$s.', 'security-ninja' ), esc_html( $params[2]->comment_author_email ), esc_html( $post_title ) );
                }
                break;
            case 'edit_comment':
                if ( isset( $params[2]['comment_post_ID'] ) ) {
                    $post_title = ( ($post = get_post( $params[2]['comment_post_ID'] )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                    $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s edited.', 'security-ninja' ), esc_html( $params[2]['newcomment_author_email'] ), esc_html( $post_title ) );
                }
                break;
            case 'trash_comment':
                $comment = get_comment( $params[1] );
                $post_title = ( ($post = get_post( $comment->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s trashed.', 'security-ninja' ), esc_html( $comment->comment_author_email ), esc_html( $post_title ) );
                break;
            case 'untrash_comment':
                $comment = get_comment( $params[1] );
                $post_title = ( ($post = get_post( $comment->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s restored.', 'security-ninja' ), esc_html( $comment->comment_author_email ), esc_html( $post_title ) );
                break;
            case 'delete_comment':
                $comment = get_comment( $params[1] );
                $post_title = ( ($post = get_post( $comment->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s permanently deleted.', 'security-ninja' ), esc_html( $comment->comment_author_email ), esc_html( $post_title ) );
                break;
            case 'spam_comment':
                $comment = get_comment( $params[1] );
                $post_title = ( ($post = get_post( $comment->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s marked as spam.', 'security-ninja' ), esc_html( $comment->comment_author_email ), esc_html( $post_title ) );
                break;
            case 'unspam_comment':
                $comment = get_comment( $params[1] );
                $post_title = ( ($post = get_post( $comment->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf( esc_html__( 'Comment by %1$s on %2$s unmarked as spam.', 'security-ninja' ), esc_html( $comment->comment_author_email ), esc_html( $post_title ) );
                break;
            case 'transition_comment_status':
                if ( $params[1] != 'approved' && $params[1] != 'unapproved' || $params[2] == 'trash' || $params[2] == 'spam' ) {
                    return;
                }
                $comment = get_comment( $params[3]->comment_ID );
                $post_title = ( ($post = get_post( $params[3]->comment_post_ID )) ? $post->post_title : __( 'Untitled', 'security-ninja' ) );
                $desc = sprintf(
                    esc_html__( 'Comment by %1$s on %2$s %3$s.', 'security-ninja' ),
                    esc_html( $params[3]->comment_author_email ),
                    esc_html( $post_title ),
                    esc_html( $params[1] )
                );
                break;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'comments',
            $action_name,
            $desc,
            $raw_data
        );
    }

    static function parse_action_settings( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        $log_action = $action_name;
        switch ( $action_name ) {
            case 'update_option_permalink_structure':
                $desc = esc_html__( 'Permalink settings updated.', 'security-ninja' );
                break;
            case 'update_option_tag_base':
                $desc = esc_html__( 'Tag base option updated.', 'security-ninja' );
                break;
            case 'update_option_category_base':
                $desc = esc_html__( 'Category base option updated.', 'security-ninja' );
                break;
            case 'update_site_option':
                return;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'settings',
            $log_action,
            $desc,
            $raw_data
        );
    }

    /**
     * WooCommerce related events
     *
     * @author  Lars Koudal
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, March 3rd, 2021.
     * @version v1.0.1  Wednesday, January 26th, 2022.
     * @version v1.0.2  Wednesday, May 15th, 2024.
     * @access  static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    public static function parse_action_woocommerce( $action_name, $params ) {
        if ( !class_exists( 'WooCommerce' ) ) {
            return;
        }
        $desc = '';
        $raw_data = null;
        switch ( $action_name ) {
            case 'woocommerce_new_product_data':
                if ( isset( $params['post_title'] ) ) {
                    $desc = sprintf( esc_html__( 'WooCommerce - New product "%s".', 'security-ninja' ), esc_html( $params['post_title'] ) );
                }
                break;
            case 'woocommerce_update_product':
                if ( isset( $params['ID'] ) ) {
                    $desc = sprintf( esc_html__( 'WooCommerce - Updated product #%d.', 'security-ninja' ), absint( $params['ID'] ) );
                }
                break;
            case 'woocommerce_new_customer':
                if ( isset( $params['customer_id'] ) ) {
                    $customer = new \WC_Customer($params['customer_id']);
                    $first_name = $customer->get_first_name();
                    $last_name = $customer->get_last_name();
                    $customer_name = $first_name . ' ' . $last_name;
                    $desc = sprintf( esc_html__( 'WooCommerce - New customer %s.', 'security-ninja' ), esc_html( $customer_name ) );
                }
                break;
            case 'woocommerce_new_order':
                if ( isset( $params['order_id'] ) ) {
                    $order = wc_get_order( $params['order_id'] );
                    if ( $order ) {
                        $desc = sprintf( esc_html__( 'WooCommerce - New order #%d.', 'security-ninja' ), absint( $params['order_id'] ) );
                    } else {
                        $desc = esc_html__( 'WooCommerce - New order.', 'security-ninja' );
                    }
                }
                break;
            case 'woocommerce_delete_coupon':
                $desc = esc_html__( 'WooCommerce - Deleted coupon.', 'security-ninja' );
                break;
            case 'woocommerce_delete_customer':
                $desc = esc_html__( 'WooCommerce - Deleted customer.', 'security-ninja' );
                break;
            case 'woocommerce_delete_order':
                $desc = esc_html__( 'WooCommerce - Deleted order.', 'security-ninja' );
                break;
            case 'woocommerce_order_status_changed':
                if ( isset( $params['order_id'], $params['old_status'], $params['new_status'] ) ) {
                    $order = wc_get_order( $params['order_id'] );
                    if ( $order ) {
                        $desc = sprintf(
                            esc_html__( 'WooCommerce - Order #%1$d status changed from %2$s to %3$s.', 'security-ninja' ),
                            absint( $params['order_id'] ),
                            esc_html( $params['old_status'] ),
                            esc_html( $params['new_status'] )
                        );
                    } else {
                        $desc = sprintf( esc_html__( 'WooCommerce - Order status changed from %1$s to %2$s.', 'security-ninja' ), esc_html( $params['old_status'] ), esc_html( $params['new_status'] ) );
                    }
                }
                break;
            case 'woocommerce_order_refunded':
                if ( isset( $params['order_id'], $params['refund_id'] ) ) {
                    $order = wc_get_order( $params['order_id'] );
                    $refund = wc_get_order( $params['refund_id'] );
                    if ( $order && $refund ) {
                        $desc = sprintf( esc_html__( 'WooCommerce - Order #%1$d refunded (Refund ID: %2$d).', 'security-ninja' ), absint( $params['order_id'] ), absint( $params['refund_id'] ) );
                    } else {
                        $desc = esc_html__( 'WooCommerce - Order refunded.', 'security-ninja' );
                    }
                }
                break;
            case 'woocommerce_product_duplicate':
                if ( isset( $params['original_id'], $params['duplicate_id'] ) ) {
                    $original_product = wc_get_product( $params['original_id'] );
                    $duplicate_product = wc_get_product( $params['duplicate_id'] );
                    if ( $original_product && $duplicate_product ) {
                        $desc = sprintf(
                            /* translators: %1$s: original product name, %2$d: original product ID, %3$s: duplicate product name, %4$d: duplicate product ID */
                            esc_html__( 'WooCommerce - Duplicated product "%1$s" (ID: %2$d) to "%3$s" (ID: %4$d).', 'security-ninja' ),
                            esc_html( $original_product->get_name() ),
                            absint( $params['original_id'] ),
                            esc_html( $duplicate_product->get_name() ),
                            absint( $params['duplicate_id'] )
                        );
                    } else {
                        $desc = esc_html__( 'WooCommerce - Duplicated product.', 'security-ninja' );
                    }
                }
                break;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'woocommerce',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * Security Ninja related events
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Wednesday, January 26th, 2022.
     * @version v1.0.1  Friday, May 13th, 2022.
     * @version v1.0.2  Wednesday, May 15th, 2024.
     * @access  public static
     * @param   mixed   $action_name
     * @param   mixed   $params
     * @return  void
     */
    public static function parse_action_security_ninja( $action_name, $params ) {
        $desc = '';
        $raw_data = null;
        // Gather raw data if available in $params
        // Expecting $params['files_scanned'] and $params['dirs_scanned'] where possible (fallback to known indexes)
        if ( is_array( $params ) ) {
            $files_scanned = $params['files_scanned'] ?? (( isset( $params[3] ) ? $params[3] : null ));
            $dirs_scanned = $params['dirs_scanned'] ?? (( isset( $params[4] ) ? $params[4] : null ));
            if ( $files_scanned !== null || $dirs_scanned !== null ) {
                $raw_data = array(
                    'files_scanned' => ( $files_scanned !== null ? intval( $files_scanned ) : 0 ),
                    'dirs_scanned'  => ( $dirs_scanned !== null ? intval( $dirs_scanned ) : 0 ),
                );
            }
        }
        switch ( $action_name ) {
            case 'security_ninja_done_testing':
                $desc = sprintf( esc_html__( 'Finished analyzing the site in %s seconds.', 'security-ninja' ), esc_html( round( $params[2], 1 ) ) );
                break;
            case 'security_ninja_core_scanner_done_scanning':
                $desc = sprintf( esc_html__( 'Core Scanner finished scanning files in %s seconds.', 'security-ninja' ), esc_html( round( $params[2], 1 ) ) );
                break;
            case 'security_ninja_scheduled_scanner_done_cron':
                $desc = sprintf( esc_html__( 'Scheduled Scanner add-on finished a scheduled scan in %s seconds.', 'security-ninja' ), esc_html( round( $params[1], 1 ) ) );
                break;
            case 'security_ninja_malware_scanner_done_scanning':
                $desc = sprintf( esc_html__( 'Malware Scanner add-on finished scanning and found %s suspicious files.', 'security-ninja' ), esc_html( $params[1] ) );
                break;
            case 'security_ninja_remote_access':
                $desc = sprintf( esc_html__( 'Remote Access was %s.', 'security-ninja' ), esc_html( $params[1] ) );
                break;
            case 'vulnerabilities_manual_scan':
                if ( isset( $params['details'] ) && is_array( $params['details'] ) ) {
                    $details = $params['details'];
                    $desc = sprintf(
                        esc_html__( 'Manual vulnerability scan completed. Checked %1$s plugins, %2$s themes. Found %3$s vulnerabilities.', 'security-ninja' ),
                        esc_html( $details['plugins_checked'] ?? '0' ),
                        esc_html( $details['themes_checked'] ?? '0' ),
                        esc_html( $details['found_vulnerabilities'] ?? '0' )
                    );
                } else {
                    $desc = esc_html__( 'Manual vulnerability scan completed.', 'security-ninja' );
                }
                break;
            default:
                $desc = sprintf( esc_html__( 'Unknown action or filter - %s.', 'security-ninja' ), esc_html( $action_name ) );
        }
        self::log_event(
            'security_ninja',
            $action_name,
            $desc,
            $raw_data
        );
    }

    /**
     * Deactivate routines
     *
     * @author  Unknown
     * @since   v0.0.1
     * @version v1.0.0  Friday, May 13th, 2022.
     * @access  static
     * @return  void
     */
    public static function deactivate() {
        $centraloptions = Wf_Sn::get_options();
        if ( !isset( $centraloptions['remove_settings_deactivate'] ) ) {
            return;
        }
        if ( !empty( $centraloptions['remove_settings_deactivate'] ) ) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'wf_sn_el';
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix only
            $wpdb->query( 'DROP TABLE IF EXISTS ' . $table_name );
        }
    }

}

register_deactivation_hook( WF_SN_BASE_FILE, array(__NAMESPACE__ . '\\wf_sn_el_modules', 'deactivate') );