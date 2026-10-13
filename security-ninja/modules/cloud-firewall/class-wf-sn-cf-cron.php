<?php

/**
 * Cloud Firewall Wf_Sn_Cf_Cron helpers (loaded on demand).
 *
 * @package WPSecurityNinja\Plugin
 */
namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Cf_Cron
 */
class Wf_Sn_Cf_Cron {
    public static function prune_visitor_log( $force = false ) {
        global $wpdb;
        $trackvisits_howlong = absint( wf_sn_cf::$options['trackvisits_howlong'] );
        if ( !$trackvisits_howlong ) {
            $trackvisits_howlong = 2;
            // in days
        }
        $table_name = $wpdb->prefix . 'wf_sn_cf_vl';
        if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name ) {
            $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . $wpdb->prefix . 'wf_sn_cf_vl WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)', $trackvisits_howlong ) );
            $max_records = 5000;
            // Sane limit for visitor log entries
            $remaining_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
            if ( $remaining_count > $max_records ) {
                // Find the timestamp of the record that would be the $max_records-th newest
                $cutoff_data = $wpdb->get_row( $wpdb->prepare( "SELECT timestamp, id FROM {$table_name} \n\t\t\t\t\tORDER BY timestamp DESC, id DESC \n\t\t\t\t\tLIMIT 1 OFFSET %d", $max_records - 1 ) );
                if ( $cutoff_data ) {
                    // For records with the same timestamp, delete those with lower IDs
                    $wpdb->query( $wpdb->prepare(
                        "DELETE FROM {$table_name} \n\t\t\t\t\t\tWHERE timestamp < %s \n\t\t\t\t\t\tOR (timestamp = %s AND id < %d)",
                        $cutoff_data->timestamp,
                        $cutoff_data->timestamp,
                        $cutoff_data->id
                    ) );
                }
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_visitor_log',
                    sprintf(
                        esc_html__( 'Pruned firewall visitors log - %1$s days, then reduced to %2$s entries (was %3$s).', 'security-ninja' ),
                        $trackvisits_howlong,
                        $max_records,
                        $remaining_count
                    ),
                    ''
                );
            } else {
                \WPSecurityNinja\Plugin\wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_visitor_log',
                    sprintf( esc_html__( 'Pruned firewall visitors log - %1$s days.', 'security-ninja' ), $trackvisits_howlong ),
                    ''
                );
            }
        }
        return true;
    }

    /**
     * Prune events log table
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @param   boolean $force  Default: false
     * @return  boolean
     */
    public static function schedule_cron_jobs() {
    }

    /**
     * Register module settings.
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @access  public static
     * @return  void
     */
    public static function prune_banned() {
        $update = false;
        $banned_ips = wf_sn_cf::get_banned_ips();
        if ( $banned_ips ) {
            foreach ( $banned_ips as $ip => $time ) {
                if ( $time < \WPSecurityNinja\Plugin\Secnin_Waf_Ban_Clock::now() ) {
                    unset($banned_ips[$ip]);
                    $update = true;
                }
            }
        }
        if ( $update ) {
            wf_sn_cf::update_banned_ips( $banned_ips );
            if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
                wf_sn_el_modules::log_event(
                    'security_ninja',
                    'pruned_banned_ips',
                    'Pruned Firewall local banned IPs.',
                    ''
                );
            }
        }
    }

    /**
     * Handle failed login - basic logging for free, advanced protection for premium
     *
     * @author  Lars Koudal
     * @since   v0.0.1
     * @version v1.0.0  Monday, December 21st, 2020.
     * @version v1.0.1  Tuesday, January 14th, 2025 - Consolidated free and premium logic
     * @access  public static
     * @param   mixed   $username
     * @return  void
     */
}
