<?php

/**
 * Central admin deep-link map for Security Ninja modules.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Admin_Links
 */
class Wf_Sn_Admin_Links {
    /**
     * Base URL for in-page tabs on the main Security Ninja admin page.
     *
     * @return string
     */
    public static function main_page_url() {
        return admin_url( 'admin.php?page=wf-sn' );
    }

    /**
     * Full admin URL for a tab hash on the main page.
     *
     * @param string $hash Tab hash without leading # (e.g. sn_tests).
     * @return string
     */
    public static function tab_url( $hash ) {
        $hash = ltrim( (string) $hash, '#' );
        return self::main_page_url() . '#' . sanitize_key( $hash );
    }

    /**
     * Known module link keys => full admin URLs.
     *
     * @return array<string, string>
     */
    public static function get_links() {
        $links = array(
            'overview'        => self::tab_url( 'sn_overview' ),
            'tests'           => self::tab_url( 'sn_tests' ),
            'vulnerabilities' => self::tab_url( 'sn_vuln' ),
            'core_scanner'    => self::tab_url( 'sn_core' ),
            'firewall'        => self::tab_url( 'sn_cf' ),
            'events'          => self::tab_url( 'sn_logger' ),
            'login'           => self::tab_url( 'sn_login' ),
            'malware'         => self::tab_url( 'sn_malware' ),
            'scheduler'       => self::tab_url( 'sn_schedule' ),
            'advisor'         => admin_url( 'admin.php?page=wf-sn-advisor' ),
            'wizard'          => admin_url( 'admin.php?page=security-ninja-wizard' ),
            'updates'         => admin_url( 'update-core.php' ),
        );
        return $links;
    }

    /**
     * Resolve a link key to URL, with optional fallback hash.
     *
     * @param string $key      Link key from get_links().
     * @param string $fallback Fallback URL when key missing.
     * @return string
     */
    public static function url( $key, $fallback = '' ) {
        $links = self::get_links();
        $key = sanitize_key( (string) $key );
        if ( isset( $links[$key] ) ) {
            return $links[$key];
        }
        return ( '' !== $fallback ? $fallback : self::tab_url( 'sn_overview' ) );
    }

    /**
     * Quick action buttons for Overview (free + premium where applicable).
     *
     * @return array<int, array{label: string, url: string, group: string}>
     */
    public static function get_quick_actions() {
        $actions = array(
            array(
                'label' => __( 'Run setup wizard', 'security-ninja' ),
                'url'   => self::url( 'wizard' ),
                'group' => 'setup',
            ),
            array(
                'label' => __( 'Open security tests', 'security-ninja' ),
                'url'   => self::url( 'tests' ),
                'group' => 'scanning',
            ),
            array(
                'label' => __( 'Open firewall', 'security-ninja' ),
                'url'   => self::url( 'firewall' ),
                'group' => 'monitoring',
            ),
            array(
                'label' => __( 'Open vulnerability scanner', 'security-ninja' ),
                'url'   => self::url( 'vulnerabilities' ),
                'group' => 'scanning',
            )
        );
        return $actions;
    }

}
