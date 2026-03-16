<?php

/**
 * AI Security Advisor – WPSN API auth: Pro (Freemius) and free (site-based).
 *
 * Used for register, credits, complete. Not gated by is__premium_only(); both free and Pro can use WPSN.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Ai_Advisor_Api_Auth
 */
class Wf_Sn_Ai_Advisor_Api_Auth {
    const OPTION_SITE_AUTH = 'wf_sn_ai_site_auth';

    /**
     * Build auth for WPSN API: Pro = Freemius header + body ids; free = site_id + site secret in headers.
     *
     * @return array{is_pro: bool, headers: array, body_auth: array} Body_auth is merged into request body; headers must be sent.
     */
    public static function build_auth() {
        return self::build_free_auth();
    }

    /**
     * Free: site_id (UUID) and site secret. Stored in option; generated on first use.
     *
     * @return array{is_pro: false, headers: array, body_auth: array}
     */
    private static function build_free_auth() {
        $stored = get_option( self::OPTION_SITE_AUTH, array() );
        if ( empty( $stored['site_id'] ) || empty( $stored['site_secret'] ) ) {
            $stored = array(
                'site_id'     => self::generate_uuid(),
                'site_secret' => wp_generate_password( 32, true, true ),
            );
            update_option( self::OPTION_SITE_AUTH, $stored, true );
        }
        $auth_value = hash( 'sha256', $stored['site_secret'] . '|' . current_time( 'Y-m-d', true ) );
        return array(
            'is_pro'    => false,
            'headers'   => array(
                'X-Site-Id'   => $stored['site_id'],
                'X-Site-Auth' => $auth_value,
            ),
            'body_auth' => array(
                'site_id'   => $stored['site_id'],
                'site_auth' => $auth_value,
            ),
        );
    }

    /**
     * Get install_id and license_id for Pro (for body). Returns null for free.
     *
     * @return array{install_id: int, license_id: int}|null
     */
    public static function get_pro_ids() {
        return null;
    }

    /**
     * Generate a UUID v4.
     *
     * @return string
     */
    private static function generate_uuid() {
        if ( function_exists( 'random_bytes' ) ) {
            try {
                $bytes = random_bytes( 16 );
            } catch ( \Exception $e ) {
                $bytes = wp_generate_password( 16, true, true );
                $bytes = substr( $bytes, 0, 16 );
            }
        } else {
            $bytes = wp_generate_password( 16, true, true );
            $bytes = substr( $bytes, 0, 16 );
        }
        if ( strlen( $bytes ) < 16 ) {
            $bytes = str_pad( $bytes, 16, "\x00" );
        }
        $bytes[6] = chr( ord( $bytes[6] ) & 0xf | 0x40 );
        $bytes[8] = chr( ord( $bytes[8] ) & 0x3f | 0x80 );
        return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $bytes ), 4 ) );
    }

}
