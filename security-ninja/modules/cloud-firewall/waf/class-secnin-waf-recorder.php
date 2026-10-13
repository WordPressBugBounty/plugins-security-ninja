<?php

/**
 * Canonical firewall decision recorder + early-event importer.
 *
 * @package WPSecurityNinja\Plugin
 */
namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Secnin_Waf_Recorder
 */
class Secnin_Waf_Recorder {
    const RECEIPT_OPTION = 'wf_sn_cf_waf_event_receipts';

    const MAX_RECEIPTS = 500;

    /**
     * Request-scoped fingerprints already recorded.
     *
     * @var array
     */
    private static $recorded = array();

    /**
     * Record a block decision once.
     *
     * @param array $decision {
     *   @type string $event_id
     *   @type string $ip
     *   @type string $rule
     *   @type string $reason
     *   @type string $uri
     *   @type string $user_agent
     *   @type string $source early|wordpress
     * }
     * @return bool True if newly recorded.
     */
    public static function record_block( array $decision ) {
        $event_id = ( isset( $decision['event_id'] ) ? (string) $decision['event_id'] : '' );
        $ip = ( isset( $decision['ip'] ) ? (string) $decision['ip'] : '' );
        $rule = ( isset( $decision['rule'] ) ? (string) $decision['rule'] : 'block' );
        $reason = ( isset( $decision['reason'] ) ? (string) $decision['reason'] : '' );
        $uri = ( isset( $decision['uri'] ) ? (string) $decision['uri'] : '' );
        $ua = ( isset( $decision['user_agent'] ) ? (string) $decision['user_agent'] : '' );
        $source = ( isset( $decision['source'] ) ? (string) $decision['source'] : 'wordpress' );
        if ( '' === $ip ) {
            return false;
        }
        $fingerprint = md5( $event_id . '|' . $ip . '|' . $rule . '|' . $uri );
        if ( isset( self::$recorded[$fingerprint] ) ) {
            return false;
        }
        if ( '' !== $event_id && self::has_receipt( $event_id ) ) {
            self::$recorded[$fingerprint] = true;
            return false;
        }
        if ( class_exists( __NAMESPACE__ . '\\wf_sn_cf' ) ) {
            wf_sn_cf::update_blocked_count( $ip );
        }
        if ( class_exists( __NAMESPACE__ . '\\wf_sn_el_modules' ) ) {
            $extra = array(
                'ip'          => $ip,
                'ban_reason'  => $reason,
                'rule'        => $rule,
                'source'      => $source,
                'event_id'    => $event_id,
                'request_uri' => $uri,
                'user_agent'  => $ua,
            );
            wf_sn_el_modules::log_event(
                'security_ninja',
                'firewall_block',
                ( $reason ? $reason : __( 'IP is blocked.', 'security-ninja' ) ),
                $extra,
                null,
                $ip
            );
        }
        if ( class_exists( __NAMESPACE__ . '\\wf_sn_cf' ) && method_exists( __NAMESPACE__ . '\\wf_sn_cf', 'log_visitor__premium_only' ) ) {
            $options = wf_sn_cf::get_options();
            if ( !empty( $options['trackvisits'] ) ) {
                wf_sn_cf::log_visitor__premium_only( array(
                    'ip'          => $ip,
                    'user_agent'  => $ua,
                    'banned'      => 1,
                    'ban_reason'  => $rule,
                    'description' => $reason,
                    'URL'         => $uri,
                    'raw_data'    => array(
                        'event_id' => $event_id,
                        'source'   => $source,
                    ),
                ) );
            }
        }
        if ( '' !== $event_id ) {
            self::store_receipt( $event_id );
        }
        self::$recorded[$fingerprint] = true;
        return true;
    }

    /**
     * Import early queue when admin/cron, or when a short allow transient is set.
     *
     * @return int
     */
    public static function maybe_import_early_queue() {
        $allowed = is_admin() || function_exists( 'wp_doing_cron' ) && wp_doing_cron();
        if ( !$allowed && get_transient( 'secnin_waf_import_queue' ) ) {
            $allowed = true;
        }
        if ( !$allowed ) {
            return 0;
        }
        return self::import_early_queue();
    }

    /**
     * Import early queue events idempotently.
     *
     * @return int Number imported.
     */
    public static function import_early_queue() {
        $dir = '';
        if ( class_exists( __NAMESPACE__ . '\\Secnin_Waf_Lifecycle' ) ) {
            $dir = trailingslashit( Secnin_Waf_Lifecycle::get_data_dir() ) . 'queue';
        }
        if ( '' === $dir || !is_dir( $dir ) ) {
            return 0;
        }
        $files = glob( $dir . '/evt-*.php' );
        if ( !is_array( $files ) || empty( $files ) ) {
            return 0;
        }
        $imported = 0;
        foreach ( $files as $file ) {
            if ( !is_readable( $file ) ) {
                continue;
            }
            $event = (include $file);
            if ( !is_array( $event ) || empty( $event['event_id'] ) || empty( $event['ip'] ) ) {
                @unlink( $file );
                // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
                continue;
            }
            $ok = self::record_block( array(
                'event_id'   => (string) $event['event_id'],
                'ip'         => (string) $event['ip'],
                'rule'       => ( isset( $event['rule'] ) ? (string) $event['rule'] : 'block' ),
                'reason'     => ( isset( $event['reason'] ) ? (string) $event['reason'] : '' ),
                'uri'        => ( isset( $event['uri'] ) ? (string) $event['uri'] : '' ),
                'user_agent' => ( isset( $event['user_agent'] ) ? (string) $event['user_agent'] : '' ),
                'source'     => 'early',
            ) );
            if ( $ok ) {
                $ban_type = ( isset( $event['ban_type'] ) ? (string) $event['ban_type'] : '' );
            }
            if ( $ok || self::has_receipt( (string) $event['event_id'] ) ) {
                @unlink( $file );
                // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
                if ( $ok ) {
                    $imported++;
                }
            }
        }
        return $imported;
    }

    /**
     * @param string $event_id Event ID.
     * @return bool
     */
    public static function has_receipt( $event_id ) {
        $receipts = get_option( self::RECEIPT_OPTION, array() );
        if ( !is_array( $receipts ) ) {
            return false;
        }
        return isset( $receipts[(string) $event_id] );
    }

    /**
     * @param string $event_id Event ID.
     * @return void
     */
    public static function store_receipt( $event_id ) {
        $receipts = get_option( self::RECEIPT_OPTION, array() );
        if ( !is_array( $receipts ) ) {
            $receipts = array();
        }
        $receipts[(string) $event_id] = time();
        if ( count( $receipts ) > self::MAX_RECEIPTS ) {
            asort( $receipts );
            $receipts = array_slice(
                $receipts,
                -1 * self::MAX_RECEIPTS,
                null,
                true
            );
        }
        update_option( self::RECEIPT_OPTION, $receipts, false );
    }

}
