<?php

/**
 * Time-boxed upgrade offers for the free plugin.
 *
 * One campaign is visible at a time. Dismiss hides that campaign until it ends.
 * A sidebar link can show it again. Pro installs never see it.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin;

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Campaigns
 */
class Wf_Sn_Campaigns {
    /**
     * User meta key. Value is a list of dismissed campaign ids.
     */
    const META_KEY = 'wf_sn_dismissed_campaigns';

    /**
     * Register the dismiss / restore handler.
     *
     * @return void
     */
    public static function init() {
        add_action( 'admin_post_wf_sn_campaign_notice', array(__CLASS__, 'handle_admin_post') );
    }

    /**
     * Campaign that is inside its UTC window, ignoring license and dismiss.
     *
     * @param int $timestamp Unix timestamp.
     * @return array<string, mixed>|null
     */
    public static function matching_campaign( $timestamp ) {
        $timestamp = (int) $timestamp;
        foreach ( self::definitions() as $campaign ) {
            if ( $timestamp >= $campaign['start'] && $timestamp <= $campaign['end'] ) {
                return $campaign;
            }
        }
        return null;
    }

    /**
     * Offer URL. Coupon is stored by the site. Checkout is not opened.
     *
     * @param array<string, mixed> $campaign  Campaign definition.
     * @param string               $placement utm_content value.
     * @param array<string, mixed> $extra     Extra query args. Later keys win.
     * @return string
     */
    public static function offer_url( $campaign, $placement, $extra = array() ) {
        $params = array(
            'utm_campaign' => $campaign['utm_campaign'],
        );
        if ( !empty( $campaign['pass_coupon'] ) ) {
            $params['coupon'] = $campaign['code'];
        }
        if ( is_array( $extra ) && !empty( $extra ) ) {
            $params = array_merge( $params, $extra );
        }
        return Utils::generate_sn_web_link( $placement, $campaign['path'], $params );
    }

    /**
     * One short paragraph for the vulnerability email. Empty for Pro and outside a window.
     *
     * Dismiss in wp-admin does not apply here. The recipient may not be the user who hid the card.
     *
     * @return string
     */
    public static function email_paragraph() {
        if ( !self::is_free_install() ) {
            return '';
        }
        $campaign = self::matching_campaign( time() );
        if ( !$campaign ) {
            return '';
        }
        $url = self::offer_url( $campaign, $campaign['placement_email'], array(
            'utm_medium' => 'email',
        ) );
        return '<p>' . esc_html( self::offer_line( $campaign ) ) . ' <a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( $campaign['button'] ) . '</a></p>';
    }

    /**
     * Whether this user hid the campaign.
     *
     * @param string $campaign_id Campaign id.
     * @param int    $user_id     User id. 0 uses the current user.
     * @return bool
     */
    public static function is_dismissed( $campaign_id, $user_id = 0 ) {
        $user_id = self::user_id( $user_id );
        if ( !$user_id ) {
            return false;
        }
        return in_array( $campaign_id, self::dismissed_ids( $user_id ), true );
    }

    /**
     * Remember or forget a dismiss for one campaign.
     *
     * @param string $campaign_id Campaign id.
     * @param bool   $dismissed   True to hide, false to show again.
     * @param int    $user_id     User id. 0 uses the current user.
     * @return void
     */
    public static function set_dismissed( $campaign_id, $dismissed, $user_id = 0 ) {
        $user_id = self::user_id( $user_id );
        if ( !$user_id || !self::campaign_by_id( $campaign_id ) ) {
            return;
        }
        $ids = self::dismissed_ids( $user_id );
        if ( $dismissed ) {
            if ( !in_array( $campaign_id, $ids, true ) ) {
                $ids[] = $campaign_id;
            }
        } else {
            $ids = array_values( array_diff( $ids, array($campaign_id) ) );
        }
        if ( empty( $ids ) ) {
            delete_user_meta( $user_id, self::META_KEY );
            return;
        }
        update_user_meta( $user_id, self::META_KEY, $ids );
    }

    /**
     * Dashboard widget offer. Hidden after dismiss. Reopen lives in the sidebar.
     *
     * @return void
     */
    public static function render_dashboard_offer() {
        $campaign = self::visible_campaign();
        if ( !$campaign || self::is_dismissed( $campaign['id'] ) ) {
            return;
        }
        self::render_offer( $campaign, $campaign['placement_dashboard'] );
    }

    /**
     * Sidebar offer. Omitted after dismiss.
     *
     * @return void
     */
    public static function render_sidebar_offer() {
        $campaign = self::visible_campaign();
        if ( !$campaign || self::is_dismissed( $campaign['id'] ) ) {
            return;
        }
        self::render_offer( $campaign, $campaign['placement_sidebar'] );
    }

    /**
     * Quiet sidebar link that shows the current campaign again.
     *
     * @return void
     */
    public static function render_sidebar_restore_link() {
        $campaign = self::visible_campaign();
        if ( !$campaign || !self::is_dismissed( $campaign['id'] ) ) {
            return;
        }
        $url = self::action_url( $campaign['id'], 'restore' );
        echo '<li class="secnin-campaign-restore"><a href="' . esc_url( $url ) . '">';
        echo esc_html( sprintf( 
            /* translators: %s: campaign name, e.g. Black Friday */
            __( 'Show the %s offer', 'security-ninja' ),
            $campaign['restore_label']
         ) );
        echo '</a></li>';
    }

    /**
     * Save dismiss or restore, then return to the previous admin screen.
     *
     * @return void
     */
    public static function handle_admin_post() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to do that.', 'security-ninja' ) );
        }
        check_admin_referer( 'wf_sn_campaign_notice' );
        $campaign_id = ( isset( $_GET['campaign'] ) ? sanitize_key( wp_unslash( $_GET['campaign'] ) ) : '' );
        $action = ( isset( $_GET['sn_do'] ) ? sanitize_key( wp_unslash( $_GET['sn_do'] ) ) : '' );
        if ( self::is_free_install() && self::campaign_by_id( $campaign_id ) ) {
            if ( 'restore' === $action ) {
                self::set_dismissed( $campaign_id, false );
            } elseif ( 'dismiss' === $action ) {
                self::set_dismissed( $campaign_id, true );
            }
        }
        wp_safe_redirect( self::redirect_target() );
        exit;
    }

    /**
     * Active campaign for a free admin who can manage options.
     *
     * @return array<string, mixed>|null
     */
    private static function visible_campaign() {
        if ( !self::is_free_install() || !current_user_can( 'manage_options' ) ) {
            return null;
        }
        return self::matching_campaign( time() );
    }

    /**
     * Free installs only. Pro, including white label, is excluded.
     *
     * @return bool
     */
    private static function is_free_install() {
        $is_free = true;
        if ( function_exists( '\\WPSecurityNinja\\Plugin\\secnin_fs' ) ) {
        }
        return $is_free;
    }

    /**
     * @param string $campaign_id Campaign id.
     * @return array<string, mixed>|null
     */
    private static function campaign_by_id( $campaign_id ) {
        foreach ( self::definitions() as $campaign ) {
            if ( $campaign['id'] === $campaign_id ) {
                return $campaign;
            }
        }
        return null;
    }

    /**
     * @param int $user_id User id. 0 uses the current user.
     * @return int
     */
    private static function user_id( $user_id ) {
        $user_id = (int) $user_id;
        if ( $user_id > 0 ) {
            return $user_id;
        }
        return (int) get_current_user_id();
    }

    /**
     * @param int $user_id User id.
     * @return string[]
     */
    private static function dismissed_ids( $user_id ) {
        $stored = get_user_meta( $user_id, self::META_KEY, true );
        if ( !is_array( $stored ) ) {
            return array();
        }
        $ids = array();
        foreach ( $stored as $id ) {
            $id = sanitize_key( $id );
            if ( '' !== $id ) {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    /**
     * @param array<string, mixed> $campaign  Campaign definition.
     * @param string               $placement utm_content value.
     * @return void
     */
    private static function render_offer( $campaign, $placement ) {
        $url = self::offer_url( $campaign, $placement );
        $hide = self::action_url( $campaign['id'], 'dismiss' );
        ?>
		<div class="secnin-campaign">
			<p class="secnin-campaign-headline"><?php 
        echo esc_html( $campaign['headline'] );
        ?></p>
			<p class="secnin-campaign-actions">
				<a class="button button-primary" href="<?php 
        echo esc_url( $url );
        ?>" target="_blank" rel="noopener"><?php 
        echo esc_html( $campaign['button'] );
        ?></a>
				<a class="secnin-campaign-hide" href="<?php 
        echo esc_url( $hide );
        ?>"><?php 
        esc_html_e( 'Hide', 'security-ninja' );
        ?></a>
			</p>
		</div>
		<?php 
    }

    /**
     * Headline plus coupon, one sentence. Used in email.
     *
     * @param array<string, mixed> $campaign Campaign definition.
     * @return string
     */
    private static function offer_line( $campaign ) {
        return sprintf( 
            /* translators: 1: offer sentence, 2: coupon code */
            __( '%1$s Code %2$s', 'security-ninja' ),
            $campaign['headline'],
            $campaign['code']
         );
    }

    /**
     * @param string $campaign_id Campaign id.
     * @param string $action      dismiss or restore.
     * @return string
     */
    private static function action_url( $campaign_id, $action ) {
        return wp_nonce_url( add_query_arg( array(
            'action'   => 'wf_sn_campaign_notice',
            'campaign' => $campaign_id,
            'sn_do'    => $action,
        ), admin_url( 'admin-post.php' ) ), 'wf_sn_campaign_notice' );
    }

    /**
     * @return string
     */
    private static function redirect_target() {
        $referer = wp_get_referer();
        if ( $referer ) {
            return $referer;
        }
        return admin_url( 'index.php' );
    }

    /**
     * Windows are UTC and do not overlap. 30% is the largest discount.
     *
     * @return array<int, array<string, mixed>>
     */
    private static function definitions() {
        return array(array(
            'id'                  => 'bfcm2026',
            'start'               => gmmktime(
                0,
                0,
                0,
                10,
                26,
                2026
            ),
            'end'                 => gmmktime(
                23,
                59,
                59,
                12,
                4,
                2026
            ),
            'headline'            => __( 'Black Friday: 30% off your first year of Pro.', 'security-ninja' ),
            'button'              => __( 'See the deal', 'security-ninja' ),
            'restore_label'       => __( 'Black Friday', 'security-ninja' ),
            'code'                => 'BFCM2026',
            'path'                => '/black-friday/',
            'pass_coupon'         => false,
            'utm_campaign'        => 'bfcm2026',
            'placement_dashboard' => 'dashboard_bfcm',
            'placement_sidebar'   => 'sidebar_bfcm',
            'placement_email'     => 'email_vuln_bfcm',
        ), array(
            'id'                  => 'xmas2026',
            'start'               => gmmktime(
                0,
                0,
                0,
                12,
                15,
                2026
            ),
            'end'                 => gmmktime(
                23,
                59,
                59,
                12,
                24,
                2026
            ),
            'headline'            => __( 'Christmas: 20% off your first year of Pro.', 'security-ninja' ),
            'button'              => __( 'See pricing', 'security-ninja' ),
            'restore_label'       => __( 'Christmas', 'security-ninja' ),
            'code'                => 'XMAS2026',
            'path'                => '/pricing/',
            'pass_coupon'         => true,
            'utm_campaign'        => 'xmas2026',
            'placement_dashboard' => 'dashboard_xmas',
            'placement_sidebar'   => 'sidebar_xmas',
            'placement_email'     => 'email_vuln_xmas',
        ), array(
            'id'                  => 'ny2027',
            'start'               => gmmktime(
                0,
                0,
                0,
                1,
                4,
                2027
            ),
            'end'                 => gmmktime(
                23,
                59,
                59,
                1,
                15,
                2027
            ),
            'headline'            => __( 'New year: 15% off your first year of Pro.', 'security-ninja' ),
            'button'              => __( 'See pricing', 'security-ninja' ),
            'restore_label'       => __( 'New year', 'security-ninja' ),
            'code'                => 'NY2027',
            'path'                => '/pricing/',
            'pass_coupon'         => true,
            'utm_campaign'        => 'ny2027',
            'placement_dashboard' => 'dashboard_ny',
            'placement_sidebar'   => 'sidebar_ny',
            'placement_email'     => 'email_vuln_ny',
        ));
    }

}
