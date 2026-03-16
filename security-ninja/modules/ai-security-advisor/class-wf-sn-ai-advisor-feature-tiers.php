<?php

/**
 * AI Security Advisor – feature tier map (FREE vs PRO) for prompt instructions.
 *
 * Single source of truth: which features the AI may recommend per plan_tier.
 * Used to generate the "Plan tier" block injected into the system instruction.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Class Wf_Sn_Ai_Advisor_Feature_Tiers
 */
class Wf_Sn_Ai_Advisor_Feature_Tiers {
    /**
     * Feature labels the AI MAY recommend when plan_tier is "free".
     *
     * @return string[]
     */
    public static function get_free_allowed_recommendations() {
        return array(
            'basic cloud firewall (no 404 Guard, no country blocking, no advanced rules)',
            'security tests (run and act on test results)',
            'vulnerability scanner (full summary; scheduling, email alerts, ignore list are Pro-only)',
            'core scanner (summary of unknown or modified files; file viewer and diff vs official core)',
            'configuration hardening (e.g. security headers, XML-RPC, best practices you can apply without the Pro Fixes page)',
            'basic events logger (firewall events and login attempts only)'
        );
    }

    /**
     * Feature labels the AI must NEVER recommend when plan_tier is "free".
     *
     * @return string[]
     */
    public static function get_free_forbidden_recommendations() {
        return array(
            'two-factor authentication (2FA)',
            'rename login / custom login URL',
            'login protection (Pro; protect login form)',
            'auto-fixer (Pro; not for all security issues)',
            'Fixes page toggles (Pro; XML-RPC, security headers, and other fixes from the main plugin Fixes page)',
            'malware scanner (Pro; file viewer and diff for repo plugins)',
            'whitelabel / customize plugin to your brand',
            'wizard / get started quickly',
            'WooCommerce protection (Pro; requires WooCommerce)',
            '404 Guard (Pro; protect from bots that generate excessive 404 errors)',
            'scheduled scanner (Pro)',
            'scheduled reports (Pro; email reports about vulnerabilities and malware)',
            'advanced firewall: country blocking, IP or geolocation blocking, stronger rules, automation',
            'visitor logging (Pro)'
        );
    }

    /**
     * Build the "Plan tier" prompt block to inject into the system instruction.
     * Defaults to free-tier instructions and overwrites with Pro instructions
     * only when secnin_fs()->can_use_premium_code__premium_only() is true.
     *
     * @return string
     */
    public static function get_feature_tier_instructions() {
        $instructions = self::build_free_tier_instructions();
        return $instructions;
    }

    /**
     * Build free-tier instructions (allowed and forbidden recommendations for plan_tier = "free").
     *
     * @return string
     */
    private static function build_free_tier_instructions() {
        $allowed = self::get_free_allowed_recommendations();
        $forbidden = self::get_free_forbidden_recommendations();
        $lines = array(
            'Plan tier:',
            '- Read plan_tier from the context. It is "free".',
            '- When plan_tier is "free", recommend ONLY the following. Do not suggest upgrading or purchasing; suggest only improvements possible within the free version.',
            '- ALLOWED recommendations for free (recommend only these):'
        );
        foreach ( $allowed as $item ) {
            $lines[] = '  • ' . $item;
        }
        $lines[] = '- NEVER recommend any of the following for free users (they are Pro-only):';
        foreach ( $forbidden as $item ) {
            $lines[] = '  • ' . $item;
        }
        $lines[] = '- For top_improvements, include ONLY improvements that use allowed features above.';
        return implode( "\n", $lines );
    }

}
