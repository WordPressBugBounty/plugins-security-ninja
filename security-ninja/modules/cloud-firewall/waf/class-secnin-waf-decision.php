<?php
/**
 * Firewall decision DTO (WordPress-independent).
 *
 * @package Security_Ninja
 */

if ( ! defined( 'SECNIN_WAF_BOOTSTRAP' ) && ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_FS_ATOMIC_STANDALONE' ) ) {
	exit;
}

/**
 * Class Secnin_Waf_Decision
 */
class Secnin_Waf_Decision {

	const ALLOW              = 'allow';
	const BLOCK              = 'block';
	const DEFER_TO_WORDPRESS = 'defer_to_wordpress';
	const ALLOW_OBSERVED     = 'allow_observed_threat';

	/**
	 * @var string
	 */
	public $action = self::ALLOW;

	/**
	 * @var string
	 */
	public $ip = '';

	/**
	 * @var string
	 */
	public $rule = '';

	/**
	 * @var string
	 */
	public $reason = '';

	/**
	 * @var string
	 */
	public $matched_rule = '';

	/**
	 * 8G match surface sent to the Block IP Network (request_uri, query_string, user_agent, referrer).
	 *
	 * @var string
	 */
	public $ban_type = '';

	/**
	 * Capabilities completed while evaluating.
	 *
	 * @var array
	 */
	public $capabilities = array();

	/**
	 * Whether recording should increment blocked counters.
	 *
	 * @var bool
	 */
	public $record_block = false;

	/**
	 * Create a decision.
	 *
	 * @param string $action Action.
	 * @param string $ip     IP.
	 * @param string $rule   Rule.
	 * @param string $reason Reason.
	 * @return self
	 */
	public static function make( $action, $ip = '', $rule = '', $reason = '' ) {
		$d           = new self();
		$d->action   = (string) $action;
		$d->ip       = (string) $ip;
		$d->rule     = (string) $rule;
		$d->reason   = (string) $reason;
		$d->record_block = ( self::BLOCK === $d->action );
		return $d;
	}

	/**
	 * Mark capability.
	 *
	 * @param string $name Name.
	 * @return void
	 */
	public function mark( $name ) {
		$this->capabilities[ (string) $name ] = true;
	}
}
