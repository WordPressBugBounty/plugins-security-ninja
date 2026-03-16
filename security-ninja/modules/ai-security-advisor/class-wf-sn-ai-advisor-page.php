<?php
/**
 * AI Security Advisor – admin page UI.
 *
 * Single full report, previous reports list, settings at bottom.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

use function WPSecurityNinja\Plugin\secnin_fs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Page
 */
class Wf_Sn_Ai_Advisor_Page {

	const OPTION_KEY = 'wf_sn_ai_advisor';

	/**
	 * Render the Security Advisor page.
	 *
	 * @return void
	 */
	public static function render() {
		$wp7_available         = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available();
		$options               = self::get_options();
		$configured_connectors = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
		$has_connectors        = ! empty( $configured_connectors );

		$docs_url  = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'what_happens_link', '/docs/security-advisor/what-happens-when-you-generate-a-report/' );
		$ui_locale = isset( $options['ui_locale'] ) && '' !== $options['ui_locale'] ? $options['ui_locale'] : ( function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale() );

		// Compute an effective locale that actually exists in the available translations list.
		$effective_locale                  = $ui_locale;
		$available_translations_for_locale = array();
		if ( is_admin() && ! function_exists( 'wp_get_available_translations' ) ) {
			require_once ABSPATH . 'wp-admin/includes/translation-install.php';
		}
		if ( function_exists( 'wp_get_available_translations' ) ) {
			$available_translations_for_locale = wp_get_available_translations();
			if ( is_array( $available_translations_for_locale ) && ! empty( $available_translations_for_locale ) ) {
				if ( ! isset( $available_translations_for_locale[ $effective_locale ] ) ) {
					$site_locale = function_exists( 'get_locale' ) ? get_locale() : '';
					// Try exact site locale.
					if ( $site_locale && isset( $available_translations_for_locale[ $site_locale ] ) ) {
						$effective_locale = $site_locale;
					} else {
						// Try matching language part (e.g. en_*) for ui_locale first.
						$lang = substr( $effective_locale, 0, 2 );
						if ( '' !== $lang ) {
							foreach ( $available_translations_for_locale as $code => $data ) {
								if ( 0 === strpos( $code, $lang . '_' ) ) {
									$effective_locale = $code;
									break;
								}
							}
						}
						// If still no match, try language part of site locale.
						if ( ! isset( $available_translations_for_locale[ $effective_locale ] ) && '' !== $site_locale ) {
							$lang = substr( $site_locale, 0, 2 );
							if ( '' !== $lang ) {
								foreach ( $available_translations_for_locale as $code => $data ) {
									if ( 0 === strpos( $code, $lang . '_' ) ) {
										$effective_locale = $code;
										break;
									}
								}
							}
						}
					}
				}
			}
		}

		$last_test = null;
		$results   = get_option( 'wf_sn_results', array() );
		if ( is_array( $results ) && ! empty( $results['last_run'] ) ) {
			$last_test = (int) $results['last_run'];
		}

		$reports = array();
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Reports' ) ) {
			$reports = Wf_Sn_Ai_Advisor_Reports::get_reports( 10, 0 );
		}

		$counts_7d   = array(
			'current_7d_total' => 0,
			'prev_7d_total'    => 0,
		);
		$prev_counts = array();
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Aggregation' ) ) {
			$curr                          = Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d();
			$prev                          = Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d();
			$counts_7d['current_7d_total'] = (int) ( isset( $curr['blocked_logins_7d'] ) ? $curr['blocked_logins_7d'] : 0 ) + (int) ( isset( $curr['xmlrpc_blocks_7d'] ) ? $curr['xmlrpc_blocks_7d'] : 0 ) + (int) ( isset( $curr['firewall_events_7d'] ) ? $curr['firewall_events_7d'] : 0 ) + (int) ( isset( $curr['failed_logins_7d'] ) ? $curr['failed_logins_7d'] : 0 );
			$counts_7d['prev_7d_total']    = (int) ( isset( $prev['blocked_logins_prev_7d'] ) ? $prev['blocked_logins_prev_7d'] : 0 ) + (int) ( isset( $prev['xmlrpc_blocks_prev_7d'] ) ? $prev['xmlrpc_blocks_prev_7d'] : 0 ) + (int) ( isset( $prev['firewall_events_prev_7d'] ) ? $prev['firewall_events_prev_7d'] : 0 ) + (int) ( isset( $prev['failed_logins_prev_7d'] ) ? $prev['failed_logins_prev_7d'] : 0 );
		}

		$latest_report_data = null;
		if ( ! empty( $reports ) ) {
			$first   = $reports[0];
			$text    = isset( $first['report_text'] ) ? $first['report_text'] : '';
			$decoded = is_string( $text ) && '' !== $text ? json_decode( $text, true ) : null;
			if ( is_array( $decoded ) && ( isset( $decoded['executive_summary'] ) || isset( $decoded['top_improvements'] ) ) ) {
				$improvements = isset( $decoded['top_improvements'] ) && is_array( $decoded['top_improvements'] ) ? $decoded['top_improvements'] : array();
				$risk_order  = array( 'low' => 0, 'medium' => 1, 'high' => 2 );
				usort( $improvements, function ( $a, $b ) use ( $risk_order ) {
					$r_a = isset( $a['risk'] ) ? ( $risk_order[ strtolower( (string) $a['risk'] ) ] ?? 0 ) : 0;
					$r_b = isset( $b['risk'] ) ? ( $risk_order[ strtolower( (string) $b['risk'] ) ] ?? 0 ) : 0;
					return $r_a - $r_b;
				} );
				$latest_report_data = array(
					'created'           => isset( $first['created'] ) ? $first['created'] : '',
					'report_json'       => $text,
					'executive_summary' => isset( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ? $decoded['executive_summary'] : '',
					'top_improvements'  => array_slice( $improvements, 0, 3 ),
				);
			}
		}

		if ( ! $wp7_available ) {
			self::render_coming_soon();
			return;
		}

		\WPSecurityNinja\Plugin\Utils::show_topbar();
		?>
		<div class="secnin_content_wrapper wf-sn-ai-advisor-fullwidth">
			<div class="secnin_content_cell" id="secnin_content_top">
				<div id="sn_tabscont" class="wf-sn-ai-advisor-page">
					<h1 class="wf-sn-ai-advisor-heading"><?php esc_html_e( 'Security Advisor', 'security-ninja' ); ?></h1>
					<p class="description"><?php esc_html_e( 'AI Security Advisor uses a cloud service. The plugin continues to function fully without it.', 'security-ninja' ); ?></p>

					<?php if ( $last_test ) : ?>
						<p class="description">
						<?php
						/* translators: %s: human-readable time difference (e.g. "2 hours") */
						echo esc_html( sprintf( __( 'Last security test: %s ago.', 'security-ninja' ), human_time_diff( $last_test, time() ) ) );
						?>
						</p>
					<?php endif; ?>

					<div class="wf-sn-ai-section wf-sn-ai-generate-block wf-sn-ai-card wf-sn-ai-generate-block-first" id="wf_sn_ai_section_full_report" data-request-type="full_report" data-ui-locale="<?php echo esc_attr( $effective_locale ); ?>">
						<div class="wf-sn-ai-card-inner">
							<?php if ( ! $has_connectors ) : ?>
								<p class="description"><?php esc_html_e( 'No AI connectors are configured yet. Add and configure a connector under Settings → Connectors to use the Security Advisor.', 'security-ninja' ); ?></p>
							<?php endif; ?>
							<div class="wf-sn-ai-generate-row">
								<button type="button" class="button button-primary wf-sn-ai-trigger wf-sn-ai-generate-btn" data-request-type="full_report" <?php disabled( ! $has_connectors ); ?>>
									<span class="dashicons dashicons-update" aria-hidden="true"></span> <?php esc_html_e( 'Generate Security Audit', 'security-ninja' ); ?>
								</button>
							</div>
							<p class="wf-sn-ai-preview-data-row description">
								<a href="#" class="wf-sn-ai-preview-data-link" data-request-type="full_report" aria-describedby="wf_sn_ai_preview_modal_title"><?php esc_html_e( 'Preview data sent to AI', 'security-ninja' ); ?></a>
							</p>
							<p class="wf-sn-ai-what-happens description">
								<?php esc_html_e( 'We send test results and event counts to the AI provider. No personal data.', 'security-ninja' ); ?>
								<a href="<?php echo esc_url( $docs_url ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Learn more', 'security-ninja' ); ?></a>
							</p>
							<div class="wf-sn-ai-result-wrapper" style="display: none;">
								<div class="wf-sn-ai-result-stage" aria-live="polite"></div>
								<span class="wf-sn-ai-result-timer" aria-hidden="true">0.0s</span>
								<div class="wf-sn-ai-waiting-tip" aria-live="polite" hidden>
									<span class="wf-sn-ai-waiting-tip-icon dashicons dashicons-lightbulb" aria-hidden="true"></span>
									<span class="wf-sn-ai-waiting-tip-text"></span>
								</div>
								<div class="wf-sn-ai-result" data-request-type="full_report" aria-live="polite"></div>
							</div>
						</div>
					</div>

					<div id="wf_sn_ai_preview_modal" class="wf-sn-ai-preview-modal" role="dialog" aria-labelledby="wf_sn_ai_preview_modal_title" aria-modal="true" hidden>
						<div class="wf-sn-ai-preview-modal-backdrop"></div>
						<div class="wf-sn-ai-preview-modal-content">
							<div class="wf-sn-ai-preview-modal-header">
								<h2 id="wf_sn_ai_preview_modal_title" class="wf-sn-ai-preview-modal-title"><?php esc_html_e( 'Preview of data sent to AI', 'security-ninja' ); ?></h2>
								<button type="button" class="wf-sn-ai-preview-modal-close button-link" aria-label="<?php esc_attr_e( 'Close', 'security-ninja' ); ?>">&times;</button>
							</div>
							<div class="wf-sn-ai-preview-modal-body">
								<pre><code class="wf-sn-ai-preview-data-content"></code></pre>
							</div>
						</div>
					</div>

					<?php if ( null !== $latest_report_data ) : ?>
						<div class="wf-sn-ai-card wf-sn-ai-latest-report" id="wf_sn_ai_latest_report_card"
							data-current-7d="<?php echo esc_attr( (string) $counts_7d['current_7d_total'] ); ?>"
							data-prev-7d="<?php echo esc_attr( (string) $counts_7d['prev_7d_total'] ); ?>"
							data-report-json="<?php echo esc_attr( $latest_report_data['report_json'] ); ?>">
							<div class="wf-sn-ai-card-inner">
								<div class="wf-sn-ai-latest-report-header">
									<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Latest Security Report', 'security-ninja' ); ?></h2>
									<span class="wf-sn-ai-latest-report-meta">
										<?php echo esc_html( $latest_report_data['created'] ? human_time_diff( strtotime( $latest_report_data['created'] ), time() ) . ' ' . __( 'ago', 'security-ninja' ) : '' ); ?>
									</span>
								</div>
								<?php
								$report_created_ts = ! empty( $latest_report_data['created'] ) ? strtotime( $latest_report_data['created'] ) : 0;
								$stale_message     = '';
								if ( $last_test && $report_created_ts && $report_created_ts < $last_test ) {
									$stale_message = __( 'This report may be outdated. Run Security Tests, then generate a new report for current results.', 'security-ninja' );
								} elseif ( $last_test && $last_test < ( time() - 7 * DAY_IN_SECONDS ) ) {
									$stale_message = __( 'Security tests were last run over 7 days ago. Run Security Tests, then generate a new report for up-to-date advice.', 'security-ninja' );
								}
								if ( '' !== $stale_message ) :
									$run_tests_url = admin_url( 'admin.php?page=wf-sn#sn_tests' );
									?>
									<p class="wf-sn-ai-stale-notice description">
										<?php echo esc_html( $stale_message ); ?>
										<a href="<?php echo esc_url( $run_tests_url ); ?>"><?php esc_html_e( 'Run Security Tests', 'security-ninja' ); ?></a>
									</p>
								<?php endif; ?>
								<div class="wf-sn-ai-latest-report-body">
									<div class="wf-sn-ai-latest-chart-wrap">
										<h3 class="wf-sn-ai-chart-title"><?php esc_html_e( 'Attack Activity (last 7 days)', 'security-ninja' ); ?></h3>
										<div class="wf-sn-ai-attack-chart" id="wf_sn_ai_attack_chart" role="img" aria-label="<?php esc_attr_e( 'Attack activity comparison: previous 7 days vs last 7 days', 'security-ninja' ); ?>"></div>
									</div>
								</div>
								<?php if ( '' !== $latest_report_data['executive_summary'] ) : ?>
									<div class="wf-sn-ai-latest-summary">
										<h3 class="wf-sn-ai-report-heading"><?php esc_html_e( 'Executive Summary', 'security-ninja' ); ?></h3>
										<div class="wf-sn-ai-report-body"><?php echo wp_kses_post( wpautop( esc_html( $latest_report_data['executive_summary'] ) ) ); ?></div>
									</div>
								<?php endif; ?>
								<p class="wf-sn-ai-view-full-report-wrap">
									<button type="button" class="button button-link wf-sn-ai-view-full-report" aria-expanded="false"><?php esc_html_e( 'View Full Report', 'security-ninja' ); ?> &rarr;</button>
								</p>
								<div class="wf-sn-ai-full-report-expanded" id="wf_sn_ai_full_report_expanded" hidden></div>
							</div>
						</div>
					<?php endif; ?>

					<?php if ( ! empty( $reports ) ) : ?>
						<div class="wf-sn-ai-previous-reports wf-sn-ai-card">
							<div class="wf-sn-ai-card-inner">
								<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Previous Reports', 'security-ninja' ); ?></h2>
								<table class="wf-sn-ai-reports-table widefat striped">
									<thead>
										<tr>
											<th scope="col"><?php esc_html_e( 'Date', 'security-ninja' ); ?></th>
											<th scope="col"><?php esc_html_e( 'Summary', 'security-ninja' ); ?></th>
											<th scope="col"><?php esc_html_e( 'Actions', 'security-ninja' ); ?></th>
										</tr>
									</thead>
									<tbody>
									<?php foreach ( $reports as $report ) : ?>
										<?php
										$created  = isset( $report['created'] ) ? $report['created'] : '';
										$text     = isset( $report['report_text'] ) ? $report['report_text'] : '';
										$id       = isset( $report['id'] ) ? (int) $report['id'] : 0;
										$time_ago = $created ? human_time_diff( strtotime( $created ), time() ) . ' ' . __( 'ago', 'security-ninja' ) : '';

										$decoded   = is_string( $text ) && '' !== $text ? json_decode( $text, true ) : null;
										$is_report = is_array( $decoded ) && ! empty( $decoded ) && (
											isset( $decoded['executive_summary'] ) ||
											isset( $decoded['overview'] ) ||
											( isset( $decoded['top_improvements'] ) && is_array( $decoded['top_improvements'] ) ) ||
											isset( $decoded['activity'] )
										);

										if ( $is_report ) {
											$preview_source = '';
											if ( ! empty( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ) {
												$preview_source = $decoded['executive_summary'];
											} elseif ( ! empty( $decoded['overview'] ) && is_string( $decoded['overview'] ) ) {
												$preview_source = $decoded['overview'];
											}
											$preview = '' !== $preview_source ? wp_trim_words( $preview_source, 15 ) : wp_trim_words( $text, 15 );
										} else {
											$preview = wp_trim_words( $text, 15 );
										}
										?>
										<tr class="wf-sn-ai-report-row" data-report-id="<?php echo esc_attr( $id ); ?>"<?php echo $is_report ? ' data-report-json="' . esc_attr( $text ) . '"' : ''; ?>>
											<td><?php echo esc_html( $time_ago ); ?></td>
											<td class="wf-sn-ai-report-summary"><?php echo esc_html( $preview ); ?></td>
											<td>
												<button type="button" class="button button-small wf-sn-ai-report-toggle" aria-expanded="false"><?php esc_html_e( 'View Report', 'security-ninja' ); ?></button>
											</td>
										</tr>
										<?php if ( $is_report ) : ?>
										<tr class="wf-sn-ai-report-detail-row" id="wf_sn_ai_report_detail_<?php echo esc_attr( $id ); ?>" hidden>
											<td colspan="3" class="wf-sn-ai-report-detail-cell"><div class="wf-sn-ai-report-full"></div></td>
										</tr>
										<?php else : ?>
										<tr class="wf-sn-ai-report-detail-row" id="wf_sn_ai_report_detail_<?php echo esc_attr( $id ); ?>" hidden>
											<td colspan="3" class="wf-sn-ai-report-detail-cell"><div class="wf-sn-ai-report-full"><?php echo wp_kses_post( wpautop( esc_html( $text ) ) ); ?></div></td>
										</tr>
										<?php endif; ?>
									<?php endforeach; ?>
									</tbody>
								</table>
							</div>
						</div>
					<?php endif; ?>

					<?php
					$current_connector = isset( $options['last_connector_provider'] ) ? $options['last_connector_provider'] : '';
					?>
					<div class="wf-sn-ai-card wf-sn-ai-settings-card">
						<div class="wf-sn-ai-card-inner">
							<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Settings', 'security-ninja' ); ?></h2>
							<p class="description"><?php esc_html_e( 'Connectors are configured in WordPress under Settings → Connectors. Here you choose which AI connector Security Advisor uses to generate reports.', 'security-ninja' ); ?></p>
							<?php if ( ! empty( $configured_connectors ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wf-sn-ai-settings-form">
									<input type="hidden" name="action" value="wf_sn_ai_advisor_save_settings" />
									<?php wp_nonce_field( 'wf_sn_ai_advisor_save_settings', 'wf_sn_ai_advisor_nonce' ); ?>
									<input type="hidden" name="wf_sn_ai_advisor_provider" value="wordpress_connectors" />
									<p>
										<label for="wf_sn_ai_advisor_connector"><?php esc_html_e( 'AI connector', 'security-ninja' ); ?></label>
										<select name="wf_sn_ai_advisor_connector" id="wf_sn_ai_advisor_connector">
											<?php foreach ( $configured_connectors as $conn_id ) : ?>
												<option value="<?php echo esc_attr( $conn_id ); ?>" <?php selected( $current_connector, $conn_id ); ?>><?php echo esc_html( ucfirst( $conn_id ) ); ?></option>
											<?php endforeach; ?>
										</select>
									</p>
									<p>
										<button type="submit" class="button button-primary"><?php esc_html_e( 'Save', 'security-ninja' ); ?></button>
									</p>
								</form>
							<?php else : ?>
								<p><?php esc_html_e( 'No AI connectors are configured yet. Add and configure a connector under Settings → Connectors to use the Security Advisor.', 'security-ninja' ); ?></p>
								<?php
								$connectors_url = admin_url( 'options-connectors.php' );
								if ( function_exists( 'wp_ai_connectors_admin_url' ) ) {
									$connectors_url = \wp_ai_connectors_admin_url();
								}
								?>
								<p><a href="<?php echo esc_url( $connectors_url ); ?>" class="button button-secondary"><?php esc_html_e( 'Go to Settings → Connectors', 'security-ninja' ); ?></a></p>
							<?php endif; ?>
						</div>
					</div>

				</div>
			</div>
		</div>
		<?php
	}

	private static function render_coming_soon() {
		\WPSecurityNinja\Plugin\Utils::show_topbar();
		?>
		<div class="secnin_content_wrapper wf-sn-ai-advisor-fullwidth">
			<div class="secnin_content_cell" id="secnin_content_top">
				<div id="sn_tabscont" class="wf-sn-ai-advisor-page">
					<h1 class="wf-sn-ai-advisor-heading"><?php esc_html_e( 'Security Advisor', 'security-ninja' ); ?></h1>
					<div class="wf-sn-ai-section wf-sn-ai-card wf-sn-ai-coming-soon-card">
						<div class="wf-sn-ai-card-inner">
							<p class="description"><?php esc_html_e( 'The Security Advisor uses WordPress 7 AI Connectors. Update to WordPress 7 to use AI Connectors and the Security Advisor from this page.', 'security-ninja' ); ?></p>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Get stored options.
	 *
	 * @return array
	 */
	public static function get_options() {
		$opts = get_option( self::OPTION_KEY, array() );
		return is_array( $opts ) ? $opts : array();
	}

	/**
	 * Update a single option key.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 */
	public static function set_option( $key, $value ) {
		$opts         = self::get_options();
		$opts[ $key ] = $value;
		update_option( self::OPTION_KEY, $opts, true );
	}
}
