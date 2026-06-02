<?php
/**
 * AI Security Advisor – admin page UI.
 *
 * Latest audit, follow-up column, settings at bottom.
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

		$full_reports = Wf_Sn_Ai_Advisor_Reports::get_reports( 1, 0, 'full_report' );

		$attack_summary = Wf_Sn_Ai_Advisor_Attack_Activity::build_summary(
			Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d(),
			Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d()
		);
		$counts_7d        = array(
			'current_7d_total' => $attack_summary['current_total'],
			'prev_7d_total'    => $attack_summary['previous_total'],
		);

		$latest_report_data = null;
		if ( ! empty( $full_reports ) ) {
			$first   = $full_reports[0];
			$text    = isset( $first['report_text'] ) ? $first['report_text'] : '';
			$decoded = is_string( $text ) && '' !== $text ? json_decode( $text, true ) : null;
			if ( is_array( $decoded ) && ( isset( $decoded['executive_summary'] ) || isset( $decoded['top_improvements'] ) ) ) {
				Wf_Sn_Ai_Advisor_Improvements::prepare_report_improvements( $decoded );
				$all_imp = isset( $decoded['top_improvements'] ) && is_array( $decoded['top_improvements'] ) ? $decoded['top_improvements'] : array();
				$latest_report_data = array(
					'created'            => isset( $first['created'] ) ? $first['created'] : '',
					'report_json'        => $text,
					'executive_summary'  => isset( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ? $decoded['executive_summary'] : '',
					'top_improvements'   => array_slice( $all_imp, 0, 3 ),
					'top_improvements_rest' => array_slice( $all_imp, 3 ),
					'row_id'             => isset( $first['id'] ) ? (int) $first['id'] : 0,
					'model'              => isset( $first['model'] ) ? (string) $first['model'] : '',
					'token_input'        => isset( $first['token_input'] ) ? (int) $first['token_input'] : 0,
					'token_output'       => isset( $first['token_output'] ) && null !== $first['token_output'] ? (int) $first['token_output'] : 0,
				);
			}
		}

		if ( ! $wp7_available ) {
			self::render_coming_soon();
			return;
		}

		$improvement_links = Wf_Sn_Ai_Advisor::get_improvement_links();

		?>
		<div class="wrap">
		<?php
		\WPSecurityNinja\Plugin\Utils::show_topbar();
		?>
		<div class="secnin_content_wrapper wf-sn-ai-advisor-fullwidth">
			<div class="secnin_content_cell" id="secnin_content_top">
				<div id="sn_tabscont" class="wf-sn-ai-advisor-page">
					<header class="wf-sn-ai-workspace-header">
						<div class="wf-sn-ai-workspace-header__brand">
							<span class="dashicons dashicons-shield wf-sn-ai-workspace-header__icon" aria-hidden="true"></span>
							<div class="wf-sn-ai-workspace-header__titles">
								<h1 class="wf-sn-ai-advisor-heading"><?php esc_html_e( 'Security Advisor', 'security-ninja' ); ?></h1>
								<p class="description wf-sn-ai-workspace-header__tagline"><?php esc_html_e( 'AI Security Advisor uses a cloud service. The plugin continues to function fully without it.', 'security-ninja' ); ?></p>
								<?php if ( $has_connectors && ! empty( $options['last_connector_provider'] ) ) : ?>
									<p class="wf-sn-ai-workspace-meta">
										<?php
										/* translators: %s: connector id (e.g. openai) */
										echo esc_html( sprintf( __( 'AI connector: %s', 'security-ninja' ), $options['last_connector_provider'] ) );
										?>
									</p>
								<?php endif; ?>
							</div>
						</div>
					</header>

					<div class="wf-sn-ai-section wf-sn-ai-panel--interact" id="wf_sn_ai_section_full_report" data-request-type="full_report" data-ui-locale="<?php echo esc_attr( $effective_locale ); ?>">
						<div class="wf-sn-ai-workspace-columns<?php echo $has_connectors ? '' : ' wf-sn-ai-workspace-columns--no-chat'; ?>">
							<div class="wf-sn-ai-report-column">
								<div class="wf-sn-ai-card wf-sn-ai-report-column-card">
									<div class="wf-sn-ai-card-inner">
										<p class="description"><?php esc_html_e( 'Generate an AI report from your latest Security Tests, then ask follow-up questions in the next column.', 'security-ninja' ); ?></p>
										<?php if ( ! $has_connectors ) : ?>
											<p class="description"><?php esc_html_e( 'No AI connectors are configured yet. Add and configure a connector under Settings → Connectors to use the Security Advisor.', 'security-ninja' ); ?></p>
										<?php endif; ?>

										<div class="wf-sn-ai-generate-primary-wrap">
											<button type="button" class="button button-primary button-large wf-sn-ai-trigger wf-sn-ai-generate-btn" data-request-type="full_report" <?php disabled( ! $has_connectors ); ?>>
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
											<div class="wf-sn-ai-result wf-sn-ai-result-canvas wf-sn-ai-result--inline-generate" data-request-type="full_report" aria-live="polite"></div>
										</div>

										<div id="wf_sn_ai_latest_report_card" class="wf-sn-ai-latest-report<?php echo null === $latest_report_data ? ' wf-sn-ai-latest-report--empty' : ''; ?>"
											data-current-7d="<?php echo esc_attr( (string) $counts_7d['current_7d_total'] ); ?>"
											data-prev-7d="<?php echo esc_attr( (string) $counts_7d['prev_7d_total'] ); ?>"
											data-parent-report-id="<?php echo null !== $latest_report_data && ! empty( $latest_report_data['row_id'] ) ? esc_attr( (string) (int) $latest_report_data['row_id'] ) : '0'; ?>"
											data-report-json="<?php echo null !== $latest_report_data ? esc_attr( $latest_report_data['report_json'] ) : ''; ?>">
											<div class="wf-sn-ai-latest-report-primary" id="wf_sn_ai_latest_report_primary">
												<?php if ( null !== $latest_report_data ) : ?>
													<div class="wf-sn-ai-latest-report-header">
														<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Latest Security Report', 'security-ninja' ); ?></h2>
														<span class="wf-sn-ai-latest-report-meta">
															<?php echo esc_html( $latest_report_data['created'] ? human_time_diff( strtotime( $latest_report_data['created'] ), time() ) . ' ' . __( 'ago', 'security-ninja' ) : '' ); ?>
														</span>
														<button type="button" class="button button-link wf-sn-ai-view-full-report" aria-expanded="false"><?php esc_html_e( 'View Full Report', 'security-ninja' ); ?> &rarr;</button>
													</div>
													<div class="wf-sn-ai-latest-report-body">
														<?php if ( '' !== $latest_report_data['executive_summary'] ) : ?>
														<div class="wf-sn-ai-latest-summary">
															<h3 class="wf-sn-ai-report-heading"><?php esc_html_e( 'Executive Summary', 'security-ninja' ); ?></h3>
															<div class="wf-sn-ai-report-body"><?php echo wp_kses_post( wpautop( esc_html( $latest_report_data['executive_summary'] ) ) ); ?></div>
														</div>
														<?php endif; ?>
														<div class="wf-sn-ai-latest-chart-wrap">
															<h3 class="wf-sn-ai-chart-title"><?php esc_html_e( 'Attack Activity (last 7 days)', 'security-ninja' ); ?></h3>
															<div class="wf-sn-ai-attack-chart" id="wf_sn_ai_attack_chart" role="img" aria-label="<?php esc_attr_e( 'Attack activity comparison: previous 7 days vs last 7 days', 'security-ninja' ); ?>"></div>
														</div>
													</div>
													<?php
													if ( ! empty( $latest_report_data['top_improvements'] ) || ! empty( $latest_report_data['top_improvements_rest'] ) ) :
														?>
														<div class="wf-sn-ai-latest-improvements">
															<h3 class="wf-sn-ai-report-heading"><?php esc_html_e( 'Issues needing attention', 'security-ninja' ); ?></h3>
															<ul class="wf-sn-ai-latest-improvements-list wf-sn-ai-latest-improvements-list--top">
																<?php
																foreach ( $latest_report_data['top_improvements'] as $imp ) {
																	echo self::render_latest_improvement_li( $imp, $improvement_links ); // Escaped in helper.
																}
																?>
															</ul>
															<?php if ( ! empty( $latest_report_data['top_improvements_rest'] ) ) : ?>
																<ul class="wf-sn-ai-latest-improvements-list wf-sn-ai-latest-improvements-list--more" id="wf_sn_ai_more_improvements" hidden>
																	<?php
																	foreach ( $latest_report_data['top_improvements_rest'] as $imp ) {
																		echo self::render_latest_improvement_li( $imp, $improvement_links );
																	}
																	?>
																</ul>
																<button type="button" class="button button-link wf-sn-ai-show-more-issues" aria-expanded="false" id="wf_sn_ai_toggle_more_issues"><?php esc_html_e( 'Show more issues', 'security-ninja' ); ?></button>
															<?php endif; ?>
														</div>
													<?php endif; ?>
													<?php
													if ( ! empty( $latest_report_data['model'] ) || ! empty( $latest_report_data['token_input'] ) || ! empty( $latest_report_data['token_output'] ) ) :
														?>
														<p class="description wf-sn-ai-report-usage-meta wf-sn-ai-meta-footer-strip">
															<?php
															/* translators: 1: model, 2: input tokens, 3: output tokens */
															echo esc_html(
																sprintf(
																	__( 'Model: %1$s · Estimated tokens in: %2$s · out: %3$s', 'security-ninja' ),
																	$latest_report_data['model'] ? $latest_report_data['model'] : '—',
																	(string) (int) $latest_report_data['token_input'],
																	(string) (int) $latest_report_data['token_output']
																)
															);
															?>
														</p>
													<?php endif; ?>
													<div class="wf-sn-ai-full-report-expanded" id="wf_sn_ai_full_report_expanded" hidden></div>
												<?php else : ?>
													<p class="description wf-sn-ai-latest-report-empty"><?php esc_html_e( 'No security audit yet. Run Security Tests on the main Security Ninja page, then generate an audit here.', 'security-ninja' ); ?></p>
												<?php endif; ?>
											</div>
										</div>

									</div>
								</div>
							</div>

							<?php if ( $has_connectors ) : ?>
							<div class="wf-sn-ai-chat-column" id="wf_sn_ai_chat_column">
								<div class="wf-sn-ai-card wf-sn-ai-chat-column-card">
									<div class="wf-sn-ai-card-inner wf-sn-ai-chat-column-inner">
										<div class="wf-sn-ai-chat-column__head">
											<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Follow-ups', 'security-ninja' ); ?></h2>
											<p class="description wf-sn-ai-convo-intro"><?php esc_html_e( 'Choose a suggested prompt at the bottom. Messages apply to your current security report only.', 'security-ninja' ); ?></p>
										</div>
										<div class="wf-sn-ai-chat-column__convo-wrap">
											<div class="wf-sn-ai-assistant-output wf-sn-ai-result-canvas wf-sn-ai-assistant-output--convo" id="wf_sn_ai_assistant_output" aria-live="polite">
												<div class="wf-sn-ai-convo-loading" id="wf_sn_ai_convo_loading" role="status" aria-live="polite">
													<span class="spinner is-active" aria-hidden="true"></span>
													<span class="wf-sn-ai-convo-loading__text"><?php esc_html_e( 'Loading messages…', 'security-ninja' ); ?></span>
												</div>
												<div class="wf-sn-ai-convo" id="wf_sn_ai_convo" role="log" aria-label="<?php esc_attr_e( 'Assistant conversation', 'security-ninja' ); ?>" hidden>
													<div class="wf-sn-ai-convo__load-wrap" id="wf_sn_ai_convo_load_wrap" hidden>
														<button type="button" class="button button-link wf-sn-ai-convo__load-older" id="wf_sn_ai_convo_load_older"><?php esc_html_e( 'Load older messages', 'security-ninja' ); ?></button>
													</div>
													<div class="wf-sn-ai-convo__turns" id="wf_sn_ai_convo_turns"></div>
												</div>
												<p class="description wf-sn-ai-empty-state" id="wf_sn_ai_assistant_empty" hidden><?php esc_html_e( 'No messages yet. Choose a suggested prompt below.', 'security-ninja' ); ?></p>
											</div>
											<p class="description wf-sn-ai-chip-status" id="wf_sn_ai_chip_status" hidden></p>
										</div>
										<div class="wf-sn-ai-chat-column__chips" role="toolbar" aria-label="<?php esc_attr_e( 'Suggested prompts', 'security-ninja' ); ?>">
											<div class="wf-sn-ai-chip-row wf-sn-ai-chip-row--footer" id="wf_sn_ai_chip_row">
												<?php foreach ( Wf_Sn_Ai_Advisor_Chips::get_chips_for_ui() as $chip ) : ?>
													<button type="button" class="button wf-sn-ai-chip<?php echo empty( $chip['enabled'] ) ? ' wf-sn-ai-chip--disabled' : ''; ?>" data-prompt-id="<?php echo esc_attr( $chip['id'] ); ?>" <?php disabled( empty( $chip['enabled'] ) ); ?>>
														<?php echo esc_html( $chip['label'] ); ?>
													</button>
												<?php endforeach; ?>
											</div>
										</div>
									</div>
								</div>
							</div>
							<?php endif; ?>

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

					<?php
					$current_connector    = isset( $options['last_connector_provider'] ) ? $options['last_connector_provider'] : '';
					$abilities_exposed    = Wf_Sn_Ai_Advisor_Abilities::is_exposed_enabled();
					$abilities_for_ui     = Wf_Sn_Ai_Advisor_Abilities::get_definitions_for_ui();
					?>
					<div class="wf-sn-ai-card wf-sn-ai-settings-card wf-sn-ai-settings-card--footer sncard settings-card">
						<div class="wf-sn-ai-card-inner">
							<h2 class="wf-sn-ai-section-title"><?php esc_html_e( 'Settings', 'security-ninja' ); ?></h2>
							<p class="description"><?php esc_html_e( 'Connectors are configured in WordPress under Settings → Connectors. Here you choose which AI connector Security Advisor uses to generate reports.', 'security-ninja' ); ?></p>
							<?php if ( empty( $configured_connectors ) ) : ?>
								<p><?php esc_html_e( 'No AI connectors are configured yet. Add and configure a connector under Settings → Connectors to use the Security Advisor.', 'security-ninja' ); ?></p>
								<?php
								$connectors_url = admin_url( 'options-connectors.php' );
								if ( function_exists( 'wp_ai_connectors_admin_url' ) ) {
									$connectors_url = \wp_ai_connectors_admin_url();
								}
								?>
								<p><a href="<?php echo esc_url( $connectors_url ); ?>" class="button button-secondary"><?php esc_html_e( 'Go to Settings → Connectors', 'security-ninja' ); ?></a></p>
							<?php endif; ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wf-sn-ai-settings-form">
								<input type="hidden" name="action" value="wf_sn_ai_advisor_save_settings" />
								<?php wp_nonce_field( 'wf_sn_ai_advisor_save_settings', 'wf_sn_ai_advisor_nonce' ); ?>
								<input type="hidden" name="wf_sn_ai_advisor_provider" value="wordpress_connectors" />
								<table class="form-table wf-sn-ai-settings-table">
									<tbody>
										<?php if ( ! empty( $configured_connectors ) ) : ?>
											<tr valign="top">
												<th scope="row">
													<label for="wf_sn_ai_advisor_connector">
														<h3><?php esc_html_e( 'AI connector', 'security-ninja' ); ?></h3>
														<p class="description"><?php esc_html_e( 'Which configured WordPress AI connector Security Advisor uses to generate reports and follow-ups.', 'security-ninja' ); ?></p>
													</label>
												</th>
												<td class="sn-cf-options">
													<select name="wf_sn_ai_advisor_connector" id="wf_sn_ai_advisor_connector">
														<?php foreach ( $configured_connectors as $conn_id ) : ?>
															<option value="<?php echo esc_attr( $conn_id ); ?>" <?php selected( $current_connector, $conn_id ); ?>><?php echo esc_html( ucfirst( $conn_id ) ); ?></option>
														<?php endforeach; ?>
													</select>
												</td>
											</tr>
										<?php endif; ?>
										<tr valign="top">
											<th scope="row">
												<label for="wf_sn_ai_advisor_abilities_exposed">
													<h3><?php esc_html_e( 'Expose data to WordPress AI abilities', 'security-ninja' ); ?></h3>
													<p class="description"><?php esc_html_e( 'Lets other WordPress AI tools read Security Ninja summaries when enabled. Report generation and follow-ups on this page are not affected.', 'security-ninja' ); ?></p>
												</label>
											</th>
											<td class="sn-cf-options">
												<?php
												\WPSecurityNinja\Plugin\Utils::create_toggle_switch(
													'wf_sn_ai_advisor_abilities_exposed',
													array(
														'value'       => 1,
														'saved_value' => Wf_Sn_Ai_Advisor_Abilities::get_exposed_saved_value(),
														'option_key'  => 'wf_sn_ai_advisor_abilities_exposed',
													)
												);
												?>
											</td>
										</tr>
									</tbody>
								</table>
								<p class="submit wf-sn-ai-settings-submit">
									<button type="submit" class="button button-primary input-button"><?php esc_html_e( 'Save Changes', 'security-ninja' ); ?></button>
								</p>
							</form>
							<div class="wf-sn-ai-abilities-list" aria-labelledby="wf_sn_ai_abilities_list_title">
									<h3 id="wf_sn_ai_abilities_list_title" class="wf-sn-ai-abilities-list__title"><?php esc_html_e( 'WordPress AI abilities', 'security-ninja' ); ?></h3>
									<p class="description wf-sn-ai-abilities-list__intro"><?php esc_html_e( 'When exposure is enabled above, other WordPress AI tools on this site can use these read-only abilities:', 'security-ninja' ); ?></p>
									<?php if ( ! $abilities_exposed ) : ?>
										<div class="wf-sn-ai-abilities-notice notice notice-warning inline">
											<p><?php esc_html_e( 'Not exposed to WordPress AI clients until you enable the setting above and save.', 'security-ninja' ); ?></p>
										</div>
									<?php endif; ?>
									<ul class="wf-sn-ai-abilities-list__items">
										<?php foreach ( $abilities_for_ui as $ability ) : ?>
											<li class="wf-sn-ai-abilities-list__item">
												<strong class="wf-sn-ai-abilities-list__label"><?php echo esc_html( $ability['label'] ); ?></strong>
												<span class="wf-sn-ai-abilities-list__summary"><?php echo esc_html( $ability['summary'] ); ?></span>
											</li>
										<?php endforeach; ?>
									</ul>
							</div>
						</div>
					</div>

				</div>
			</div>
		</div>
		</div>
		<?php
	}

	private static function render_coming_soon() {
		$updates_url = admin_url( 'update-core.php' );
		$main_sn_url = admin_url( 'admin.php?page=wf-sn' );
		?>
		<div class="wrap">
		<?php
		\WPSecurityNinja\Plugin\Utils::show_topbar();
		?>
		<div class="secnin_content_wrapper wf-sn-ai-advisor-fullwidth">
			<div class="secnin_content_cell" id="secnin_content_top">
				<div id="sn_tabscont" class="wf-sn-ai-advisor-page">
					<header class="wf-sn-ai-workspace-header">
						<div class="wf-sn-ai-workspace-header__brand">
							<span class="dashicons dashicons-shield wf-sn-ai-workspace-header__icon" aria-hidden="true"></span>
							<div class="wf-sn-ai-workspace-header__titles">
								<h1 class="wf-sn-ai-advisor-heading"><?php esc_html_e( 'Security Advisor', 'security-ninja' ); ?></h1>
							</div>
						</div>
					</header>
					<div class="wf-sn-ai-wp7-required" role="region" aria-labelledby="wf-sn-ai-wp7-required-title">
						<span class="wf-sn-ai-wp7-required__icon dashicons dashicons-info" aria-hidden="true"></span>
						<div class="wf-sn-ai-wp7-required__body">
							<h2 id="wf-sn-ai-wp7-required-title" class="wf-sn-ai-wp7-required__title"><?php esc_html_e( 'WordPress 7 is required', 'security-ninja' ); ?></h2>
							<p class="wf-sn-ai-wp7-required__lead"><?php esc_html_e( 'Security Advisor uses the built-in AI Connectors in WordPress 7. Once your site is on WordPress 7, you can connect an AI provider in your WordPress settings and generate reports from this page.', 'security-ninja' ); ?></p>
							<ul class="wf-sn-ai-wp7-required__list">
								<li><?php esc_html_e( 'All other Security Ninja features keep working on your current WordPress version.', 'security-ninja' ); ?></li>
								<li><?php esc_html_e( 'After upgrading, configure AI under Settings → Connectors, then return here.', 'security-ninja' ); ?></li>
							</ul>
							<p class="wf-sn-ai-wp7-required__actions">
								<a href="<?php echo esc_url( $updates_url ); ?>" class="button button-primary"><?php esc_html_e( 'Go to Dashboard → Updates', 'security-ninja' ); ?></a>
								<a href="<?php echo esc_url( $main_sn_url ); ?>" class="button button-secondary"><?php esc_html_e( 'Back to Security Ninja', 'security-ninja' ); ?></a>
							</p>
						</div>
					</div>
				</div>
			</div>
		</div>
		</div>
		<?php
	}

	/**
	 * Single improvement list item HTML for latest report.
	 *
	 * @param array $imp               Improvement row from AI JSON.
	 * @param array $improvement_links Map of improvement id => hash fragment (e.g. #sn_tests).
	 * @return string HTML.
	 */
	private static function render_latest_improvement_li( array $imp, array $improvement_links = array() ) {
		$risk = Wf_Sn_Ai_Advisor_Improvements::normalize_risk( $imp );
		$priority_label = 'high' === $risk ? __( 'High Priority', 'security-ninja' ) : ( 'medium' === $risk ? __( 'Medium Priority', 'security-ninja' ) : __( 'Low Priority', 'security-ninja' ) );
		$label          = isset( $imp['short_label'] ) && '' !== $imp['short_label'] ? $imp['short_label'] : ( isset( $imp['title'] ) ? $imp['title'] : '' );
		$title          = isset( $imp['title'] ) && is_string( $imp['title'] ) ? $imp['title'] : '';
		$details        = isset( $imp['details'] ) && is_string( $imp['details'] ) ? $imp['details'] : '';
		$imp_id         = isset( $imp['id'] ) ? (string) $imp['id'] : '';
		$hash           = ( '' !== $imp_id && isset( $improvement_links[ $imp_id ] ) ) ? (string) $improvement_links[ $imp_id ] : '';
		$sn_base        = admin_url( 'admin.php?page=wf-sn' );
		$open_url       = '' !== $hash ? $sn_base . ( 0 === strpos( $hash, '#' ) ? $hash : '#' . $hash ) : '';
		$body_has       = '' !== $details || '' !== $open_url || ( '' !== $title && $title !== $label );

		ob_start();
		if ( $body_has ) :
			/* translators: Hidden accessibility label for expandable issue row; %s: issue title */
			$summary_aria = sprintf( __( 'Show details: %s', 'security-ninja' ), $label );
			?>
		<li class="wf-sn-ai-latest-improvement-item">
			<details class="wf-sn-ai-latest-improvement wf-sn-ai-priority-<?php echo esc_attr( $risk ); ?>">
				<summary class="wf-sn-ai-latest-improvement__summary" aria-label="<?php echo esc_attr( $summary_aria ); ?>">
					<span class="wf-sn-ai-improvement-dot" aria-hidden="true"></span>
					<span class="wf-sn-ai-improvement-label"><?php echo esc_html( $label ); ?></span>
					<span class="wf-sn-ai-priority-badge"><?php echo esc_html( $priority_label ); ?></span>
				</summary>
				<div class="wf-sn-ai-latest-improvement__body">
					<?php if ( '' !== $title && $title !== $label ) : ?>
						<p class="wf-sn-ai-improvement-title"><?php echo esc_html( $title ); ?></p>
					<?php endif; ?>
					<?php if ( '' !== $details ) : ?>
						<div class="wf-sn-ai-improvement-body"><?php echo wp_kses_post( nl2br( esc_html( $details ) ) ); ?></div>
					<?php endif; ?>
					<?php if ( '' !== $open_url ) : ?>
						<p class="wf-sn-ai-improvement-actions">
							<a href="<?php echo esc_url( $open_url ); ?>" class="wf-sn-ai-improvement-link" target="_blank" rel="noopener"><?php esc_html_e( 'Open in Security Ninja', 'security-ninja' ); ?></a>
						</p>
					<?php endif; ?>
				</div>
			</details>
		</li>
			<?php
		else :
			?>
		<li class="wf-sn-ai-latest-improvement-item wf-sn-ai-latest-improvement-item--static">
			<div class="wf-sn-ai-latest-improvement wf-sn-ai-priority-<?php echo esc_attr( $risk ); ?> wf-sn-ai-latest-improvement--static">
				<span class="wf-sn-ai-improvement-dot" aria-hidden="true"></span>
				<span class="wf-sn-ai-improvement-label"><?php echo esc_html( $label ); ?></span>
				<span class="wf-sn-ai-priority-badge"><?php echo esc_html( $priority_label ); ?></span>
			</div>
		</li>
			<?php
		endif;
		return (string) ob_get_clean();
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
