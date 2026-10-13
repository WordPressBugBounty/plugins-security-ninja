<?php

/**
 * AI Security Advisor – admin page UI.
 *
 * Latest audit, follow-up column, settings at bottom.
 *
 * @package Security_Ninja
 */
namespace WPSecurityNinja\Plugin\AiAdvisor;

use WPSecurityNinja\Plugin\Wf_Sn_Admin_Links;
use WPSecurityNinja\Plugin\Wf_Sn_Priority_Resolver;
use WPSecurityNinja\Plugin\Wf_Sn_Security_Snapshot_Diff;
use function WPSecurityNinja\Plugin\secnin_fs;
if ( !defined( 'ABSPATH' ) ) {
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
        $wp7_available = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::is_available();
        $options = self::get_options();
        $configured_connectors = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_configured_providers();
        $ai_state = Wf_Sn_Ai_Advisor::get_card_state();
        $has_connectors = !empty( $ai_state['has_connectors'] );
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        $show_docs_link = true;
        $docs_url = \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'ai_advisor_docs', '/docs/security-advisor/what-happens-when-you-generate-a-report/' );
        $ui_locale = ( isset( $options['ui_locale'] ) && '' !== $options['ui_locale'] ? $options['ui_locale'] : (( function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale() )) );
        // Compute an effective locale that actually exists in the available translations list.
        $effective_locale = $ui_locale;
        $available_translations_for_locale = array();
        if ( is_admin() && !function_exists( 'wp_get_available_translations' ) ) {
            require_once ABSPATH . 'wp-admin/includes/translation-install.php';
        }
        if ( function_exists( 'wp_get_available_translations' ) ) {
            $available_translations_for_locale = wp_get_available_translations();
            if ( is_array( $available_translations_for_locale ) && !empty( $available_translations_for_locale ) ) {
                if ( !isset( $available_translations_for_locale[$effective_locale] ) ) {
                    $site_locale = ( function_exists( 'get_locale' ) ? get_locale() : '' );
                    // Try exact site locale.
                    if ( $site_locale && isset( $available_translations_for_locale[$site_locale] ) ) {
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
                        if ( !isset( $available_translations_for_locale[$effective_locale] ) && '' !== $site_locale ) {
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
        $attack_summary = Wf_Sn_Ai_Advisor_Attack_Activity::build_summary( Wf_Sn_Ai_Advisor_Aggregation::get_counts_7d(), Wf_Sn_Ai_Advisor_Aggregation::get_counts_prev_7d() );
        $counts_7d = array(
            'current_7d_total' => $attack_summary['current_total'],
            'prev_7d_total'    => $attack_summary['previous_total'],
        );
        $latest_report_data = null;
        if ( !empty( $full_reports ) ) {
            $first = $full_reports[0];
            $text = ( isset( $first['report_text'] ) ? $first['report_text'] : '' );
            $decoded = ( is_string( $text ) && '' !== $text ? json_decode( $text, true ) : null );
            if ( is_array( $decoded ) && (isset( $decoded['executive_summary'] ) || isset( $decoded['top_improvements'] )) ) {
                Wf_Sn_Ai_Advisor_Improvements::prepare_report_improvements( $decoded );
                $all_imp = ( isset( $decoded['top_improvements'] ) && is_array( $decoded['top_improvements'] ) ? $decoded['top_improvements'] : array() );
                $latest_report_data = array(
                    'created'               => ( isset( $first['created'] ) ? $first['created'] : '' ),
                    'report_json'           => $text,
                    'executive_summary'     => ( isset( $decoded['executive_summary'] ) && is_string( $decoded['executive_summary'] ) ? $decoded['executive_summary'] : '' ),
                    'top_improvements'      => array_slice( $all_imp, 0, 3 ),
                    'top_improvements_rest' => array_slice( $all_imp, 3 ),
                    'row_id'                => ( isset( $first['id'] ) ? (int) $first['id'] : 0 ),
                    'model'                 => ( isset( $first['model'] ) ? (string) $first['model'] : '' ),
                    'token_input'           => ( isset( $first['token_input'] ) ? (int) $first['token_input'] : 0 ),
                    'token_output'          => ( isset( $first['token_output'] ) && null !== $first['token_output'] ? (int) $first['token_output'] : 0 ),
                );
            }
        }
        if ( !$wp7_available ) {
            self::render_coming_soon();
            return;
        }
        $improvement_links = Wf_Sn_Ai_Advisor::get_improvement_links();
        $connectors_url = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_admin_url();
        $connectors_for_ui = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_connectors_for_ui();
        $selected_meta = Wf_Sn_Ai_Advisor_Provider_Wp_Connectors::get_selected_connector_metadata();
        $history_counts = Wf_Sn_Ai_Advisor_Reports::count_all();
        $connection_state = Wf_Sn_Ai_Advisor_Schedule_Policy::get_connection_state();
        $scheduler_url = \WPSecurityNinja\Plugin\Wf_Sn_Admin_Links::url( 'scheduler' );
        $schedule_enabled = self::is_scheduled_report_enabled();
        $schedule_interval = self::get_scheduled_report_interval();
        $scheduler_state = ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Scheduler' ) ? Wf_Sn_Ai_Advisor_Scheduler::get_scheduler_state() : array(
            'timestamp' => 0,
            'backend'   => 'none',
        ) );
        $schedule_status = ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Ai_Advisor_Scheduler' ) ? Wf_Sn_Ai_Advisor_Scheduler::get_status_line(
            $schedule_enabled,
            $connection_state,
            $schedule_interval,
            $scheduler_state
        ) : '' );
        $has_report = null !== $latest_report_data;
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
								<h1 class="wf-sn-ai-advisor-heading"><?php 
        esc_html_e( 'AI Security Advisor', 'security-ninja' );
        ?></h1>
								<p class="description wf-sn-ai-workspace-header__tagline"><?php 
        echo esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( '%s scans your site. The AI Advisor explains what changed, what matters, and what to fix first.', 'security-ninja' ),
            $plugin_name
         ) );
        ?></p>
								<?php 
        self::render_status_line(
            $has_connectors,
            $selected_meta,
            $connectors_url,
            $has_report,
            $latest_report_data,
            $schedule_status,
            $scheduler_url
        );
        ?>
								<p class="description wf-sn-ai-privacy-line"><?php 
        esc_html_e( 'Only scan results, event counts, and security summaries are sent to your selected AI provider. No personal data is sent.', 'security-ninja' );
        ?></p>
							</div>
						</div>
					</header>

					<div class="wf-sn-ai-section wf-sn-ai-panel--interact" id="wf_sn_ai_section_full_report" data-request-type="full_report" data-ui-locale="<?php 
        echo esc_attr( $effective_locale );
        ?>">
						<div class="wf-sn-ai-workspace-columns wf-sn-ai-workspace-columns--single">
							<div class="wf-sn-ai-report-column">
								<div class="wf-sn-ai-card wf-sn-ai-report-column-card">
									<div class="wf-sn-ai-card-inner">
										<?php 
        $readiness_issues = array();
        foreach ( Wf_Sn_Ai_Advisor_Readiness::get_items() as $item ) {
            if ( 'ready' !== $item['status'] ) {
                $readiness_issues[] = $item;
            }
        }
        if ( !empty( $readiness_issues ) ) {
            self::render_readiness_compact();
        }
        ?>

										<?php 
        if ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NO_CONNECTOR === $connection_state ) {
            ?>
											<div class="wf-sn-ai-onboarding-steps" role="region" aria-label="<?php 
            esc_attr_e( 'Getting started with AI connectors', 'security-ninja' );
            ?>">
												<p><?php 
            esc_html_e( 'Connect an AI provider under Settings → Connectors, then generate your first review here.', 'security-ninja' );
            ?></p>
												<p class="wf-sn-ai-onboarding-steps__actions">
													<a href="<?php 
            echo esc_url( $connectors_url );
            ?>" class="button button-primary"><?php 
            esc_html_e( 'Go to Settings → Connectors', 'security-ninja' );
            ?></a>
												</p>
											</div>
										<?php 
        } elseif ( Wf_Sn_Ai_Advisor_Schedule_Policy::STATE_NOT_SELECTED === $connection_state ) {
            ?>
											<div class="wf-sn-ai-onboarding-steps" role="region">
												<p><?php 
            esc_html_e( 'Choose which AI connector to use in AI connection below, then generate a review.', 'security-ninja' );
            ?></p>
											</div>
										<?php 
        }
        ?>

										<?php 
        if ( !$has_report ) {
            ?>
											<p class="description wf-sn-ai-generate-lead"><?php 
            echo esc_html( sprintf( 
                /* translators: %s: plugin display name */
                __( 'Generate your first AI review from the latest %s scan data.', 'security-ninja' ),
                $plugin_name
             ) );
            ?></p>
											<div class="wf-sn-ai-generate-primary-wrap">
												<button type="button" class="button button-primary button-large wf-sn-ai-trigger wf-sn-ai-generate-btn" data-request-type="full_report" <?php 
            disabled( !$has_connectors );
            ?>>
													<?php 
            esc_html_e( 'Generate your first review', 'security-ninja' );
            ?>
												</button>
											</div>
										<?php 
        }
        ?>

										<?php 
        if ( $has_connectors ) {
            ?>
											<p class="wf-sn-ai-preview-data-row description">
												<a href="#" class="wf-sn-ai-preview-data-link" data-request-type="full_report" aria-describedby="wf_sn_ai_preview_modal_title"><?php 
            esc_html_e( 'Preview data sent to AI', 'security-ninja' );
            ?></a>
												<?php 
            if ( $show_docs_link ) {
                ?>
													<a href="<?php 
                echo esc_url( $docs_url );
                ?>" target="_blank" rel="noopener"><?php 
                esc_html_e( 'Learn more', 'security-ninja' );
                ?></a>
												<?php 
            }
            ?>
											</p>
										<?php 
        }
        ?>

										<div class="wf-sn-ai-result-wrapper" style="display: none;">
											<div class="wf-sn-ai-result-stage" aria-live="polite"></div>
											<p class="wf-sn-ai-result-stats description" hidden></p>
											<span class="wf-sn-ai-result-timer" aria-hidden="true">0.0s</span>
											<div class="wf-sn-ai-waiting-tip" aria-live="polite" hidden>
												<span class="wf-sn-ai-waiting-tip-icon dashicons dashicons-lightbulb" aria-hidden="true"></span>
												<span class="wf-sn-ai-waiting-tip-text"></span>
											</div>
											<div class="wf-sn-ai-result wf-sn-ai-result-canvas wf-sn-ai-result--inline-generate" data-request-type="full_report" aria-live="polite"></div>
										</div>

										<div id="wf_sn_ai_latest_report_card" class="wf-sn-ai-latest-report<?php 
        echo ( $has_report ? '' : ' wf-sn-ai-latest-report--empty' );
        ?>"
											data-current-7d="<?php 
        echo esc_attr( (string) $counts_7d['current_7d_total'] );
        ?>"
											data-prev-7d="<?php 
        echo esc_attr( (string) $counts_7d['prev_7d_total'] );
        ?>"
											data-parent-report-id="<?php 
        echo ( $has_report && !empty( $latest_report_data['row_id'] ) ? esc_attr( (string) (int) $latest_report_data['row_id'] ) : '0' );
        ?>"
											data-report-json="<?php 
        echo ( $has_report ? esc_attr( $latest_report_data['report_json'] ) : '' );
        ?>">
											<div class="wf-sn-ai-latest-report-primary" id="wf_sn_ai_latest_report_primary">
												<?php 
        if ( $has_report ) {
            ?>
													<div class="wf-sn-ai-latest-report-header">
														<h2 class="wf-sn-ai-section-title"><?php 
            esc_html_e( 'Latest Security Report', 'security-ninja' );
            ?></h2>
														<span class="wf-sn-ai-latest-report-meta">
															<?php 
            echo esc_html( ( $latest_report_data['created'] ? human_time_diff( strtotime( $latest_report_data['created'] ), time() ) . ' ' . __( 'ago', 'security-ninja' ) : '' ) );
            ?>
														</span>
														<button type="button" class="button button-link wf-sn-ai-view-full-report" aria-expanded="false"><?php 
            esc_html_e( 'View Full Report', 'security-ninja' );
            ?> &rarr;</button>
													</div>
													<div class="wf-sn-ai-latest-report-body">
														<?php 
            if ( '' !== $latest_report_data['executive_summary'] ) {
                ?>
														<div class="wf-sn-ai-latest-summary">
															<h3 class="wf-sn-ai-report-heading"><?php 
                esc_html_e( 'Executive Summary', 'security-ninja' );
                ?></h3>
															<div class="wf-sn-ai-report-body"><?php 
                echo wp_kses_post( wpautop( esc_html( $latest_report_data['executive_summary'] ) ) );
                ?></div>
														</div>
														<?php 
            }
            ?>
														<div class="wf-sn-ai-latest-chart-wrap">
															<h3 class="wf-sn-ai-chart-title"><?php 
            esc_html_e( 'Attack Activity (last 7 days)', 'security-ninja' );
            ?></h3>
															<div class="wf-sn-ai-attack-chart" id="wf_sn_ai_attack_chart" role="img" aria-label="<?php 
            esc_attr_e( 'Attack activity comparison: previous 7 days vs last 7 days', 'security-ninja' );
            ?>"></div>
														</div>
													</div>
													<?php 
            if ( !empty( $latest_report_data['top_improvements'] ) || !empty( $latest_report_data['top_improvements_rest'] ) ) {
                ?>
														<div class="wf-sn-ai-latest-improvements">
															<h3 class="wf-sn-ai-report-heading"><?php 
                esc_html_e( 'Issues needing attention', 'security-ninja' );
                ?></h3>
															<ul class="wf-sn-ai-latest-improvements-list wf-sn-ai-latest-improvements-list--top">
																<?php 
                foreach ( $latest_report_data['top_improvements'] as $imp ) {
                    echo self::render_latest_improvement_li( $imp, $improvement_links );
                    // Escaped in helper.
                }
                ?>
															</ul>
															<?php 
                if ( !empty( $latest_report_data['top_improvements_rest'] ) ) {
                    ?>
																<ul class="wf-sn-ai-latest-improvements-list wf-sn-ai-latest-improvements-list--more" id="wf_sn_ai_more_improvements" hidden>
																	<?php 
                    foreach ( $latest_report_data['top_improvements_rest'] as $imp ) {
                        echo self::render_latest_improvement_li( $imp, $improvement_links );
                    }
                    ?>
																</ul>
																<button type="button" class="button button-link wf-sn-ai-show-more-issues" aria-expanded="false" id="wf_sn_ai_toggle_more_issues"><?php 
                    esc_html_e( 'Show more issues', 'security-ninja' );
                    ?></button>
															<?php 
                }
                ?>
														</div>
													<?php 
            }
            ?>
													<?php 
            if ( !empty( $latest_report_data['model'] ) || !empty( $latest_report_data['token_input'] ) || !empty( $latest_report_data['token_output'] ) ) {
                ?>
														<p class="description wf-sn-ai-report-usage-meta wf-sn-ai-meta-footer-strip">
															<?php 
                /* translators: 1: model, 2: input tokens, 3: output tokens */
                echo esc_html( sprintf(
                    __( 'Model: %1$s · Estimated tokens in: %2$s · out: %3$s', 'security-ninja' ),
                    ( $latest_report_data['model'] ? $latest_report_data['model'] : '-' ),
                    (string) (int) $latest_report_data['token_input'],
                    (string) (int) $latest_report_data['token_output']
                ) );
                ?>
														</p>
													<?php 
            }
            ?>
													<div class="wf-sn-ai-full-report-expanded" id="wf_sn_ai_full_report_expanded" hidden></div>
												<?php 
        } else {
            ?>
													<?php 
            self::render_no_report_yet_state();
            ?>
												<?php 
        }
        ?>
											</div>
										</div>

										<?php 
        if ( $has_report ) {
            ?>
											<div class="wf-sn-ai-generate-secondary-wrap">
												<button type="button" class="button button-secondary wf-sn-ai-trigger wf-sn-ai-generate-btn" data-request-type="full_report" <?php 
            disabled( !$has_connectors );
            ?>>
													<?php 
            esc_html_e( 'Generate a new review now', 'security-ninja' );
            ?>
												</button>
											</div>
										<?php 
        }
        ?>

										<?php 
        if ( $history_counts['full_report'] > 1 ) {
            ?>
											<?php 
            self::render_what_changed_panel();
            ?>
										<?php 
        }
        ?>

									</div>
								</div>
							</div>

							<?php 
        $followup_enabled_chips = Wf_Sn_Ai_Advisor_Chips::get_enabled_chips_for_ui();
        $followup_toolbar_active = $has_report && !empty( $followup_enabled_chips );
        $followup_comparison_chips = array();
        foreach ( Wf_Sn_Ai_Advisor_Chips::get_enabled_chips_for_ui() as $chip ) {
            if ( in_array( $chip['id'], Wf_Sn_Ai_Advisor_Chips::comparison_prompt_ids(), true ) ) {
                $followup_comparison_chips[] = $chip;
            }
        }
        $followup_primary_chips = array();
        foreach ( $followup_enabled_chips as $chip ) {
            if ( in_array( $chip['id'], Wf_Sn_Ai_Advisor_Chips::PRIMARY_PROMPT_IDS, true ) ) {
                $followup_primary_chips[] = $chip;
            }
        }
        ?>
							<div class="wf-sn-ai-chat-column" id="wf_sn_ai_chat_column" data-followup-ready="<?php 
        echo ( $followup_toolbar_active ? '1' : '0' );
        ?>"<?php 
        echo ( $has_connectors ? '' : ' hidden' );
        ?>>
								<div class="wf-sn-ai-card wf-sn-ai-chat-column-card">
									<div class="wf-sn-ai-card-inner wf-sn-ai-chat-column-inner">
										<div class="wf-sn-ai-chat-column__head">
											<h2 class="wf-sn-ai-section-title"><?php 
        esc_html_e( 'Follow-ups', 'security-ninja' );
        ?></h2>
											<p class="description wf-sn-ai-convo-intro wf-sn-ai-convo-intro--active"<?php 
        echo ( $followup_toolbar_active ? '' : ' hidden' );
        ?>>
												<?php 
        echo esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'Ask a guided question. Answers stay limited to your %s scan results and recent security activity.', 'security-ninja' ),
            $plugin_name
         ) );
        ?>
											</p>
										</div>
										<div class="wf-sn-ai-chat-column__convo-wrap">
											<div class="wf-sn-ai-assistant-output wf-sn-ai-result-canvas wf-sn-ai-assistant-output--convo" id="wf_sn_ai_assistant_output" aria-live="polite">
												<div class="wf-sn-ai-convo-loading" id="wf_sn_ai_convo_loading" role="status" aria-live="polite"<?php 
        echo ( $followup_toolbar_active ? '' : ' hidden' );
        ?>>
													<span class="spinner is-active" aria-hidden="true"></span>
													<span class="wf-sn-ai-convo-loading__text"><?php 
        esc_html_e( 'Loading messages…', 'security-ninja' );
        ?></span>
												</div>
												<div class="wf-sn-ai-convo" id="wf_sn_ai_convo" role="log" aria-label="<?php 
        esc_attr_e( 'Assistant conversation', 'security-ninja' );
        ?>" hidden>
													<div class="wf-sn-ai-convo__load-wrap" id="wf_sn_ai_convo_load_wrap" hidden>
														<button type="button" class="button button-link wf-sn-ai-convo__load-older" id="wf_sn_ai_convo_load_older"><?php 
        esc_html_e( 'Load older messages', 'security-ninja' );
        ?></button>
													</div>
													<div class="wf-sn-ai-convo__turns" id="wf_sn_ai_convo_turns"></div>
												</div>
												<p class="description wf-sn-ai-empty-state" id="wf_sn_ai_assistant_empty" hidden><?php 
        esc_html_e( 'No messages yet. Pick a guided question below.', 'security-ninja' );
        ?></p>
											</div>
											<p class="description wf-sn-ai-chip-status" id="wf_sn_ai_chip_status" hidden></p>
										</div>
										<div class="wf-sn-ai-chat-column__chips wf-sn-ai-followup-active" id="wf_sn_ai_followup_active" role="toolbar" aria-label="<?php 
        esc_attr_e( 'Suggested prompts', 'security-ninja' );
        ?>"<?php 
        echo ( $followup_toolbar_active ? '' : ' hidden' );
        ?>>
											<p class="description wf-sn-ai-chip-hint"><?php 
        esc_html_e( 'Choose a guided question', 'security-ninja' );
        ?></p>
											<div class="wf-sn-ai-chip-row wf-sn-ai-chip-row--footer" id="wf_sn_ai_chip_row">
												<?php 
        foreach ( $followup_primary_chips as $chip ) {
            ?>
													<div class="wf-sn-ai-chip-wrap">
														<button type="button" class="button wf-sn-ai-chip" data-prompt-id="<?php 
            echo esc_attr( $chip['id'] );
            ?>">
															<?php 
            echo esc_html( $chip['label'] );
            ?>
														</button>
													</div>
												<?php 
        }
        ?>
												<?php 
        foreach ( $followup_comparison_chips as $chip ) {
            ?>
													<div class="wf-sn-ai-chip-wrap">
														<button type="button" class="button wf-sn-ai-chip" data-prompt-id="<?php 
            echo esc_attr( $chip['id'] );
            ?>">
															<?php 
            echo esc_html( $chip['label'] );
            ?>
														</button>
													</div>
												<?php 
        }
        ?>
											</div>
										</div>
									</div>
								</div>
							</div>

						</div>
					</div>

					<div id="wf_sn_ai_preview_modal" class="wf-sn-ai-preview-modal" role="dialog" aria-labelledby="wf_sn_ai_preview_modal_title" aria-modal="true" hidden>
						<div class="wf-sn-ai-preview-modal-backdrop"></div>
						<div class="wf-sn-ai-preview-modal-content">
							<div class="wf-sn-ai-preview-modal-header">
								<h2 id="wf_sn_ai_preview_modal_title" class="wf-sn-ai-preview-modal-title"><?php 
        esc_html_e( 'Preview of data sent to AI', 'security-ninja' );
        ?></h2>
								<button type="button" class="wf-sn-ai-preview-modal-close button-link" aria-label="<?php 
        esc_attr_e( 'Close', 'security-ninja' );
        ?>">&times;</button>
							</div>
							<div class="wf-sn-ai-preview-modal-body">
								<p class="wf-sn-ai-preview-stats description" hidden></p>
								<pre><code class="wf-sn-ai-preview-data-content"></code></pre>
							</div>
						</div>
					</div>

					<?php 
        $current_connector = ( isset( $options['last_connector_provider'] ) ? $options['last_connector_provider'] : '' );
        $abilities_exposed = Wf_Sn_Ai_Advisor_Abilities::is_exposed_enabled();
        $abilities_for_ui = Wf_Sn_Ai_Advisor_Abilities::get_definitions_for_ui();
        ?>
					<div class="wf-sn-ai-card wf-sn-ai-settings-card wf-sn-ai-connection-card sncard settings-card">
						<div class="wf-sn-ai-card-inner">
							<h2 class="wf-sn-ai-section-title"><?php 
        esc_html_e( 'AI connection', 'security-ninja' );
        ?></h2>
							<p class="description"><?php 
        esc_html_e( 'Connectors are configured in WordPress under Settings → Connectors. Here you choose which one Security Advisor uses.', 'security-ninja' );
        ?></p>
							<?php 
        if ( empty( $configured_connectors ) ) {
            ?>
								<p><?php 
            esc_html_e( 'No AI connectors are configured yet.', 'security-ninja' );
            ?></p>
								<p><a href="<?php 
            echo esc_url( $connectors_url );
            ?>" class="button button-secondary"><?php 
            esc_html_e( 'Go to Settings → Connectors', 'security-ninja' );
            ?></a></p>
							<?php 
        }
        ?>
							<form method="post" action="<?php 
        echo esc_url( admin_url( 'admin-post.php' ) );
        ?>" class="wf-sn-ai-settings-form">
								<input type="hidden" name="action" value="wf_sn_ai_advisor_save_settings" />
								<?php 
        wp_nonce_field( 'wf_sn_ai_advisor_save_settings', 'wf_sn_ai_advisor_nonce' );
        ?>
								<input type="hidden" name="wf_sn_ai_advisor_provider" value="wordpress_connectors" />
								<div class="wf-sn-ai-settings-stack">
									<?php 
        if ( !empty( $configured_connectors ) ) {
            ?>
										<section class="wf-sn-ai-settings-group">
											<div class="wf-sn-ai-settings-row">
												<div class="wf-sn-ai-settings-row__content">
													<label for="wf_sn_ai_advisor_connector">
														<h3><?php 
            esc_html_e( 'AI connector', 'security-ninja' );
            ?></h3>
														<p class="description"><?php 
            esc_html_e( 'Used for reviews and follow-ups on this page, and for automatic reviews from the Scheduler.', 'security-ninja' );
            ?></p>
													</label>
												</div>
												<div class="wf-sn-ai-settings-row__control">
													<select name="wf_sn_ai_advisor_connector" id="wf_sn_ai_advisor_connector" class="regular-text">
														<?php 
            foreach ( $connectors_for_ui as $conn_meta ) {
                ?>
															<option value="<?php 
                echo esc_attr( $conn_meta['id'] );
                ?>" <?php 
                selected( $current_connector, $conn_meta['id'] );
                ?>><?php 
                echo esc_html( $conn_meta['label'] );
                ?></option>
														<?php 
            }
            ?>
													</select>
													<div class="wf-sn-ai-test-connection" id="wf_sn_ai_test_connection">
														<button type="button" class="button button-secondary wf-sn-ai-test-connection__btn" id="wf_sn_ai_test_connection_btn"><?php 
            esc_html_e( 'Test connection', 'security-ninja' );
            ?></button>
														<span class="wf-sn-ai-test-connection__status" id="wf_sn_ai_test_connection_status" role="status" aria-live="polite"></span>
													</div>
												</div>
											</div>
										</section>
									<?php 
        }
        ?>
									<div class="wf-sn-ai-settings-actions">
										<button type="submit" class="button button-primary input-button"><?php 
        esc_html_e( 'Save Changes', 'security-ninja' );
        ?></button>
									</div>
								</div>
							</form>
						</div>
					</div>

					<details class="wf-sn-ai-card wf-sn-ai-settings-card wf-sn-ai-settings-card--footer sncard settings-card">
						<summary class="wf-sn-ai-section-title wf-sn-ai-settings-summary"><?php 
        esc_html_e( 'Advanced', 'security-ninja' );
        ?></summary>
						<div class="wf-sn-ai-card-inner">
							<form method="post" action="<?php 
        echo esc_url( admin_url( 'admin-post.php' ) );
        ?>" class="wf-sn-ai-settings-form">
								<input type="hidden" name="action" value="wf_sn_ai_advisor_save_settings" />
								<?php 
        wp_nonce_field( 'wf_sn_ai_advisor_save_settings', 'wf_sn_ai_advisor_nonce' );
        ?>
								<input type="hidden" name="wf_sn_ai_advisor_provider" value="wordpress_connectors" />
								<?php 
        if ( !empty( $configured_connectors ) && $current_connector ) {
            ?>
									<input type="hidden" name="wf_sn_ai_advisor_connector" value="<?php 
            echo esc_attr( $current_connector );
            ?>" />
								<?php 
        }
        ?>
								<section class="wf-sn-ai-settings-group wf-sn-ai-settings-group--abilities">
									<div class="wf-sn-ai-settings-row wf-sn-ai-settings-row--toggle">
										<div class="wf-sn-ai-settings-row__content">
											<label for="wf_sn_ai_advisor_abilities_exposed">
												<h3><?php 
        esc_html_e( 'Expose data to WordPress AI abilities', 'security-ninja' );
        ?></h3>
												<p class="description"><?php 
        echo esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'Lets other WordPress AI tools read %s summaries when enabled. Report generation and follow-ups on this page are not affected.', 'security-ninja' ),
            $plugin_name
         ) );
        ?></p>
											</label>
										</div>
										<div class="wf-sn-ai-settings-row__control">
											<?php 
        \WPSecurityNinja\Plugin\Utils::create_toggle_switch( 'wf_sn_ai_advisor_abilities_exposed', array(
            'value'       => 1,
            'saved_value' => Wf_Sn_Ai_Advisor_Abilities::get_exposed_saved_value(),
            'option_key'  => 'wf_sn_ai_advisor_abilities_exposed',
        ) );
        ?>
										</div>
									</div>
									<div class="wf-sn-ai-abilities-list" aria-labelledby="wf_sn_ai_abilities_list_title">
										<h4 id="wf_sn_ai_abilities_list_title" class="wf-sn-ai-abilities-list__title"><?php 
        esc_html_e( 'Available abilities', 'security-ninja' );
        ?></h4>
										<p class="description wf-sn-ai-abilities-list__intro"><?php 
        esc_html_e( 'When exposure is enabled, other WordPress AI tools on this site can use these read-only abilities:', 'security-ninja' );
        ?></p>
										<?php 
        if ( !$abilities_exposed ) {
            ?>
											<div class="wf-sn-ai-abilities-notice notice notice-warning inline">
												<p><?php 
            esc_html_e( 'Not exposed to WordPress AI clients until you enable the setting above and save.', 'security-ninja' );
            ?></p>
											</div>
										<?php 
        }
        ?>
										<ul class="wf-sn-ai-abilities-list__items">
											<?php 
        foreach ( $abilities_for_ui as $ability ) {
            ?>
												<li class="wf-sn-ai-abilities-list__item">
													<strong class="wf-sn-ai-abilities-list__label"><?php 
            echo esc_html( $ability['label'] );
            ?></strong>
													<span class="wf-sn-ai-abilities-list__summary"><?php 
            echo esc_html( $ability['summary'] );
            ?></span>
												</li>
											<?php 
        }
        ?>
										</ul>
									</div>
								</section>
								<div class="wf-sn-ai-settings-actions">
									<button type="submit" class="button button-primary input-button"><?php 
        esc_html_e( 'Save Changes', 'security-ninja' );
        ?></button>
								</div>
							</form>
							<div class="wf-sn-ai-danger-zone">
								<h3><?php 
        esc_html_e( 'Clear AI history', 'security-ninja' );
        ?></h3>
								<p>
									<?php 
        printf( 
            /* translators: 1: number of saved reports, 2: number of follow-up messages */
            esc_html__( 'Saved AI reports: %1$s · Follow-up messages: %2$s', 'security-ninja' ),
            esc_html( number_format_i18n( $history_counts['full_report'] ) ),
            esc_html( number_format_i18n( $history_counts['prompt_chip'] ) )
         );
        ?>
								</p>
								<p class="description"><?php 
        esc_html_e( 'Removes saved AI security reports and follow-up conversation history only. Scan results, data readiness, and site-wide priority hints are not affected.', 'security-ninja' );
        ?></p>
								<form method="post" action="<?php 
        echo esc_url( admin_url( 'admin-post.php' ) );
        ?>" class="wf-sn-ai-clear-history-form">
									<input type="hidden" name="action" value="wf_sn_ai_advisor_clear_history" />
									<input type="hidden" name="redirect_to" value="<?php 
        echo esc_attr( Wf_Sn_Ai_Advisor::SLUG );
        ?>" />
									<?php 
        wp_nonce_field( 'wf_sn_ai_advisor_clear_history', '_wpnonce' );
        ?>
									<?php 
        submit_button(
            __( 'Clear all AI reports and history', 'security-ninja' ),
            'delete sn-confirm-submit',
            'wf-sn-ai-clear-history',
            true,
            array(
                'id'              => 'wf-sn-ai-clear-history',
                'data-sn-confirm' => esc_attr__( 'This will permanently delete all AI security reports and follow-up messages. Your connector settings will be kept. Continue?', 'security-ninja' ),
                'data-sn-danger'  => '1',
            )
        );
        ?>
								</form>
							</div>
						</div>
					</details>

				</div>
			</div>
		</div>
		</div>
		<?php 
    }

    /**
     * Compact scan-data readiness strip above the generate action.
     *
     * @return void
     */
    private static function render_readiness_compact() {
        $items = Wf_Sn_Ai_Advisor_Readiness::get_items();
        $issues = array();
        foreach ( $items as $item ) {
            if ( 'ready' !== $item['status'] ) {
                $issues[] = $item;
            }
        }
        echo '<div class="wf-sn-ai-readiness-compact" role="status">';
        echo '<span class="wf-sn-ai-readiness-compact__label">' . esc_html__( 'Scan data', 'security-ninja' ) . '</span>';
        if ( empty( $issues ) ) {
            echo '<span class="wf-sn-ai-readiness-compact__ok">' . esc_html__( 'Ready for AI review', 'security-ninja' ) . '</span>';
        } else {
            echo '<ul class="wf-sn-ai-readiness-compact__issues">';
            foreach ( $issues as $item ) {
                $icon = ( 'missing' === $item['status'] ? '○' : '⚠' );
                echo '<li class="wf-sn-ai-readiness-compact__issue wf-sn-ai-readiness-compact__issue--' . esc_attr( $item['status'] ) . '">';
                echo '<span aria-hidden="true">' . esc_html( $icon ) . '</span> ';
                echo esc_html( $item['label'] ) . ' — ' . esc_html( $item['detail'] );
                echo '</li>';
            }
            echo '</ul>';
            echo '<a href="' . esc_url( Wf_Sn_Ai_Advisor_Readiness::recommended_scans_url() ) . '" class="button button-small wf-sn-ai-readiness-compact__action">' . esc_html__( 'Run recommended scans', 'security-ninja' ) . '</a>';
        }
        echo '</div>';
    }

    /**
     * Empty state when no AI report is saved yet.
     *
     * @return void
     */
    private static function render_no_report_yet_state() {
        echo '<div class="wf-sn-ai-no-report-yet">';
        echo '<p>' . esc_html__( 'No AI security report saved yet.', 'security-ninja' ) . '</p>';
        echo '</div>';
    }

    /**
     * Status line: connector, last review, schedule.
     *
     * @param bool                       $has_connectors   Whether connectors exist.
     * @param array<string,mixed>|null   $selected_meta    Selected connector metadata.
     * @param string                     $connectors_url   Connectors admin URL.
     * @param bool                       $has_report       Whether a report exists.
     * @param array<string,mixed>|null   $latest_report    Latest report data.
     * @param string                     $schedule_status  Schedule status sentence.
     * @param string                     $scheduler_url    Scheduler tab URL.
     * @return void
     */
    private static function render_status_line(
        $has_connectors,
        $selected_meta,
        $connectors_url,
        $has_report,
        $latest_report,
        $schedule_status,
        $scheduler_url
    ) {
        echo '<p class="wf-sn-ai-status-line">';
        if ( $has_connectors && is_array( $selected_meta ) && !empty( $selected_meta['label'] ) ) {
            printf( 
                /* translators: %s: connector display name */
                esc_html__( 'Using %s', 'security-ninja' ),
                esc_html( $selected_meta['label'] )
             );
        } else {
            echo '<a href="' . esc_url( $connectors_url ) . '">' . esc_html__( 'Set up AI connector', 'security-ninja' ) . '</a>';
        }
        echo ' · ';
        if ( $has_report && is_array( $latest_report ) && !empty( $latest_report['created'] ) ) {
            echo esc_html( sprintf( 
                /* translators: %s: human time */
                __( 'Last review %s ago', 'security-ninja' ),
                human_time_diff( strtotime( $latest_report['created'] ), time() )
             ) );
        } else {
            echo esc_html__( 'No review yet', 'security-ninja' );
        }
        if ( '' !== $schedule_status ) {
            echo ' · ';
            echo esc_html( $schedule_status );
            echo ' <a href="' . esc_url( $scheduler_url ) . '">' . esc_html__( 'Scheduler', 'security-ninja' ) . '</a>';
        }
        echo '</p>';
    }

    /**
     * Deterministic top priorities panel.
     */
    private static function render_top_priorities_panel() {
        $priorities = Wf_Sn_Priority_Resolver::get( 5 );
        if ( empty( $priorities ) ) {
            return;
        }
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        echo '<div class="wf-sn-ai-card wf-sn-ai-top-priorities sncard wf-sn-ai-top-priorities--inline">';
        echo '<h2 class="wf-sn-ai-section-title">' . esc_html__( 'Suggested next steps', 'security-ninja' ) . '</h2>';
        echo '<p class="description">' . esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'Based on your latest %s scan data (not from saved AI reports).', 'security-ninja' ),
            $plugin_name
         ) ) . '</p>';
        echo '<ol class="wf-sn-ai-priority-list">';
        foreach ( $priorities as $index => $item ) {
            echo '<li class="wf-sn-ai-priority-item wf-sn-ai-priority-item--' . esc_attr( $item['severity'] ) . '">';
            echo '<strong>' . esc_html( $index + 1 . '. ' . $item['title'] ) . '</strong> ';
            echo '<span class="wf-sn-ai-priority-badge">' . esc_html( ucfirst( $item['severity'] ) ) . '</span>';
            echo '<p class="description">' . esc_html( $item['summary'] ) . '</p>';
            echo '<a href="' . esc_url( $item['action_url'] ) . '" class="button button-small">' . esc_html( $item['action_text'] ) . '</a>';
            echo '</li>';
        }
        echo '</ol></div>';
    }

    /**
     * What changed since last AI report.
     */
    private static function render_what_changed_panel() {
        $diff = Wf_Sn_Security_Snapshot_Diff::get_report_diff();
        if ( !$diff['has_comparison'] ) {
            return;
        }
        $has_lines = !empty( $diff['new'] ) || !empty( $diff['improved'] ) || !empty( $diff['needs_attention'] );
        if ( !$has_lines ) {
            return;
        }
        echo '<div class="wf-sn-ai-card wf-sn-ai-delta-card sncard wf-sn-ai-delta-card--inline">';
        echo '<h2 class="wf-sn-ai-section-title">' . esc_html__( 'What changed since last AI report', 'security-ninja' ) . '</h2>';
        self::render_diff_lists( $diff );
        echo '</div>';
    }

    /**
     * @param array{new: string[], improved: string[], needs_attention: string[]} $diff Diff buckets.
     */
    private static function render_diff_lists( array $diff ) {
        foreach ( array(
            'new'             => __( 'New', 'security-ninja' ),
            'improved'        => __( 'Checked', 'security-ninja' ),
            'needs_attention' => __( 'Needs attention', 'security-ninja' ),
        ) as $key => $label ) {
            if ( empty( $diff[$key] ) ) {
                continue;
            }
            echo '<h3>' . esc_html( $label ) . '</h3><ul>';
            foreach ( $diff[$key] as $line ) {
                echo '<li>' . esc_html( $line ) . '</li>';
            }
            echo '</ul>';
        }
    }

    private static function render_coming_soon() {
        $updates_url = admin_url( 'update-core.php' );
        $main_sn_url = admin_url( 'admin.php?page=wf-sn' );
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
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
								<h1 class="wf-sn-ai-advisor-heading"><?php 
        esc_html_e( 'Security Advisor', 'security-ninja' );
        ?></h1>
							</div>
						</div>
					</header>
					<div class="wf-sn-ai-wp7-required" role="region" aria-labelledby="wf-sn-ai-wp7-required-title">
						<span class="wf-sn-ai-wp7-required__icon dashicons dashicons-info" aria-hidden="true"></span>
						<div class="wf-sn-ai-wp7-required__body">
							<h2 id="wf-sn-ai-wp7-required-title" class="wf-sn-ai-wp7-required__title"><?php 
        esc_html_e( 'WordPress 7 is required', 'security-ninja' );
        ?></h2>
							<p class="wf-sn-ai-wp7-required__lead"><?php 
        esc_html_e( 'Security Advisor uses the built-in AI Connectors in WordPress 7. Once your site is on WordPress 7, you can connect an AI provider in your WordPress settings and generate reports from this page.', 'security-ninja' );
        ?></p>
							<ul class="wf-sn-ai-wp7-required__list">
								<li><?php 
        echo esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'All other %s features keep working on your current WordPress version.', 'security-ninja' ),
            $plugin_name
         ) );
        ?></li>
								<li><?php 
        esc_html_e( 'After upgrading, configure AI under Settings → Connectors, then return here.', 'security-ninja' );
        ?></li>
							</ul>
							<p class="wf-sn-ai-wp7-required__actions">
								<a href="<?php 
        echo esc_url( $updates_url );
        ?>" class="button button-primary"><?php 
        esc_html_e( 'Go to Dashboard → Updates', 'security-ninja' );
        ?></a>
								<a href="<?php 
        echo esc_url( $main_sn_url );
        ?>" class="button button-secondary"><?php 
        echo esc_html( sprintf( 
            /* translators: %s: plugin display name */
            __( 'Back to %s', 'security-ninja' ),
            $plugin_name
         ) );
        ?></a>
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
        $plugin_name = \WPSecurityNinja\Plugin\Utils::get_branded_plugin_name();
        $risk = Wf_Sn_Ai_Advisor_Improvements::normalize_risk( $imp );
        $priority_label = ( 'high' === $risk ? __( 'High Priority', 'security-ninja' ) : (( 'medium' === $risk ? __( 'Medium Priority', 'security-ninja' ) : __( 'Low Priority', 'security-ninja' ) )) );
        $label = ( isset( $imp['short_label'] ) && '' !== $imp['short_label'] ? $imp['short_label'] : (( isset( $imp['title'] ) ? $imp['title'] : '' )) );
        $title = ( isset( $imp['title'] ) && is_string( $imp['title'] ) ? $imp['title'] : '' );
        $details = ( isset( $imp['details'] ) && is_string( $imp['details'] ) ? $imp['details'] : '' );
        $imp_id = ( isset( $imp['id'] ) ? (string) $imp['id'] : '' );
        $hash = ( '' !== $imp_id && isset( $improvement_links[$imp_id] ) ? (string) $improvement_links[$imp_id] : '' );
        $sn_base = admin_url( 'admin.php?page=wf-sn' );
        $open_url = ( '' !== $hash ? $sn_base . (( 0 === strpos( $hash, '#' ) ? $hash : '#' . $hash )) : '' );
        $body_has = '' !== $details || '' !== $open_url || '' !== $title && $title !== $label;
        ob_start();
        if ( $body_has ) {
            /* translators: Hidden accessibility label for expandable issue row; %s: issue title */
            $summary_aria = sprintf( __( 'Show details: %s', 'security-ninja' ), $label );
            ?>
		<li class="wf-sn-ai-latest-improvement-item">
			<details class="wf-sn-ai-latest-improvement wf-sn-ai-priority-<?php 
            echo esc_attr( $risk );
            ?>">
				<summary class="wf-sn-ai-latest-improvement__summary" aria-label="<?php 
            echo esc_attr( $summary_aria );
            ?>">
					<span class="wf-sn-ai-improvement-dot" aria-hidden="true"></span>
					<span class="wf-sn-ai-improvement-label"><?php 
            echo esc_html( $label );
            ?></span>
					<span class="wf-sn-ai-priority-badge"><?php 
            echo esc_html( $priority_label );
            ?></span>
				</summary>
				<div class="wf-sn-ai-latest-improvement__body">
					<?php 
            if ( '' !== $title && $title !== $label ) {
                ?>
						<p class="wf-sn-ai-improvement-title"><?php 
                echo esc_html( $title );
                ?></p>
					<?php 
            }
            ?>
					<?php 
            if ( '' !== $details ) {
                ?>
						<div class="wf-sn-ai-improvement-body"><?php 
                echo wp_kses_post( nl2br( esc_html( $details ) ) );
                ?></div>
					<?php 
            }
            ?>
					<?php 
            if ( '' !== $open_url ) {
                ?>
						<p class="wf-sn-ai-improvement-actions">
							<a href="<?php 
                echo esc_url( $open_url );
                ?>" class="wf-sn-ai-improvement-link" target="_blank" rel="noopener"><?php 
                echo esc_html( sprintf( 
                    /* translators: %s: plugin display name */
                    __( 'Open in %s', 'security-ninja' ),
                    $plugin_name
                 ) );
                ?></a>
						</p>
					<?php 
            }
            ?>
				</div>
			</details>
		</li>
			<?php 
        } else {
            ?>
		<li class="wf-sn-ai-latest-improvement-item wf-sn-ai-latest-improvement-item--static">
			<div class="wf-sn-ai-latest-improvement wf-sn-ai-priority-<?php 
            echo esc_attr( $risk );
            ?> wf-sn-ai-latest-improvement--static">
				<span class="wf-sn-ai-improvement-dot" aria-hidden="true"></span>
				<span class="wf-sn-ai-improvement-label"><?php 
            echo esc_html( $label );
            ?></span>
				<span class="wf-sn-ai-priority-badge"><?php 
            echo esc_html( $priority_label );
            ?></span>
			</div>
		</li>
			<?php 
        }
        return (string) ob_get_clean();
    }

    /**
     * Connector status badge in the workspace header.
     *
     * @param bool                                      $has_connectors Whether any connector is configured.
     * @param array<string,mixed>|null                  $selected_meta  Selected connector metadata.
     * @param string                                    $connectors_url Admin URL for Connectors settings.
     * @return void
     */
    private static function render_connector_badge( $has_connectors, $selected_meta, $connectors_url ) {
        if ( $has_connectors && is_array( $selected_meta ) && !empty( $selected_meta['label'] ) ) {
            echo '<p class="wf-sn-ai-connector-badge wf-sn-ai-connector-badge--connected">';
            echo '<span class="wf-sn-ai-connector-badge__dot" aria-hidden="true"></span>';
            if ( !empty( $selected_meta['logo_url'] ) ) {
                echo '<img class="wf-sn-ai-connector-badge__logo" src="' . esc_url( $selected_meta['logo_url'] ) . '" alt="" width="20" height="20" />';
            }
            echo '<span class="wf-sn-ai-connector-badge__text">';
            printf( 
                /* translators: %s: connector display name */
                esc_html__( 'Using %s', 'security-ninja' ),
                esc_html( $selected_meta['label'] )
             );
            echo '</span></p>';
            return;
        }
        echo '<p class="wf-sn-ai-connector-badge wf-sn-ai-connector-badge--warning">';
        echo '<span class="wf-sn-ai-connector-badge__dot" aria-hidden="true"></span>';
        echo '<span class="wf-sn-ai-connector-badge__text">' . esc_html__( 'No AI connector configured', 'security-ninja' ) . '</span> ';
        echo '<a href="' . esc_url( $connectors_url ) . '" class="button button-small">' . esc_html__( 'Set up AI connector', 'security-ninja' ) . '</a>';
        echo '</p>';
    }

    /**
     * Get stored options.
     *
     * @return array
     */
    public static function get_options() {
        $opts = get_option( self::OPTION_KEY, array() );
        return ( is_array( $opts ) ? $opts : array() );
    }

    /**
     * Whether scheduled AI reports are enabled.
     *
     * @return bool
     */
    public static function is_scheduled_report_enabled() {
        $opts = self::get_options();
        return !empty( $opts['scheduled_report_enabled'] );
    }

    /**
     * Scheduled report interval slug.
     *
     * @return string
     */
    public static function get_scheduled_report_interval() {
        $opts = self::get_options();
        $interval = ( isset( $opts['scheduled_report_interval'] ) ? sanitize_key( (string) $opts['scheduled_report_interval'] ) : Wf_Sn_Ai_Advisor_Schedule_Policy::INTERVAL_MONTHLY );
        $is_premium = false;
        return Wf_Sn_Ai_Advisor_Schedule_Policy::normalize_interval( $interval, $is_premium );
    }

    /**
     * Update a single option key.
     *
     * @param string $key   Key.
     * @param mixed  $value Value.
     */
    public static function set_option( $key, $value ) {
        $opts = self::get_options();
        $opts[$key] = $value;
        update_option( self::OPTION_KEY, $opts, true );
    }

}
