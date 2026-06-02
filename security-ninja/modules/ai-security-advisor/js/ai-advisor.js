(function ($) {
	'use strict';

	var base = window.wfSnAiAdvisor || {};
	base.strings = base.strings || {};

	var ajaxUrl = window.ajaxurl || '';
	var nonce = base.nonce || '';
	var PROMPT_CHIP = 'prompt_chip';
	var LONG_ANSWER_CHARS = 380;
	var PRIORITY_COLLAPSE_CHARS = 280;
	var convoNextOffset = 0;
	var convoHasMore = false;
	var convoLoadInProgress = false;
	var chipExpandIdSeq = 0;

	function nextChipExpandDomId() {
		chipExpandIdSeq += 1;
		return 'wf_sn_ai_expand_' + chipExpandIdSeq;
	}

	function escHtml(str) {
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function formatTextForHtml(str) {
		return escHtml(str).replace(/\n/g, '<br>');
	}

	function extractAjaxErrorMessage(response, fallback) {
		if (response && response.data) {
			if (typeof response.data === 'string' && response.data) {
				return response.data;
			}
			if (response.data.message) {
				return response.data.message;
			}
		}
		return fallback || '';
	}

	function escAttr(str) {
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function truncateSummaryLine(s, max) {
		var t = String(s).replace(/\s+/g, ' ').trim();
		if (t.length <= max) {
			return t;
		}
		return t.slice(0, max).trim() + '\u2026';
	}

	function chipSummaryNewCount(count) {
		var tpl = base.strings.chipNewItems || 'New items (%d)';
		return tpl.replace('%d', String(count));
	}

	function chipSummaryResolvedCount(count) {
		var tpl = base.strings.chipResolvedItems || 'Resolved (%d)';
		return tpl.replace('%d', String(count));
	}

	function getCurrentParentReportId() {
		var $card = $('#wf_sn_ai_latest_report_card');
		if ($card.length) {
			var fromCard = parseInt($card.data('parent-report-id'), 10);
			if (!isNaN(fromCard) && fromCard > 0) {
				return fromCard;
			}
		}
		var fromBase = parseInt(base.latestParentReportId, 10);
		return !isNaN(fromBase) && fromBase > 0 ? fromBase : 0;
	}

	function setCurrentParentReportId(reportId) {
		var id = parseInt(reportId, 10);
		if (isNaN(id) || id <= 0) {
			return;
		}
		base.latestParentReportId = id;
		var $card = $('#wf_sn_ai_latest_report_card');
		if ($card.length) {
			$card.attr('data-parent-report-id', String(id));
		}
	}

	function chipLabelForPromptId(promptId) {
		if (!base.chips || !promptId) {
			return '';
		}
		var i;
		for (i = 0; i < base.chips.length; i++) {
			if (base.chips[i].id === promptId) {
				return base.chips[i].label ? String(base.chips[i].label) : '';
			}
		}
		return '';
	}

	function scrollAdvisorResponseIntoView() {
		var el = document.querySelector('#wf_sn_ai_chat_column') || document.querySelector('.wf-sn-ai-chat-column');
		if (!el || !el.scrollIntoView) {
			return;
		}
		var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'nearest' });
	}

	/**
	 * Build primary column HTML for latest report after AJAX full audit (mirrors server-rendered structure).
	 *
	 * @param {Object} report Parsed report object.
	 * @param {Object} usage Usage metadata.
	 * @return {string} HTML.
	 */
	function buildLatestReportPrimaryFromAjax(report, usage) {
		var title = base.strings.latestSecurityReport || '';
		var ago = base.strings.justNow || '';
		var viewL = base.strings.viewFullReport || '';
		var chartTitle = base.strings.attackActivityChartTitle || '';
		var chartAria = base.strings.attackActivityChartAria || '';
		var parts = [];
		parts.push('<div class="wf-sn-ai-latest-report-header">');
		parts.push('<h2 class="wf-sn-ai-section-title">' + escHtml(title) + '</h2>');
		parts.push('<span class="wf-sn-ai-latest-report-meta">' + escHtml(ago) + '</span>');
		parts.push(
			'<button type="button" class="button button-link wf-sn-ai-view-full-report" aria-expanded="false">' +
				escHtml(viewL) +
				' &rarr;</button>'
		);
		parts.push('</div>');
		parts.push('<div class="wf-sn-ai-latest-report-body">');
		var execLatest = renderLatestExecutiveBlock(report);
		if (execLatest) {
			parts.push(execLatest);
		}
		parts.push('<div class="wf-sn-ai-latest-chart-wrap">');
		parts.push('<h3 class="wf-sn-ai-chart-title">' + escHtml(chartTitle) + '</h3>');
		parts.push(
			'<div class="wf-sn-ai-attack-chart" id="wf_sn_ai_attack_chart" role="img" aria-label="' +
				escAttr(chartAria) +
				'"></div>'
		);
		parts.push('</div></div>');
		parts.push(renderReport(report, true));
		var uline = renderUsageLine(usage);
		if (uline) {
			parts.push(
				'<p class="description wf-sn-ai-report-usage-meta wf-sn-ai-meta-footer-strip">' + uline + '</p>'
			);
		}
		parts.push('<div class="wf-sn-ai-full-report-expanded" id="wf_sn_ai_full_report_expanded" hidden></div>');
		return parts.join('');
	}

	/**
	 * Replace #wf_sn_ai_latest_report_primary with new audit content and refresh chart.
	 *
	 * @param {Object} report Parsed report object.
	 * @param {Object} usage Usage metadata.
	 * @return {boolean} True if DOM was updated.
	 */
	function syncLatestReportCard(report, usage, reportId) {
		var $card = $('#wf_sn_ai_latest_report_card');
		var $primary = $('#wf_sn_ai_latest_report_primary');
		if (!$card.length || !$primary.length || !report || typeof report !== 'object') {
			return false;
		}
		try {
			$card.attr('data-report-json', JSON.stringify(report));
		} catch (e) {
			return false;
		}
		if (reportId) {
			setCurrentParentReportId(reportId);
		}
		$card.removeClass('wf-sn-ai-latest-report--empty');
		$primary.html(buildLatestReportPrimaryFromAjax(report, usage));
		renderAttackChart();
		return true;
	}

	function resetConvoForNewReport() {
		convoNextOffset = 0;
		convoHasMore = false;
		$('#wf_sn_ai_convo_turns').empty();
		$('#wf_sn_ai_convo_load_wrap').prop('hidden', true);
		fetchChipHistoryPage(0, false);
	}

	function assistantSkeletonHtml() {
		return (
			'<div class="wf-sn-ai-skeleton" aria-hidden="true">' +
			'<div class="wf-sn-ai-skeleton__bar wf-sn-ai-skeleton__bar--long"></div>' +
			'<div class="wf-sn-ai-skeleton__bar wf-sn-ai-skeleton__bar--medium"></div>' +
			'<div class="wf-sn-ai-skeleton__bar"></div>' +
			'</div>'
		);
	}

	function restoreChipStates() {
		$('.wf-sn-ai-chip').each(function () {
			var $c = $(this);
			var id = $c.attr('data-prompt-id');
			if (!id || !base.chips) {
				$c.prop('disabled', false);
				return;
			}
			var en = false;
			for (var i = 0; i < base.chips.length; i++) {
				if (base.chips[i].id === id) {
					en = !!base.chips[i].enabled;
					break;
				}
			}
			$c.prop('disabled', !en);
		});
	}

	/**
	 * Lock or unlock Generate + all chips during any AI request.
	 *
	 * @param {boolean} busy True to disable everything.
	 */
	function setAdvisorActionsBusy(busy) {
		var $root = $('#sn_tabscont.wf-sn-ai-advisor-page');
		var $gen = $('.wf-sn-ai-trigger');
		if (busy) {
			$root.addClass('wf-sn-ai-advisor-page--ai-busy');
			$('.wf-sn-ai-chip').prop('disabled', true);
			$gen.prop('disabled', true);
		} else {
			$root.removeClass('wf-sn-ai-advisor-page--ai-busy');
			restoreChipStates();
			var canGen = Array.isArray(base.connectors) && base.connectors.length > 0;
			$gen.prop('disabled', !canGen);
		}
	}

	function renderUsageLine(usage) {
		if (!usage || typeof usage !== 'object') {
			return '';
		}
		var tpl = base.strings.usageLine || '';
		if (!tpl) {
			return '';
		}
		return tpl
			.replace('%1$s', escHtml(String(usage.model || '—')))
			.replace('%2$s', escHtml(String(usage.token_input != null ? usage.token_input : '—')))
			.replace('%3$s', escHtml(String(usage.token_output != null ? usage.token_output : '—')));
	}

	/**
	 * Executive block for the latest-report card (matches server .wf-sn-ai-latest-summary).
	 *
	 * @param {Object} report Parsed report.
	 * @return {string} HTML or empty.
	 */
	function renderLatestExecutiveBlock(report) {
		if (!report || !report.executive_summary) {
			return '';
		}
		return (
			'<div class="wf-sn-ai-latest-summary">' +
				'<h3 class="wf-sn-ai-report-heading">' +
				escHtml(base.strings.executiveSummary || '') +
				'</h3>' +
				'<div class="wf-sn-ai-report-body">' +
				formatTextForHtml(report.executive_summary) +
				'</div></div>'
		);
	}

	function renderReport(report, skipExecutive) {
		if (!report || typeof report !== 'object') {
			return '';
		}

		try {
			var html = [];

			if (!skipExecutive && report.executive_summary) {
				html.push(
					'<div class="wf-sn-ai-report-section wf-sn-ai-report-executive">' +
						'<h3 class="wf-sn-ai-report-heading">' + escHtml(base.strings.executiveSummary || '') + '</h3>' +
						'<div class="wf-sn-ai-report-body">' + formatTextForHtml(report.executive_summary) + '</div>' +
					'</div>'
				);
			}

			if (report.overview) {
				html.push(
					'<div class="wf-sn-ai-report-section wf-sn-ai-report-overview">' +
						'<h3 class="wf-sn-ai-report-heading">' + escHtml(base.strings.overview || '') + '</h3>' +
						'<div class="wf-sn-ai-report-body">' + formatTextForHtml(report.overview) + '</div>' +
					'</div>'
				);
			}

			if (Array.isArray(report.top_improvements) && report.top_improvements.length) {
				var improvementsHtml = [];
				var improvementLinks = base.improvementLinks || {};
				var baseUrlPath = base.baseUrlPath || '/wp-admin/admin.php?page=wf-sn';
				for (var i = 0; i < report.top_improvements.length; i++) {
					var item = report.top_improvements[i] || {};
					var title = item.title || item.short_label || '';
					var label = item.short_label || title;
					var details = item.details || '';
					var risk = (item.risk || 'low').toLowerCase();
					var riskLabel = risk.charAt(0).toUpperCase() + risk.slice(1);
					var hash = item.id && improvementLinks[item.id] ? improvementLinks[item.id] : '';
					var openInSnUrl = hash ? (window.location.origin + baseUrlPath + hash) : '';
					var openInSnLink = openInSnUrl
						? '<a href="' + escAttr(openInSnUrl) + '" class="wf-sn-ai-improvement-link" target="_blank" rel="noopener">' + escHtml(base.strings.openInSn || 'Open in Security Ninja') + '</a>'
						: '';
					var ariaLabel = (base.strings.topImprovements || 'Expand') + ': ' + label;

					improvementsHtml.push(
						'<div class="wf-sn-ai-improvement">' +
							'<button type="button" class="wf-sn-ai-improvement-toggle" aria-expanded="false" aria-label="' + escAttr(ariaLabel) + '">' +
								'<span class="wf-sn-ai-improvement-label">' + escHtml(label) + '</span>' +
								'<span class="wf-sn-ai-risk-badge wf-sn-ai-risk-' + risk + '">' + ((base.strings.riskLabel || '').replace('%s', escHtml(riskLabel))) + '</span>' +
							'</button>' +
							'<div class="wf-sn-ai-improvement-details" aria-hidden="true" hidden>' +
								'<p class="wf-sn-ai-improvement-title">' + escHtml(title) + '</p>' +
								'<div class="wf-sn-ai-improvement-body">' + formatTextForHtml(details) + (openInSnLink ? '<p class="wf-sn-ai-improvement-actions">' + openInSnLink + '</p>' : '') + '</div>' +
							'</div>' +
						'</div>'
					);
				}

				html.push(
					'<div class="wf-sn-ai-report-section wf-sn-ai-report-improvements">' +
						'<h3 class="wf-sn-ai-report-heading">' + escHtml(base.strings.topImprovements || '') + '</h3>' +
						'<div class="wf-sn-ai-report-body">' + improvementsHtml.join('') + '</div>' +
					'</div>'
				);
			}

			if (report.activity) {
				var activity = report.activity;
				var activitySummary = activity.summary || '';
				var activityExtra = '';
				if (activity.attack_volume_trend || activity.attack_volume_reason) {
					activityExtra =
						'<p class="wf-sn-ai-activity-trend">' +
							(activity.attack_volume_trend ? ((base.strings.trendLabel || '').replace('%s', escHtml(activity.attack_volume_trend)) + '. ') : '') +
							(activity.attack_volume_reason ? escHtml(activity.attack_volume_reason) : '') +
						'</p>';
				}
				html.push(
					'<div class="wf-sn-ai-report-section wf-sn-ai-report-activity">' +
						'<h3 class="wf-sn-ai-report-heading">' + escHtml(base.strings.activityLast7Days || '') + '</h3>' +
						'<div class="wf-sn-ai-report-body">' +
							(activitySummary ? '<p>' + formatTextForHtml(activitySummary) + '</p>' : '') +
							activityExtra +
						'</div>' +
					'</div>'
				);
			}

			return html.join('');
		} catch (e) {
			return '';
		}
	}

	function renderChipResponse(resp, promptId) {
		if (!resp || typeof resp !== 'object') {
			return '';
		}
		var parts = [];
		if (promptId === 'delta_since_last') {
			if (resp.delta_summary) {
				parts.push('<p class="wf-sn-ai-assistant-delta-summary">' + formatTextForHtml(resp.delta_summary) + '</p>');
			}
			if (Array.isArray(resp.new_items) && resp.new_items.length) {
				var ni;
				var newList = '<ul class="wf-sn-ai-assistant-list">';
				for (ni = 0; ni < resp.new_items.length; ni++) {
					newList += '<li>' + formatTextForHtml(String(resp.new_items[ni])) + '</li>';
				}
				newList += '</ul>';
				parts.push(
					'<details class="wf-sn-ai-assistant-details">' +
						'<summary class="wf-sn-ai-assistant-details__summary">' +
						escHtml(chipSummaryNewCount(resp.new_items.length)) +
						'</summary>' +
						'<div class="wf-sn-ai-assistant-details__body">' +
						newList +
						'</div></details>'
				);
			}
			if (Array.isArray(resp.resolved_items) && resp.resolved_items.length) {
				var ri;
				var resList = '<ul class="wf-sn-ai-assistant-list">';
				for (ri = 0; ri < resp.resolved_items.length; ri++) {
					resList += '<li>' + formatTextForHtml(String(resp.resolved_items[ri])) + '</li>';
				}
				resList += '</ul>';
				parts.push(
					'<details class="wf-sn-ai-assistant-details">' +
						'<summary class="wf-sn-ai-assistant-details__summary">' +
						escHtml(chipSummaryResolvedCount(resp.resolved_items.length)) +
						'</summary>' +
						'<div class="wf-sn-ai-assistant-details__body">' +
						resList +
						'</div></details>'
				);
			}
			if (resp.priority_shifts) {
				var ps = String(resp.priority_shifts);
				if (ps.length > PRIORITY_COLLAPSE_CHARS) {
					var psPreview = truncateSummaryLine(ps, PRIORITY_COLLAPSE_CHARS);
					var psExpId = nextChipExpandDomId();
					parts.push(
						'<div class="wf-sn-ai-chip-expand">' +
							'<div class="wf-sn-ai-chip-expand__teaser">' +
								'<p class="wf-sn-ai-assistant-priority wf-sn-ai-assistant-priority--preview">' +
									formatTextForHtml(psPreview) +
									'</p>' +
								'<button type="button" class="button button-link wf-sn-ai-chip-expand__toggle" aria-expanded="false" aria-controls="' +
									escAttr(psExpId) +
									'">' +
									escHtml(base.strings.chipShowFullAnswer || 'Show full answer') +
									'</button>' +
							'</div>' +
							'<div class="wf-sn-ai-chip-expand__full" id="' +
								escAttr(psExpId) +
								'" hidden tabindex="-1">' +
								'<p class="wf-sn-ai-assistant-priority">' +
									formatTextForHtml(ps) +
									'</p>' +
							'</div>' +
						'</div>'
					);
				} else {
					parts.push('<p class="wf-sn-ai-assistant-priority">' + formatTextForHtml(ps) + '</p>');
				}
			}
			if (resp.notes) {
				var nt = String(resp.notes);
				parts.push(
					'<details class="wf-sn-ai-assistant-details">' +
						'<summary class="wf-sn-ai-assistant-details__summary">' +
						escHtml(base.strings.chipNotes || 'Notes') +
						'</summary>' +
						'<div class="wf-sn-ai-assistant-details__body"><p class="wf-sn-ai-assistant-notes">' +
						formatTextForHtml(nt) +
						'</p></div></details>'
				);
			}
		} else {
			var ans = resp.answer ? String(resp.answer) : '';
			var bullets = Array.isArray(resp.bullets) && resp.bullets.length ? resp.bullets : [];
			var b;
			var bulletsInner = '';
			if (bullets.length) {
				bulletsInner = '<ul class="wf-sn-ai-assistant-list">';
				for (b = 0; b < bullets.length; b++) {
					bulletsInner += '<li>' + formatTextForHtml(String(bullets[b])) + '</li>';
				}
				bulletsInner += '</ul>';
			}
			if (ans.length > LONG_ANSWER_CHARS) {
				var ansPreview = truncateSummaryLine(ans, LONG_ANSWER_CHARS);
				var ansExpId = nextChipExpandDomId();
				parts.push(
					'<div class="wf-sn-ai-chip-expand">' +
						'<div class="wf-sn-ai-chip-expand__teaser">' +
							'<p class="wf-sn-ai-assistant-answer wf-sn-ai-assistant-answer--preview">' +
								formatTextForHtml(ansPreview) +
								'</p>' +
							'<button type="button" class="button button-link wf-sn-ai-chip-expand__toggle" aria-expanded="false" aria-controls="' +
								escAttr(ansExpId) +
								'">' +
								escHtml(base.strings.chipShowFullAnswer || 'Show full answer') +
								'</button>' +
						'</div>' +
						'<div class="wf-sn-ai-chip-expand__full" id="' +
							escAttr(ansExpId) +
							'" hidden tabindex="-1">' +
							'<p class="wf-sn-ai-assistant-answer">' +
								formatTextForHtml(ans) +
								'</p>' +
							bulletsInner +
						'</div>' +
					'</div>'
				);
			} else {
				if (ans) {
					parts.push('<p class="wf-sn-ai-assistant-answer">' + formatTextForHtml(ans) + '</p>');
				}
				if (bulletsInner) {
					if (ans) {
						parts.push(
							'<details class="wf-sn-ai-assistant-details">' +
								'<summary class="wf-sn-ai-assistant-details__summary">' +
								escHtml(base.strings.chipMoreDetail || 'More detail') +
								'</summary>' +
								'<div class="wf-sn-ai-assistant-details__body">' +
								bulletsInner +
								'</div></details>'
						);
					} else {
						parts.push(
							'<details class="wf-sn-ai-assistant-details" open>' +
								'<summary class="wf-sn-ai-assistant-details__summary">' +
								escHtml(base.strings.chipMoreDetail || 'More detail') +
								'</summary>' +
								'<div class="wf-sn-ai-assistant-details__body">' +
								bulletsInner +
								'</div></details>'
						);
					}
				}
			}
		}
		return parts.join('');
	}

	function getChipHistoryLimit() {
		var n = parseInt(base.chipHistoryPageSize, 10);
		if (n >= 5 && n <= 25) {
			return n;
		}
		return 15;
	}

	function setConvoLoading(isLoading) {
		var $loading = $('#wf_sn_ai_convo_loading');
		var $convo = $('#wf_sn_ai_convo');
		var $empty = $('#wf_sn_ai_assistant_empty');
		if (!$loading.length) {
			return;
		}
		$loading.prop('hidden', !isLoading);
		if (isLoading) {
			$convo.prop('hidden', true);
			$empty.prop('hidden', true);
		}
	}

	function finishInitialConvoLoad() {
		setConvoLoading(false);
		syncConvoEmptyState();
	}

	function syncConvoEmptyState() {
		var $turns = $('#wf_sn_ai_convo_turns');
		var $empty = $('#wf_sn_ai_assistant_empty');
		var $convo = $('#wf_sn_ai_convo');
		if (!$turns.length || !$empty.length) {
			return;
		}
		var hasContent = $turns.children('.wf-sn-ai-convo__turn').length > 0;
		$empty.prop('hidden', hasContent);
		if ($convo.length) {
			$convo.prop('hidden', !hasContent);
		}
	}

	function removeConvoPending() {
		$('#wf_sn_ai_convo_pending').remove();
	}

	function buildConvoTurnHtml(id, promptId, promptLabel, response, createdIso, createdDisplay) {
		var echoTpl = base.strings.promptEchoPrefix || '';
		var promptLine = '';
		if (echoTpl && promptLabel) {
			var pill =
				'<p class="wf-sn-ai-convo__prompt">' + escHtml(echoTpl.replace('%s', promptLabel)) + '</p>';
			var timeHtml = '';
			if (createdDisplay && String(createdDisplay).length) {
				var iso = createdIso && String(createdIso).length ? String(createdIso) : '';
				var dtPart = iso ? ' datetime="' + escAttr(iso) + '"' : '';
				timeHtml =
					'<time class="wf-sn-ai-convo__chip-time"' + dtPart + '>' + escHtml(String(createdDisplay)) + '</time>';
			}
			promptLine = '<div class="wf-sn-ai-convo__chip-wrap">' + pill + timeHtml + '</div>';
		}
		var inner = renderChipResponse(response, promptId);
		if (!inner) {
			inner = '<p class="description">' + escHtml(base.strings.requestFailed || '') + '</p>';
		}
		var idAttr = id ? ' data-report-id="' + escAttr(String(id)) + '"' : '';
		return (
			'<article class="wf-sn-ai-convo__turn"' +
			idAttr +
			' data-prompt-id="' +
			escAttr(String(promptId)) +
			'">' +
			promptLine +
			'<div class="wf-sn-ai-convo__answer wf-sn-ai-result-canvas">' +
			inner +
			'</div>' +
			'</article>'
		);
	}

	function appendConvoTurn(id, promptId, promptLabel, response, usage, createdIso, createdDisplay) {
		var html = buildConvoTurnHtml(id, promptId, promptLabel, response, createdIso, createdDisplay);
		$('#wf_sn_ai_convo_turns').append(html);
		syncConvoEmptyState();
	}

	function appendConvoPendingTurn(promptId, promptLabel) {
		removeConvoPending();
		var echoTpl = base.strings.promptEchoPrefix || '';
		var promptLine = '';
		if (echoTpl && promptLabel) {
			promptLine =
				'<p class="wf-sn-ai-convo__prompt">' + escHtml(echoTpl.replace('%s', promptLabel)) + '</p>';
		}
		var html =
			'<article class="wf-sn-ai-convo__turn wf-sn-ai-convo__turn--pending" id="wf_sn_ai_convo_pending" data-prompt-id="' +
			escAttr(String(promptId)) +
			'">' +
			promptLine +
			'<div class="wf-sn-ai-convo__answer wf-sn-ai-result-canvas">' +
			assistantSkeletonHtml() +
			'</div></article>';
		$('#wf_sn_ai_convo_turns').append(html);
		syncConvoEmptyState();
	}

	function appendConvoErrorTurn(promptId, promptLabel, message) {
		var echoTpl = base.strings.promptEchoPrefix || '';
		var promptLine = '';
		if (echoTpl && promptLabel) {
			promptLine =
				'<p class="wf-sn-ai-convo__prompt">' + escHtml(echoTpl.replace('%s', promptLabel)) + '</p>';
		}
		var html =
			'<article class="wf-sn-ai-convo__turn wf-sn-ai-convo__turn--error" data-prompt-id="' +
			escAttr(String(promptId)) +
			'">' +
			promptLine +
			'<div class="wf-sn-ai-convo__answer wf-sn-ai-result-canvas"><p class="description">' +
			escHtml(message) +
			'</p></div></article>';
		$('#wf_sn_ai_convo_turns').append(html);
		syncConvoEmptyState();
	}

	function fetchChipHistoryPage(offset, isPrepend) {
		var $turns = $('#wf_sn_ai_convo_turns');
		var $wrap = $('#wf_sn_ai_convo_load_wrap');
		var $convo = $('#wf_sn_ai_convo');
		var $btnOlder = $('#wf_sn_ai_convo_load_older');
		var isInitialLoad = offset === 0 && !isPrepend;
		if (!$turns.length) {
			return;
		}
		if (convoLoadInProgress) {
			return;
		}
		convoLoadInProgress = true;
		$btnOlder.prop('disabled', true);
		if (isInitialLoad) {
			setConvoLoading(true);
			$turns.empty();
		} else if (offset === 0) {
			$turns.empty();
		}
		var limit = getChipHistoryLimit();
		var prevScroll = null;
		if (isPrepend && $convo.length && $convo[0]) {
			prevScroll = { scrollTop: $convo[0].scrollTop, scrollHeight: $convo[0].scrollHeight };
		}
		$.post(ajaxUrl, {
			action: 'wf_sn_ai_advisor_chip_history_page',
			nonce: nonce,
			offset: offset,
			limit: limit,
			parent_report_id: getCurrentParentReportId()
		})
			.done(function (response) {
				if (!response.success || !response.data) {
					convoLoadInProgress = false;
					$btnOlder.prop('disabled', false);
					if (isInitialLoad) {
						finishInitialConvoLoad();
					} else {
						syncConvoEmptyState();
					}
					return;
				}
				var items = Array.isArray(response.data.items) ? response.data.items : [];
				var chrono = items.slice().reverse();
				var i;
				var htmlChunk = '';
				for (i = 0; i < chrono.length; i++) {
					var it = chrono[i];
					htmlChunk += buildConvoTurnHtml(
						it.id,
						it.prompt_id,
						it.prompt_label,
						it.response,
						it.created_iso,
						it.created_display
					);
				}
				if (isPrepend && htmlChunk) {
					$turns.prepend(htmlChunk);
					if (prevScroll && $convo[0]) {
						$convo[0].scrollTop = $convo[0].scrollHeight - prevScroll.scrollHeight + prevScroll.scrollTop;
					}
				} else if (htmlChunk) {
					$turns.append(htmlChunk);
				}
				convoNextOffset =
					response.data.next_offset != null ? parseInt(response.data.next_offset, 10) : offset + items.length;
				convoHasMore = !!response.data.has_more;
				$wrap.prop('hidden', !convoHasMore);
				convoLoadInProgress = false;
				$btnOlder.prop('disabled', false);
				if (isInitialLoad) {
					finishInitialConvoLoad();
				} else {
					syncConvoEmptyState();
				}
			})
			.fail(function () {
				convoLoadInProgress = false;
				$btnOlder.prop('disabled', false);
				if (isInitialLoad) {
					finishInitialConvoLoad();
				} else {
					syncConvoEmptyState();
				}
			});
	}

	function initConvoThread() {
		var $turns = $('#wf_sn_ai_convo_turns');
		if (!$turns.length) {
			return;
		}
		convoNextOffset = 0;
		convoHasMore = false;
		fetchChipHistoryPage(0, false);
		$('#wf_sn_ai_convo_load_older')
			.off('click.wfSnConvo')
			.on('click.wfSnConvo', function () {
				if (!convoHasMore || convoLoadInProgress) {
					return;
				}
				fetchChipHistoryPage(convoNextOffset, true);
			});
	}

	function runRequest(requestType, $section) {
		var $wrapper = $section.find('.wf-sn-ai-result-wrapper');
		var $stage = $wrapper.find('.wf-sn-ai-result-stage');
		var $timerEl = $wrapper.find('.wf-sn-ai-result-timer');
		var $tipEl = $wrapper.find('.wf-sn-ai-waiting-tip');
		var $result = $wrapper.find('.wf-sn-ai-result');
		var $btn = $section.find('.wf-sn-ai-trigger');

		setAdvisorActionsBusy(true);
		$btn.attr('aria-busy', 'true');
		$btn.data('original-label', $btn.html());
		$btn.html('<span class="dashicons dashicons-update" aria-hidden="true"></span> ' + (base.strings.generating || 'Generating…'));
		$wrapper.show();
		$result.empty().hide().attr('aria-live', 'polite');
		$stage.show().text(base.strings.stagePreparing || '');
		$timerEl.show().text('0.0s');
		$tipEl.prop('hidden', true).removeClass('wf-sn-ai-tip-visible wf-sn-ai-tip-enter').find('.wf-sn-ai-waiting-tip-text').empty();

		var startTime = Date.now();
		var timerId = setInterval(function () {
			var elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
			$timerEl.text(elapsed + 's');
		}, 200);

		var tipIndex = 0;
		var tipIntervalId = null;
		var tips = Array.isArray(base.strings.waitingTips) && base.strings.waitingTips.length ? base.strings.waitingTips : [];
		var $tipText = $tipEl.find('.wf-sn-ai-waiting-tip-text');

		function showTip(text, isFirst) {
			$tipText.text(text);
			if (isFirst) {
				$tipEl.addClass('wf-sn-ai-tip-visible');
			} else {
				$tipEl.addClass('wf-sn-ai-tip-enter');
				setTimeout(function () {
					$tipEl.removeClass('wf-sn-ai-tip-enter');
				}, 400);
			}
		}

		var stageTimeout = setTimeout(function () {
			$stage.text(base.strings.stageSending || '');
		}, 600);
		var stageTimeout2 = setTimeout(function () {
			$stage.text(base.strings.stageWaiting || '');
			if (tips.length) {
				$tipEl.prop('hidden', false);
				showTip(tips[0], true);
				tipIndex = 1;
				tipIntervalId = setInterval(function () {
					showTip(tips[tipIndex % tips.length], false);
					tipIndex += 1;
				}, 5000);
			}
		}, 1500);

		var uiLocale = $section.data('ui-locale') || base.uiLocale || '';

		var postData = {
			action: 'wf_sn_ai_advisor_request',
			nonce: nonce,
			request_type: requestType,
			ui_locale: uiLocale
		};
		$.post(ajaxUrl, postData)
			.done(function (response) {
				clearInterval(timerId);
				clearTimeout(stageTimeout);
				clearTimeout(stageTimeout2);
				if (tipIntervalId) {
					clearInterval(tipIntervalId);
					tipIntervalId = null;
				}
				$tipEl.prop('hidden', true).removeClass('wf-sn-ai-tip-visible wf-sn-ai-tip-enter').find('.wf-sn-ai-waiting-tip-text').empty();
				$stage.text(base.strings.stageReceived || '').delay(800).fadeOut(200);
				$timerEl.fadeOut(200);
				setAdvisorActionsBusy(false);
				$btn.removeAttr('aria-busy');
				if ($btn.data('original-label')) {
					$btn.html($btn.data('original-label'));
				}
				if (response.success && response.data && response.data.report) {
					var newReportId = response.data.report_id ? parseInt(response.data.report_id, 10) : 0;
					var synced = syncLatestReportCard(response.data.report, response.data.usage, newReportId);
					if (synced) {
						$result.empty().hide();
						$wrapper.hide();
						resetConvoForNewReport();
					} else {
						var inner = renderReport(response.data.report);
						var uline = renderUsageLine(response.data.usage);
						if (uline) {
							inner += '<p class="wf-sn-ai-inline-usage description wf-sn-ai-inline-usage--footer">' + uline + '</p>';
						}
						$result.html(inner).show();
					}
				} else if (response.success && response.data && response.data.raw_text) {
					$result.html('<pre>' + escHtml(response.data.raw_text) + '</pre>').show();
				} else {
					var errMsg = extractAjaxErrorMessage(response, base.strings.requestFailed || '');
					$result.html('<p class="description">' + formatTextForHtml(errMsg) + '</p>').show();
				}
			})
			.fail(function () {
				clearInterval(timerId);
				clearTimeout(stageTimeout);
				clearTimeout(stageTimeout2);
				if (tipIntervalId) {
					clearInterval(tipIntervalId);
					tipIntervalId = null;
				}
				$tipEl.prop('hidden', true).removeClass('wf-sn-ai-tip-visible wf-sn-ai-tip-enter').find('.wf-sn-ai-waiting-tip-text').empty();
				$stage.hide();
				$timerEl.hide();
				setAdvisorActionsBusy(false);
				$btn.removeAttr('aria-busy');
				if ($btn.data('original-label')) {
					$btn.html($btn.data('original-label'));
				}
				$result.text(base.strings.connectionError || base.strings.requestFailed || '').show();
			});
	}

	function runChipRequest(promptId) {
		var $turns = $('#wf_sn_ai_convo_turns');
		var $status = $('#wf_sn_ai_chip_status');
		if (!$turns.length) {
			return;
		}
		setAdvisorActionsBusy(true);
		var uiLocale = $('#wf_sn_ai_section_full_report').data('ui-locale') || base.uiLocale || '';
		var chipLbl = chipLabelForPromptId(promptId);

		$status.text(base.strings.chipRunning || '…').prop('hidden', false);
		appendConvoPendingTurn(promptId, chipLbl);
		scrollAdvisorResponseIntoView();

		$.post(ajaxUrl, {
			action: 'wf_sn_ai_advisor_request',
			nonce: nonce,
			request_type: PROMPT_CHIP,
			prompt_id: promptId,
			ui_locale: uiLocale
		})
			.done(function (response) {
				setAdvisorActionsBusy(false);
				$status.prop('hidden', true).text('');
				removeConvoPending();
				var lbl = chipLabelForPromptId(response.data && response.data.prompt_id ? response.data.prompt_id : promptId) || chipLbl;
				if (response.success && response.data && response.data.response) {
					var rid = response.data.report_id ? parseInt(response.data.report_id, 10) : 0;
					appendConvoTurn(
						rid,
						promptId,
						lbl,
						response.data.response,
						response.data.usage,
						response.data.created_iso,
						response.data.created_display
					);
					var $convo = $('#wf_sn_ai_convo');
					if ($convo.length && $convo[0]) {
						$convo[0].scrollTop = $convo[0].scrollHeight;
					}
				} else {
					var msg = extractAjaxErrorMessage(response, base.strings.requestFailed || '');
					appendConvoErrorTurn(promptId, lbl, msg);
				}
			})
			.fail(function () {
				setAdvisorActionsBusy(false);
				$status.prop('hidden', true).text('');
				removeConvoPending();
				var lbl = chipLabelForPromptId(promptId);
				appendConvoErrorTurn(
					promptId,
					lbl,
					base.strings.connectionError || base.strings.requestFailed || ''
				);
			});
	}

	function initSections() {
		$('.wf-sn-ai-trigger').on('click', function () {
			var requestType = $(this).data('request-type');
			var $section = $(this).closest('.wf-sn-ai-section');
			runRequest(requestType, $section);
		});
	}

	function initChips() {
		$(document).on('click', '.wf-sn-ai-chip:not(:disabled)', function () {
			var pid = $(this).attr('data-prompt-id');
			if (!pid) {
				return;
			}
			runChipRequest(String(pid));
		});
	}

	function initChipExpandToggles() {
		$(document).on('click.wfSnChipExpand', '.wf-sn-ai-chip-expand__toggle', function (e) {
			e.preventDefault();
			var $btn = $(this);
			var cid = $btn.attr('aria-controls');
			if (!cid) {
				return;
			}
			var fullEl = document.getElementById(cid);
			var $wrap = $btn.closest('.wf-sn-ai-chip-expand');
			if (!fullEl || !$wrap.length) {
				return;
			}
			$wrap.find('.wf-sn-ai-chip-expand__teaser').prop('hidden', true);
			fullEl.hidden = false;
			$btn.attr('aria-expanded', 'true');
			try {
				fullEl.focus();
			} catch (err) {
				// Ignore focus errors in edge browsers.
			}
		});
	}

	function initDeleteReports() {
		$(document).on('click', '.wf-sn-ai-delete-report', function () {
			var id = $(this).data('report-id');
			if (!id) {
				return;
			}
			var msg = base.strings.deleteConfirm || 'Delete?';
			if (!window.confirm(msg)) {
				return;
			}
			var $btn = $(this);
			$btn.prop('disabled', true);
			$.post(ajaxUrl, {
				action: 'wf_sn_ai_advisor_delete_report',
				nonce: nonce,
				id: id
			})
				.done(function (response) {
					if (response.success) {
						var delId = response.data && response.data.id != null ? response.data.id : $btn.data('report-id');
						var $row = $btn.closest('tr');
						if (delId) {
							$('.wf-sn-ai-convo__turn[data-report-id="' + String(delId) + '"]').remove();
							syncConvoEmptyState();
						}
						if ($row.length) {
							var $next = $row.next('tr');
							$row.remove();
							if ($next.is('.wf-sn-ai-report-detail-row, .wf-sn-ai-chip-detail-row')) {
								$next.remove();
							}
						}
					} else {
						$btn.prop('disabled', false);
					}
				})
				.fail(function () {
					$btn.prop('disabled', false);
				});
		});
	}

	function initShowMoreIssues() {
		$(document).on('click', '#wf_sn_ai_toggle_more_issues', function () {
			var $btn = $(this);
			var $more = $('#wf_sn_ai_more_improvements');
			if (!$more.length) {
				return;
			}
			var open = $btn.attr('aria-expanded') === 'true';
			if (open) {
				$more.prop('hidden', true);
				$btn.attr('aria-expanded', 'false').text(base.strings.showMoreIssues || 'Show more');
			} else {
				$more.prop('hidden', false);
				$btn.attr('aria-expanded', 'true').text(base.strings.showFewerIssues || 'Show fewer');
			}
		});
	}

	function initPreviewModal() {
		var $modal = $('#wf_sn_ai_preview_modal');
		var $content = $modal.find('.wf-sn-ai-preview-data-content');
		if (!$modal.length || !$content.length) {
			return;
		}

		function showModal() {
			$modal.prop('hidden', false);
		}
		function hideModal() {
			$modal.prop('hidden', true);
		}

		$(document).on('click', '.wf-sn-ai-preview-data-link', function (e) {
			e.preventDefault();
			var $link = $(this);
			var $section = $link.closest('.wf-sn-ai-section');
			var uiLocale = $section.length ? $section.data('ui-locale') || '' : (base.uiLocale || '');
			var requestType = $link.data('request-type') || 'full_report';

			$content.text(base.strings.previewLoading || 'Loading…');
			showModal();

			$.post(ajaxUrl, {
				action: 'wf_sn_ai_advisor_preview_data',
				nonce: nonce,
				request_type: requestType,
				ui_locale: uiLocale
			})
				.done(function (response) {
					if (response.success && response.data && response.data.data) {
						try {
							$content.text(JSON.stringify(response.data.data, null, 2));
						} catch (err) {
							$content.text(base.strings.previewError || '');
						}
					} else {
						$content.text(response.data && response.data.message ? response.data.message : (base.strings.previewError || ''));
					}
				})
				.fail(function () {
					$content.text(base.strings.previewError || base.strings.connectionError || '');
				});
		});

		$modal.find('.wf-sn-ai-preview-modal-close, .wf-sn-ai-preview-modal-backdrop').on('click', hideModal);
	}

	function initViewFullReport() {
		$(document).on('click', '.wf-sn-ai-view-full-report', function () {
			var $btn = $(this);
			var $card = $btn.closest('.wf-sn-ai-latest-report');
			var $expanded = $card.find('#wf_sn_ai_full_report_expanded');
			if (!$expanded.length) {
				return;
			}
			var expanded = $btn.attr('aria-expanded') === 'true';
			var newExpanded = !expanded;
			if (newExpanded && $expanded.children().length === 0) {
				var reportJson = $card.attr('data-report-json');
				if (reportJson) {
					try {
						var report = JSON.parse(reportJson);
						if (report && typeof report === 'object') {
							$expanded.html(renderReport(report));
						}
					} catch (e) {
						$expanded.text(base.strings.requestFailed || '');
					}
				}
			}
			$expanded.prop('hidden', !newExpanded);
			$btn.attr('aria-expanded', newExpanded);
		});
	}

	function renderAttackChart() {
		var $card = $('#wf_sn_ai_latest_report_card');
		var $container = $('#wf_sn_ai_attack_chart');
		if (!$card.length || !$container.length) {
			return;
		}
		var current = parseInt($card.data('current-7d'), 10) || 0;
		var prev = parseInt($card.data('prev-7d'), 10) || 0;
		var maxVal = Math.max(current, prev, 1);
		var w1 = prev > 0 ? Math.round((prev / maxVal) * 100) : 0;
		var w2 = current > 0 ? Math.round((current / maxVal) * 100) : 0;
		var labelPrev = base.strings.previous7Days || 'Previous 7 days';
		var labelCurrent = base.strings.last7Days || 'Last 7 days';
		var html = '<div class="wf-sn-ai-chart-bars">' +
			'<div class="wf-sn-ai-chart-bar-wrap"><span class="wf-sn-ai-chart-label">' + escHtml(labelPrev) + '</span><div class="wf-sn-ai-chart-bar wf-sn-ai-chart-bar-prev" style="width:' + w1 + '%" title="' + escHtml(String(prev)) + '"></div><span class="wf-sn-ai-chart-value">' + prev + '</span></div>' +
			'<div class="wf-sn-ai-chart-bar-wrap"><span class="wf-sn-ai-chart-label">' + escHtml(labelCurrent) + '</span><div class="wf-sn-ai-chart-bar wf-sn-ai-chart-bar-current" style="width:' + w2 + '%" title="' + escHtml(String(current)) + '"></div><span class="wf-sn-ai-chart-value">' + current + '</span></div>' +
			'</div>';
		$container.html(html);
	}

	function initImprovementToggles(container) {
		container = container || $(document);
		container.off('click.wfSnImprovement').on('click.wfSnImprovement', '.wf-sn-ai-improvement-toggle', function () {
			var $btn = $(this);
			var $details = $btn.closest('.wf-sn-ai-improvement').find('.wf-sn-ai-improvement-details');
			var expanded = $btn.attr('aria-expanded') === 'true';
			var newExpanded = !expanded;
			$btn.attr('aria-expanded', newExpanded);
			$details.attr('aria-hidden', newExpanded ? 'false' : 'true');
			if (newExpanded) {
				$details.prop('hidden', false);
			} else {
				$details.prop('hidden', true);
			}
		});
	}

	$(function () {
		initSections();
		initChips();
		initChipExpandToggles();
		initDeleteReports();
		initShowMoreIssues();
		initPreviewModal();
		initViewFullReport();
		initConvoThread();
		renderAttackChart();
		initImprovementToggles($(document));
	});
})(jQuery);
