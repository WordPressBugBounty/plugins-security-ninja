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

	function getSelectedConnectorId() {
		var $select = $('#wf_sn_ai_advisor_connector');
		if (!$select.length) {
			return '';
		}
		return String($select.val() || '').trim();
	}

	function connectorPostField() {
		var id = getSelectedConnectorId();
		return id ? { connector_id: id } : {};
	}

	function getConnectorLabel(connectorId) {
		var id = connectorId || getSelectedConnectorId();
		if (!id) {
			return '';
		}
		if (base.connectorsMeta && Array.isArray(base.connectorsMeta)) {
			for (var i = 0; i < base.connectorsMeta.length; i++) {
				if (base.connectorsMeta[i].id === id) {
					return base.connectorsMeta[i].label || id;
				}
			}
		}
		return id;
	}

	function formatLocalized(str, args) {
		var out = String(str || '');
		var list = Array.isArray(args) ? args : [];
		for (var i = 0; i < list.length; i++) {
			out = out.replace(new RegExp('%' + (i + 1) + '\\$s', 'g'), list[i]);
		}
		if (list.length) {
			out = out.replace(/%s/g, list[0]);
		}
		return out;
	}

	function formatPrepareStatsLine(stats) {
		if (!stats || typeof stats !== 'object') {
			return '';
		}
		var kb = stats.payload_chars ? (stats.payload_chars / 1024).toFixed(1) : '0';
		var tokens = stats.estimated_input_tokens ? String(stats.estimated_input_tokens) : '0';
		var guidance = stats.guidance_item_count !== undefined ? String(stats.guidance_item_count) : '0';
		return formatLocalized(base.strings.prepareStatsLine || '', [kb, tokens, guidance]);
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

	function renderStructuredErrorHtml(data, fallbackMsg) {
		var msg = fallbackMsg || '';
		var technical = null;
		var actions = [];
		if (data && typeof data === 'object') {
			if (data.message) {
				msg = data.message;
			}
			if (data.technical) {
				technical = data.technical;
			}
			if (Array.isArray(data.actions)) {
				actions = data.actions;
			}
		}
		var html = '<div class="wf-sn-ai-error-panel">';
		html += '<h3 class="wf-sn-ai-error-title">' + escHtml(base.strings.errorTitle || 'The AI provider did not respond') + '</h3>';
		html += '<p>' + formatTextForHtml(msg) + '</p>';
		html += '<p class="description">' + escHtml(base.strings.nothingChangedOnSite || 'Nothing was changed on your site.') + '</p>';
		html += '<p class="wf-sn-ai-error-actions">';
		if (actions.indexOf('retry') !== -1) {
			html += '<button type="button" class="button button-primary wf-sn-ai-error-retry">' + escHtml(base.strings.tryAgain || 'Try again') + '</button> ';
		}
		if (actions.indexOf('switch_connector') !== -1) {
			html += '<button type="button" class="button wf-sn-ai-error-switch">' + escHtml(base.strings.switchConnector || 'Use another AI connector') + '</button> ';
		}
		if (actions.indexOf('view_results') !== -1 && base.mainSnUrl) {
			html += '<a href="' + escAttr(base.mainSnUrl) + '#sn_tests" class="button button-link">' + escHtml(base.strings.viewResults || 'View scan results without AI') + '</a>';
		}
		html += '</p>';
		if (technical && (technical.error || technical.provider || technical.time)) {
			html += '<details class="wf-sn-ai-error-technical"><summary>' + escHtml(base.strings.technicalDetails || 'Technical details') + '</summary><ul>';
			if (technical.provider) {
				html += '<li><strong>Provider:</strong> ' + escHtml(String(technical.provider)) + '</li>';
			}
			if (technical.time) {
				html += '<li><strong>Time:</strong> ' + escHtml(String(technical.time)) + '</li>';
			}
			if (technical.error) {
				html += '<li><strong>Error:</strong> ' + escHtml(String(technical.error)) + '</li>';
			}
			if (technical.model) {
				html += '<li><strong>Model:</strong> ' + escHtml(String(technical.model)) + '</li>';
			}
			if (technical.generation_mode) {
				html += '<li><strong>Mode:</strong> ' + escHtml(String(technical.generation_mode)) + '</li>';
			}
			if (technical.finish_reason) {
				html += '<li><strong>Finish reason:</strong> ' + escHtml(String(technical.finish_reason)) + '</li>';
			}
			if (technical.max_tokens !== undefined && technical.max_tokens !== null && technical.max_tokens !== '') {
				html += '<li><strong>Max tokens:</strong> ' + escHtml(String(technical.max_tokens)) + '</li>';
			}
			if (technical.output_tokens !== undefined && technical.output_tokens !== null && technical.output_tokens !== '') {
				html += '<li><strong>Output tokens:</strong> ' + escHtml(String(technical.output_tokens)) + '</li>';
			}
			if (technical.input_tokens !== undefined && technical.input_tokens !== null && technical.input_tokens !== '') {
				html += '<li><strong>Input tokens:</strong> ' + escHtml(String(technical.input_tokens)) + '</li>';
			}
			if (technical.response_chars !== undefined && technical.response_chars !== null && technical.response_chars !== '') {
				html += '<li><strong>Response length:</strong> ' + escHtml(String(technical.response_chars)) + ' chars</li>';
			}
			if (technical.request_id) {
				html += '<li><strong>Request ID:</strong> ' + escHtml(String(technical.request_id)) + '</li>';
			}
			html += '</ul></details>';
		}
		if (data && data.snapshot_saved) {
			html += '<p class="description">' + escHtml(base.strings.snapshotSaved || 'We saved the scan snapshot. Retrying will reuse the same scan data unless you refresh scans.') + '</p>';
		}
		html += '</div>';
		return html;
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
		$('.wf-sn-ai-chip-wrap').each(function () {
			var $wrap = $(this);
			var $c = $wrap.find('.wf-sn-ai-chip');
			var id = $c.attr('data-prompt-id');
			if (!id || !base.chips) {
				$c.prop('disabled', false).removeClass('wf-sn-ai-chip--disabled');
				return;
			}
			var chipMeta = null;
			for (var i = 0; i < base.chips.length; i++) {
				if (base.chips[i].id === id) {
					chipMeta = base.chips[i];
					break;
				}
			}
			var en = chipMeta ? !!chipMeta.enabled : true;
			$c.prop('disabled', !en);
			if (en) {
				$c.removeClass('wf-sn-ai-chip--disabled');
			} else {
				$c.addClass('wf-sn-ai-chip--disabled');
			}
		});
	}

	var COMPARISON_CHIP_IDS = ['delta_since_last', 'what_improved'];

	function enabledChipsFromList(chips) {
		if (!Array.isArray(chips)) {
			return [];
		}
		return chips.filter(function (chip) {
			return chip && chip.enabled;
		});
	}

	function hasLockedComparisonChips(chips) {
		if (!Array.isArray(chips)) {
			return false;
		}
		return chips.some(function (chip) {
			return chip && COMPARISON_CHIP_IDS.indexOf(chip.id) !== -1 && !chip.enabled;
		});
	}

	function rebuildChipRow(chips) {
		var $row = $('#wf_sn_ai_chip_row');
		if (!$row.length) {
			return;
		}
		var enabled = enabledChipsFromList(chips);
		var html = '';
		enabled.forEach(function (chip) {
			html +=
				'<div class="wf-sn-ai-chip-wrap">' +
				'<button type="button" class="button wf-sn-ai-chip" data-prompt-id="' +
				escAttr(chip.id) +
				'">' +
				escHtml(chip.label) +
				'</button></div>';
		});
		$row.html(html);
		var $comparison = $('#wf_sn_ai_followup_comparison');
		if ($comparison.length) {
			$comparison.prop('hidden', !hasLockedComparisonChips(chips));
		}
	}

	function setFollowUpPhase(active, chips) {
		var $column = $('#wf_sn_ai_chat_column');
		var $journey = $('#wf_sn_ai_followup_journey');
		var $locked = $('#wf_sn_ai_followup_locked');
		var $active = $('#wf_sn_ai_followup_active');
		var $introActive = $('.wf-sn-ai-convo-intro--active');
		var $introLocked = $('.wf-sn-ai-convo-intro--locked');
		if (!$column.length) {
			return;
		}
		$column.attr('data-followup-ready', active ? '1' : '0');
		if (active) {
			$journey.prop('hidden', true);
			$locked.prop('hidden', true);
			$active.prop('hidden', false);
			$introActive.prop('hidden', false);
			$introLocked.prop('hidden', true);
			rebuildChipRow(chips || base.chips);
		} else {
			$journey.prop('hidden', false);
			$locked.prop('hidden', false);
			$active.prop('hidden', true);
			$introActive.prop('hidden', true);
			$introLocked.prop('hidden', false);
		}
		syncConvoEmptyState();
	}

	function applyFollowUpChips(chips, followupReady) {
		if (Array.isArray(chips)) {
			base.chips = chips;
		}
		var active =
			typeof followupReady === 'boolean'
				? followupReady
				: enabledChipsFromList(base.chips).length > 0;
		setFollowUpPhase(active, base.chips);
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
			.replace('%1$s', escHtml(String(usage.model || '-')))
			.replace('%2$s', escHtml(String(usage.token_input != null ? usage.token_input : '-')))
			.replace('%3$s', escHtml(String(usage.token_output != null ? usage.token_output : '-')));
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
		var $journey = $('#wf_sn_ai_followup_journey');
		if (!$loading.length) {
			return;
		}
		$loading.prop('hidden', !isLoading);
		if (isLoading) {
			$convo.prop('hidden', true);
			$empty.prop('hidden', true);
			if ($journey.length) {
				$journey.prop('hidden', true);
			}
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
		var $journey = $('#wf_sn_ai_followup_journey');
		if (!$turns.length || !$empty.length) {
			return;
		}
		var journeyVisible = $journey.length && !$journey.prop('hidden');
		if (journeyVisible) {
			$empty.prop('hidden', true);
			if ($convo.length) {
				$convo.prop('hidden', true);
			}
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

	function appendConvoErrorTurn(promptId, promptLabel, errorData) {
		var echoTpl = base.strings.promptEchoPrefix || '';
		var promptLine = '';
		if (echoTpl && promptLabel) {
			promptLine =
				'<p class="wf-sn-ai-convo__prompt">' + escHtml(echoTpl.replace('%s', promptLabel)) + '</p>';
		}
		var errHtml = '';
		if (errorData && typeof errorData === 'object') {
			errHtml = renderStructuredErrorHtml(errorData, base.strings.requestFailed || '');
		} else {
			errHtml = renderStructuredErrorHtml(null, String(errorData || base.strings.requestFailed || ''));
		}
		var html =
			'<article class="wf-sn-ai-convo__turn wf-sn-ai-convo__turn--error" data-prompt-id="' +
			escAttr(String(promptId)) +
			'">' +
			promptLine +
			'<div class="wf-sn-ai-convo__answer wf-sn-ai-result-canvas">' +
			errHtml +
			'</div></article>';
		var $turn = $(html);
		$('#wf_sn_ai_convo_turns').append($turn);
		bindStructuredErrorActions($turn.find('.wf-sn-ai-convo__answer'), promptId);
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

	function bindStructuredErrorActions($container, chipPromptId) {
		$container.find('.wf-sn-ai-error-retry').on('click', function () {
			if (chipPromptId) {
				runChipRequest(String(chipPromptId));
				return;
			}
			var $section = $('#wf_sn_ai_section_full_report');
			runRequest('full_report', $section);
		});
		$container.find('.wf-sn-ai-error-switch').on('click', function () {
			var $settings = $('.wf-sn-ai-settings-card');
			if ($settings.length && !$settings.prop('open')) {
				$settings.prop('open', true);
			}
			$('html, body').animate({ scrollTop: $settings.offset().top - 40 }, 300);
		});
	}

	function runRequest(requestType, $section) {
		var $wrapper = $section.find('.wf-sn-ai-result-wrapper');
		var $stage = $wrapper.find('.wf-sn-ai-result-stage');
		var $statsEl = $wrapper.find('.wf-sn-ai-result-stats');
		var $timerEl = $wrapper.find('.wf-sn-ai-result-timer');
		var $tipEl = $wrapper.find('.wf-sn-ai-waiting-tip');
		var $result = $wrapper.find('.wf-sn-ai-result');
		var $btn = $section.find('.wf-sn-ai-trigger');

		setAdvisorActionsBusy(true);
		$btn.attr('aria-busy', 'true');
		$btn.data('original-label', $btn.html());
		$btn.html( escHtml( base.strings.generating || 'Generating…' ) );
		$wrapper.show();
		$result.empty().hide().removeClass('wf-sn-ai-result--error').attr('aria-live', 'polite');
		$stage.show().text(base.strings.stagePreparing || '');
		$statsEl.empty().hide();
		$timerEl.show().text('0.0s');
		$tipEl.prop('hidden', true).removeClass('wf-sn-ai-tip-visible wf-sn-ai-tip-enter').find('.wf-sn-ai-waiting-tip-text').empty();

		var startTime = Date.now();
		var timerId = setInterval(function () {
			var elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
			$timerEl.text(elapsed + 's');
		}, 200);

		var tipIndex = 0;
		var tipIntervalId = null;
		var longWaitTimeoutId = null;
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

		function startWaitingTips() {
			if (!tips.length || tipIntervalId) {
				return;
			}
			$tipEl.prop('hidden', false);
			showTip(tips[0], true);
			tipIndex = 1;
			tipIntervalId = setInterval(function () {
				showTip(tips[tipIndex % tips.length], false);
				tipIndex += 1;
			}, 5000);
		}

		function cleanupWaitUi() {
			clearInterval(timerId);
			if (tipIntervalId) {
				clearInterval(tipIntervalId);
				tipIntervalId = null;
			}
			if (longWaitTimeoutId) {
				clearTimeout(longWaitTimeoutId);
				longWaitTimeoutId = null;
			}
			$tipEl.prop('hidden', true).removeClass('wf-sn-ai-tip-visible wf-sn-ai-tip-enter').find('.wf-sn-ai-waiting-tip-text').empty();
		}

		function resetButton() {
			setAdvisorActionsBusy(false);
			$btn.removeAttr('aria-busy');
			if ($btn.data('original-label')) {
				$btn.html($btn.data('original-label'));
			}
		}

		function handleSuccess(response) {
			cleanupWaitUi();
			$stage.text(base.strings.stageReceived || '').delay(800).fadeOut(200);
			$timerEl.fadeOut(200);
			$statsEl.fadeOut(200);
			resetButton();
			if (response.success && response.data && response.data.report) {
				var newReportId = response.data.report_id ? parseInt(response.data.report_id, 10) : 0;
				var synced = syncLatestReportCard(response.data.report, response.data.usage, newReportId);
				if (synced) {
					$result.empty().hide();
					$wrapper.hide();
					resetConvoForNewReport();
					if (response.data.chips) {
						applyFollowUpChips(response.data.chips, response.data.followup_ready);
					} else {
						applyFollowUpChips(null, true);
					}
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
				$result.addClass('wf-sn-ai-result--error').html(renderStructuredErrorHtml(response.data, errMsg)).show();
				bindStructuredErrorActions($result);
			}
		}

		function handleFailure(message) {
			cleanupWaitUi();
			$stage.hide();
			$timerEl.hide();
			$statsEl.hide();
			resetButton();
			$result.addClass('wf-sn-ai-result--error').html(renderStructuredErrorHtml(null, message || base.strings.connectionError || base.strings.requestFailed || '')).show();
			bindStructuredErrorActions($result);
		}

		var uiLocale = $section.data('ui-locale') || base.uiLocale || '';

		function runGenerationPhase(prepareData) {
			var connectorLabel = (prepareData && prepareData.connector_label) || getConnectorLabel(prepareData && prepareData.connector_id);
			if (!connectorLabel) {
				connectorLabel = base.strings.stageSending || 'AI';
			}
			$stage.text(formatLocalized(base.strings.stageSendingTo || base.strings.stageSending || '', [connectorLabel]));
			if (prepareData && prepareData.stats) {
				var statsLine = formatPrepareStatsLine(prepareData.stats);
				if (statsLine) {
					$statsEl.text(statsLine).show();
				}
			}
			startWaitingTips();
			longWaitTimeoutId = setTimeout(function () {
				if (base.strings.longWaitExpectation) {
					showTip(base.strings.longWaitExpectation, false);
				}
			}, 45000);

			$.post(
				ajaxUrl,
				$.extend(
					{
						action: 'wf_sn_ai_advisor_request',
						nonce: nonce,
						request_type: requestType,
						ui_locale: uiLocale,
						prepared: 1
					},
					connectorPostField()
				)
			)
				.done(handleSuccess)
				.fail(function () {
					handleFailure(base.strings.connectionError || base.strings.requestFailed || '');
				});
			$stage.text(formatLocalized(base.strings.stageWaitingFor || base.strings.stageWaiting || '', [connectorLabel]));
		}

		$.post(
			ajaxUrl,
			$.extend(
				{
					action: 'wf_sn_ai_advisor_prepare',
					nonce: nonce,
					ui_locale: uiLocale
				},
				connectorPostField()
			)
		)
			.done(function (response) {
				if (response.success && response.data && response.data.prepared) {
					runGenerationPhase(response.data);
					return;
				}
				handleFailure(extractAjaxErrorMessage(response, base.strings.requestFailed || ''));
			})
			.fail(function () {
				handleFailure(base.strings.connectionError || base.strings.requestFailed || '');
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

		$.post(
			ajaxUrl,
			$.extend(
				{
					action: 'wf_sn_ai_advisor_request',
					nonce: nonce,
					request_type: PROMPT_CHIP,
					prompt_id: promptId,
					ui_locale: uiLocale
				},
				connectorPostField()
			)
		)
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
					appendConvoErrorTurn(
						promptId,
						lbl,
						response.data && typeof response.data === 'object' ? response.data : extractAjaxErrorMessage(response, base.strings.requestFailed || '')
					);
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
		if ($('#wf_sn_ai_chat_column').length) {
			var initialReady =
				typeof base.followupReady === 'boolean'
					? base.followupReady
					: enabledChipsFromList(base.chips).length > 0;
			setFollowUpPhase(initialReady, base.chips);
		}
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
			var $btn = $(this);
			SnDialog.confirm({
				message: msg,
				danger: true
			}).then(function (ok) {
				if (!ok) {
					return;
				}
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
		$(document).on('click', '.wf-sn-ai-preview-data-link', function (e) {
			e.preventDefault();
			var $link = $(this);
			var $section = $link.closest('.wf-sn-ai-section');
			var uiLocale = $section.length ? $section.data('ui-locale') || '' : (base.uiLocale || '');
			var requestType = $link.data('request-type') || 'full_report';
			var title = base.strings.previewModalTitle || 'Preview of data sent to AI';

			SnDialog.open({
				title: title,
				size: 'large',
				bodyHtml: '<p class="wf-sn-ai-preview-loading">' + $('<div/>').text(base.strings.previewLoading || 'Loading…').html() + '</p>'
			});

			$.post(
				ajaxUrl,
				$.extend(
					{
						action: 'wf_sn_ai_advisor_preview_data',
						nonce: nonce,
						request_type: requestType,
						ui_locale: uiLocale
					},
					connectorPostField()
				)
			)
				.done(function (response) {
					var root = document.getElementById('sn-dialog-root');
					var body = root ? root.querySelector('.sn-dialog-body') : null;
					if (!body) {
						return;
					}
					var html = '';
					if (response.success && response.data && response.data.data) {
						if (response.data.stats) {
							var statsLine = formatPrepareStatsLine(response.data.stats);
							if (statsLine) {
								html += '<p class="wf-sn-ai-preview-stats">' + $('<div/>').text(statsLine).html() + '</p>';
							}
						}
						try {
							html += '<pre class="wf-sn-ai-preview-data-content"><code>' + $('<div/>').text(JSON.stringify(response.data.data, null, 2)).html() + '</code></pre>';
						} catch (err) {
							html += '<p>' + $('<div/>').text(base.strings.previewError || '').html() + '</p>';
						}
					} else {
						html = '<p>' + $('<div/>').text(response.data && response.data.message ? response.data.message : (base.strings.previewError || '')).html() + '</p>';
					}
					body.innerHTML = html;
				})
				.fail(function () {
					var root = document.getElementById('sn-dialog-root');
					var body = root ? root.querySelector('.sn-dialog-body') : null;
					if (body) {
						body.innerHTML = '<p>' + $('<div/>').text(base.strings.previewError || base.strings.connectionError || '').html() + '</p>';
					}
				});
		});
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

	function initTestConnection() {
		var $btn = $('#wf_sn_ai_test_connection_btn');
		var $status = $('#wf_sn_ai_test_connection_status');
		if (!$btn.length || !$status.length) {
			return;
		}
		$btn.on('click', function () {
			var connectorId = getSelectedConnectorId();
			if (!connectorId) {
				$status
					.removeClass('wf-sn-ai-test-connection__status--ok wf-sn-ai-test-connection__status--error')
					.addClass('wf-sn-ai-test-connection__status--error')
					.text(base.strings.testConnectionSelect || 'Select a connector first.');
				return;
			}
			$btn.prop('disabled', true);
			$status
				.removeClass('wf-sn-ai-test-connection__status--ok wf-sn-ai-test-connection__status--error')
				.html('<span class="spinner is-active" aria-hidden="true"></span> ' + escHtml(base.strings.testConnectionRunning || 'Testing connection…'));
			$.post(base.ajaxurl, {
				action: 'wf_sn_ai_advisor_test_connector',
				nonce: base.nonce,
				connector_id: connectorId
			})
				.done(function (response) {
					if (response.success && response.data && response.data.message) {
						$status
							.removeClass('wf-sn-ai-test-connection__status--error')
							.addClass('wf-sn-ai-test-connection__status--ok')
							.text(response.data.message);
						return;
					}
					var errMsg = (response.data && response.data.message) ? response.data.message : (base.strings.requestFailed || 'Request failed.');
					var fixUrl = (response.data && response.data.connectors_url) ? response.data.connectors_url : (base.connectorsAdminUrl || '');
					var html = escHtml(errMsg);
					if (fixUrl) {
						html += ' <a href="' + escAttr(fixUrl) + '">' + escHtml(base.strings.testConnectionFixLink || 'Open Settings → Connectors') + '</a>';
					}
					$status
						.removeClass('wf-sn-ai-test-connection__status--ok')
						.addClass('wf-sn-ai-test-connection__status--error')
						.html(html);
				})
				.fail(function () {
					$status
						.removeClass('wf-sn-ai-test-connection__status--ok')
						.addClass('wf-sn-ai-test-connection__status--error')
						.text(base.strings.connectionError || 'The request failed.');
				})
				.always(function () {
					$btn.prop('disabled', false);
				});
		});
		$('#wf_sn_ai_advisor_connector').on('change', function () {
			$status.removeClass('wf-sn-ai-test-connection__status--ok wf-sn-ai-test-connection__status--error').empty();
		});
	}

	function initRunScheduledNow() {
		var $btn = $('#wf_sn_ai_schedule_run_now_btn');
		var $status = $('#wf_sn_ai_schedule_run_now_status');
		if (!$btn.length || !$status.length) {
			return;
		}
		$btn.on('click', function () {
			$btn.prop('disabled', true);
			$status
				.removeClass('wf-sn-ai-schedule-run-now__status--ok wf-sn-ai-schedule-run-now__status--error')
				.html('<span class="spinner is-active" aria-hidden="true"></span> ' + escHtml(base.strings.scheduleRunNowRunning || 'Queuing report…'));
			$.post(base.ajaxurl, {
				action: 'wf_sn_ai_advisor_run_scheduled_now',
				nonce: base.nonce
			})
				.done(function (response) {
					if (response.success && response.data && response.data.message) {
						$status
							.removeClass('wf-sn-ai-schedule-run-now__status--error')
							.addClass('wf-sn-ai-schedule-run-now__status--ok')
							.text(response.data.message);
						return;
					}
					var errMsg = (response.data && response.data.message) ? response.data.message : (base.strings.requestFailed || 'Request failed.');
					$status
						.removeClass('wf-sn-ai-schedule-run-now__status--ok')
						.addClass('wf-sn-ai-schedule-run-now__status--error')
						.text(errMsg);
				})
				.fail(function () {
					$status
						.removeClass('wf-sn-ai-schedule-run-now__status--ok')
						.addClass('wf-sn-ai-schedule-run-now__status--error')
						.text(base.strings.connectionError || 'The request failed.');
				})
				.always(function () {
					$btn.prop('disabled', false);
				});
		});
	}

	function initSchedulePanelToggle() {
		var $panel = $('#wf_sn_ai_schedule_panel');
		var $toggle = $('#wf_sn_ai_advisor_scheduled_report_enabled');
		if (!$panel.length || !$toggle.length || $panel.hasClass('wf-sn-ai-schedule--locked')) {
			return;
		}
		function syncPanelState() {
			if ($toggle.is(':checked')) {
				$panel.removeClass('is-disabled').addClass('is-enabled');
			} else {
				$panel.removeClass('is-enabled').addClass('is-disabled');
			}
		}
		$toggle.on('change', syncPanelState);
		syncPanelState();
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
		initTestConnection();
		initRunScheduledNow();
		initSchedulePanelToggle();
		renderAttackChart();
		initImprovementToggles($(document));
	});
})(jQuery);
