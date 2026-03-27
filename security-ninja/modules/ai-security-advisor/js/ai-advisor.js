(function ($) {
	'use strict';

	var base = window.wfSnAiAdvisor || {};
	base.strings = base.strings || {};

	// Use the standard WordPress ajaxurl. If it's missing, something is fundamentally wrong with the page context.
	var ajaxUrl = window.ajaxurl || '';
	var nonce = base.nonce || '';

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

	function escAttr(str) {
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	/**
	 * Convert report object to plain text for print/copy.
	 *
	 * @param {Object} report Decoded report object.
	 * @return {string}
	 */
	function reportToPlainText(report) {
		if (!report || typeof report !== 'object') {
			return '';
		}
		var lines = [];
		lines.push(base.strings.executiveSummary || 'Security Advisor Report');
		lines.push('');
		if (report.executive_summary) {
			lines.push(report.executive_summary);
			lines.push('');
		}
		if (report.overview) {
			lines.push(base.strings.overview || 'Overview');
			lines.push(report.overview);
			lines.push('');
		}
		if (Array.isArray(report.top_improvements) && report.top_improvements.length) {
			lines.push(base.strings.topImprovements || 'Top improvements');
			for (var i = 0; i < report.top_improvements.length; i++) {
				var item = report.top_improvements[i] || {};
				var title = item.title || item.short_label || '';
				var details = item.details || '';
				lines.push(title);
				if (details) {
					lines.push(details);
				}
				lines.push('');
			}
		}
		if (report.activity) {
			lines.push(base.strings.activityLast7Days || 'Activity (last 7 days)');
			if (report.activity.summary) {
				lines.push(report.activity.summary);
			}
			if (report.activity.attack_volume_trend || report.activity.attack_volume_reason) {
				lines.push((report.activity.attack_volume_trend || '') + ' ' + (report.activity.attack_volume_reason || ''));
			}
		}
		return lines.join('\n').trim();
	}

	function renderReport(report) {
		if (!report || typeof report !== 'object') {
			return '';
		}

		try {
			var html = [];

			if (report.executive_summary) {
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
					if (item.id === 'mysql_permissions') {
						risk = 'low';
					}
					if (['low', 'medium', 'high'].indexOf(risk) === -1) {
						risk = 'low';
					}
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

			var exportLabel = base.strings.exportReport || 'Print / Copy report';
			var reportJson = '';
			try {
				reportJson = JSON.stringify(report);
			} catch (e) {}
			if (reportJson) {
				html.push(
					'<div class="wf-sn-ai-export-report-wrap">' +
						'<button type="button" class="button button-small wf-sn-ai-export-report-btn" data-report-json="' + escAttr(reportJson) + '">' + escHtml(exportLabel) + '</button>' +
					'</div>'
				);
			}

			return html.join('');
		} catch (e) {
			return '';
		}
	}

	function runRequest(requestType, $section) {
		var $wrapper = $section.find('.wf-sn-ai-result-wrapper');
		var $stage = $wrapper.find('.wf-sn-ai-result-stage');
		var $timerEl = $wrapper.find('.wf-sn-ai-result-timer');
		var $tipEl = $wrapper.find('.wf-sn-ai-waiting-tip');
		var $result = $wrapper.find('.wf-sn-ai-result');
		var $btn = $section.find('.wf-sn-ai-trigger');

		$btn.prop('disabled', true).attr('aria-busy', 'true');
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
				$btn.prop('disabled', false).removeAttr('aria-busy');
				if ($btn.data('original-label')) {
					$btn.html($btn.data('original-label'));
				}
				if (response.success && response.data && response.data.report) {
					$result.html(renderReport(response.data.report)).show();
				} else if (response.success && response.data && response.data.raw_text) {
					$result.html('<pre>' + escHtml(response.data.raw_text) + '</pre>').show();
				} else {
					var errMsg = (response.data && response.data.message) ? response.data.message : (base.strings.requestFailed || '');
					$result.text(errMsg).show();
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
				$btn.prop('disabled', false).removeAttr('aria-busy');
				if ($btn.data('original-label')) {
					$btn.html($btn.data('original-label'));
				}
				$result.text(base.strings.connectionError || base.strings.requestFailed || '').show();
			});
	}

	function initSections() {
		$('.wf-sn-ai-trigger').on('click', function () {
			var requestType = $(this).data('request-type');
			var $section = $(this).closest('.wf-sn-ai-section');
			runRequest(requestType, $section);
		});
	}

	function initPreviewModal() {
		var $modal = $('#wf_sn_ai_preview_modal');
		var $content = $modal.find('.wf-sn-ai-preview-data-content');
		if (!$modal.length || !$content.length) return;

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


	function initReportToggles() {
		$(document).on('click', '.wf-sn-ai-report-toggle', function () {
			var $btn = $(this);
			var $row = $btn.closest('tr.wf-sn-ai-report-row');
			var $detailRow = $row.length ? $row.next('tr.wf-sn-ai-report-detail-row') : $btn.closest('.wf-sn-ai-report-item');
			var $full = $detailRow.find('.wf-sn-ai-report-full');
			if (!$full.length) {
				$detailRow = $btn.closest('.wf-sn-ai-report-item');
				$full = $detailRow.find('.wf-sn-ai-report-full');
			}
			var expanded = $btn.attr('aria-expanded') === 'true';
			var newExpanded = !expanded;

			var reportJson = $row.length ? $row.attr('data-report-json') : $btn.closest('.wf-sn-ai-report-item').attr('data-report-json');
			if (newExpanded && $full.length && $full.children().length === 0 && reportJson) {
				try {
					var report = JSON.parse(reportJson);
					if (report && typeof report === 'object') {
						$full.html(renderReport(report));
					}
				} catch (e) {
					$full.text(base.strings.requestFailed || '');
				}
			}

			if ($detailRow.length && $detailRow.hasClass('wf-sn-ai-report-detail-row')) {
				$detailRow.prop('hidden', !newExpanded);
			} else {
				$full.prop('hidden', !newExpanded);
			}
			$btn.attr('aria-expanded', newExpanded);
		});
	}

	function initViewFullReport() {
		$(document).on('click', '.wf-sn-ai-view-full-report', function () {
			var $btn = $(this);
			var $card = $btn.closest('.wf-sn-ai-latest-report');
			var $expanded = $card.find('#wf_sn_ai_full_report_expanded');
			if (!$expanded.length) return;
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
		if (!$card.length || !$container.length) return;
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

	function initExportButton(container) {
		container = container || $(document);
		container.off('click.wfSnExport').on('click.wfSnExport', '.wf-sn-ai-export-report-btn', function () {
			var reportJson = $(this).attr('data-report-json');
			if (!reportJson) {
				var $card = $(this).closest('.wf-sn-ai-latest-report');
				if ($card.length) {
					reportJson = $card.attr('data-report-json');
				}
				if (!reportJson) {
					var $row = $(this).closest('tr').prev('tr.wf-sn-ai-report-row');
					if ($row.length) {
						reportJson = $row.attr('data-report-json');
					}
				}
			}
			if (!reportJson) return;
			try {
				var report = JSON.parse(reportJson);
				var text = reportToPlainText(report);
				if (!text) return;
				var w = window.open('', '_blank');
				if (w) {
					// Plain text only; no scripts or links so no mixed-content or external requests.
					w.document.write('<pre style="white-space:pre-wrap;font-family:inherit;padding:1em;">' + escHtml(text) + '</pre>');
					w.document.close();
					w.focus();
					w.print();
					w.close();
				}
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(text).then(function () {
						var $btn = $(this);
						var orig = $btn.text();
						$btn.text(base.strings.copied || 'Copied');
						setTimeout(function () {
							$btn.text(orig);
						}, 1500);
					}.bind(this));
				}
			} catch (e) {}
		});
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
		initPreviewModal();
		initReportToggles();
		initViewFullReport();
		renderAttackChart();
		initImprovementToggles($(document));
		initExportButton($(document));
	});
})(jQuery);
