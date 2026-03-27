/* globals jQuery:true, ajaxurl:true, wf_sn:true */
/* Functions are loaded on Security Ninja WP admin pages */

jQuery(document).ready(function($) {
	// Close welcome notice
	$(document).on('click', '.secnin-welcome-notice .closeme', function() {
		$('.secnin-welcome-notice').slideUp();
	});

	// Only run tab logic on Security Ninja pages
	if (!$('#wf-sn-tabs').length && !$('#wf-sn-cf-subtabs').length) {
		return;
	}

	// Initialize Cloud Firewall subtabs if present
	if ($('#wf-sn-cf-subtabs').length) {
		$('#wf-sn-cf-subtabs').tabs({
			active: 0,
			activate: function(event, ui) {
				$('#wf-sn-cf-subtabs .nav-tab').removeClass('nav-tab-active');
				$(ui.newTab).addClass('nav-tab-active');
			}
		});

		// Hide all subtabs except the first one initially
		$('.wf-sn-subtab').not(':first').hide();
		$('#wf-sn-cf-subtabs .nav-tab').not(':first').removeClass('nav-tab-active');
	}

	// Helper to normalize hash values
	function normalizeHash(hash) {
		if (!hash) {
			return '';
		}
		// First remove all hash symbols
		hash = hash.replace(/#/g, '');
		// Strip query string in fragment (e.g. #sn_whitelabel&require_license=false -> sn_whitelabel)
		hash = hash.split('&')[0];
		// Then remove any leading/trailing slashes
		hash = hash.replace(/^\/+|\/+$/g, '');
		return hash;
	}

	// Handle initial hash to activate correct main tab
	if ($('#wf-sn-tabs').length) {
		var hash = window.location.hash;
		if (hash) {
			var scrollPos = $(window).scrollTop();
			$('#wf-sn-tabs').find('a').removeClass('nav-tab-active');
			$('.wf-sn-tab').removeClass('active');

			hash = normalizeHash(hash) || 'sn_tests';

			$('a[href="#' + hash + '"]').addClass('nav-tab-active').removeClass('hidden');
			$('#' + hash).addClass('active');

			$(window).scrollTop(scrollPos);
			$('[name="_wp_http_referer"]').val(window.location);
		}

		// Initialize jQuery UI tabs for main tabs (hash handling is in click handler)
		$('#wf-sn-tabs').tabs({
			activate: function(event, ui) {
				var scrollTop = $(window).scrollTop();
				window.location.hash = normalizeHash(ui.newPanel.attr('id'));
				$(window).scrollTop(scrollTop);
			}
		}).fadeIn('fast');

		// Fallback generic tabs container if present
		if ($('#tabs').length) {
			$('#tabs').tabs({
				activate: function() {
					$.cookie('sn_tabs_selected', $('#tabs').tabs('option', 'active'));
				},
				active: $('#tabs').tabs({ active: $.cookie('sn_tabs_selected') })
			});
		}

		// Main tab click handling
		$('#wf-sn-tabs').find('a').on('click', function(e) {
			e.preventDefault();
			$('#wf-sn-tabs').find('a').removeClass('nav-tab-active');
			$('.wf-sn-tab').removeClass('active');

			var tabtarget = $(this).attr('id').replace('-tab', '');
			var $panel = $('#' + tabtarget);

			$panel.addClass('active');
			$(this).addClass('nav-tab-active');

			if ($panel.hasClass('nosave')) {
				$('#submit').hide();
			} else {
				$('#submit').show();
			}

			var scrollPos = $(window).scrollTop();
			window.location.hash = normalizeHash(tabtarget);
			$(window).scrollTop(scrollPos);
			$('[name="_wp_http_referer"]').val(window.location);
		});

		// Handle internal links within overview tab content that point to other tabs
		$(document).on('click', '#sn_overview a[href^="#"]', function(e) {
			e.preventDefault();
			var targetId = $(this).attr('href').substring(1);
			targetId = normalizeHash(targetId);

			var $tabLink = $('a[href="#' + targetId + '"]');
			if ($tabLink.length) {
				$('#wf-sn-tabs').find('a').removeClass('nav-tab-active');
				$('.wf-sn-tab').removeClass('active');

				$tabLink.addClass('nav-tab-active');
				$('#' + targetId).addClass('active');

				var scrollPos = $(window).scrollTop();
				window.location.hash = targetId;
				$(window).scrollTop(scrollPos);
				$('[name="_wp_http_referer"]').val(window.location);
			}
		});
	}
});

