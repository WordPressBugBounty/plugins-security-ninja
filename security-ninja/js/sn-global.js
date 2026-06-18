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

	// Helper to normalize hash values
	function normalizeHash(hash) {
		if (!hash) {
			return '';
		}
		hash = hash.replace(/#/g, '');
		hash = hash.split('&')[0];
		hash = hash.replace(/^\/+|\/+$/g, '');
		return hash;
	}

	function activateMainTab(tabId) {
		tabId = normalizeHash(tabId);
		if (!tabId) {
			return;
		}

		var $tabLink = $('a[href="#' + tabId + '"]');
		var $panel = $('#' + tabId);
		if (!$tabLink.length || !$panel.length) {
			return;
		}

		$('#wf-sn-tabs').find('a').removeClass('nav-tab-active');
		$('.wf-sn-tab').removeClass('active');

		$panel.addClass('active');
		$tabLink.addClass('nav-tab-active');

		if ($panel.hasClass('nosave')) {
			$('#submit').hide();
		} else {
			$('#submit').show();
		}

		var scrollPos = $(window).scrollTop();
		window.location.hash = tabId;
		$(window).scrollTop(scrollPos);
		$('[name="_wp_http_referer"]').val(window.location);
	}

	if ($('#wf-sn-tabs').length) {
		// Manual tab switching only — do not use jQuery UI tabs on #wf-sn-tabs (panels live in #sn_tabscont).
		$('#wf-sn-tabs').fadeIn('fast');

		var hash = window.location.hash;
		if (hash) {
			activateMainTab(hash);
		}

		$('#wf-sn-tabs').find('a').on('click', function(e) {
			e.preventDefault();
			var tabtarget = $(this).attr('id').replace('-tab', '');
			activateMainTab(tabtarget);
		});

		$(document).on('click', '#sn_overview a[href^="#"]', function(e) {
			e.preventDefault();
			activateMainTab($(this).attr('href').substring(1));
		});
	}

	// Cloud Firewall subtabs — optional jQuery UI widget; never block main tabs if this fails.
	if ($('#wf-sn-cf-subtabs').length && $.fn.tabs) {
		try {
			$('#wf-sn-cf-subtabs').tabs({
				active: 0,
				activate: function(event, ui) {
					$('#wf-sn-cf-subtabs .nav-tab').removeClass('nav-tab-active');
					$(ui.newTab).addClass('nav-tab-active');
				}
			});

			$('.wf-sn-subtab').not(':first').hide();
			$('#wf-sn-cf-subtabs .nav-tab').not(':first').removeClass('nav-tab-active');
		} catch (err) {
			// Subtab widget is optional; main Security Ninja tabs must keep working.
		}
	}
});
