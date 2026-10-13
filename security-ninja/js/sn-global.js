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

		// Scope to the main tab bar. Firewall Settings also uses href="#sn_cf".
		var $tabLink = $('#wf-sn-tabs a[href="#' + tabId + '"]');
		var $panel = $('#' + tabId);
		if (!$tabLink.length || !$panel.length || !$panel.hasClass('wf-sn-tab')) {
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

	// Open a main tab, or a target inside one (admin notices use in-page hashes).
	function openHashTarget(hash) {
		var id = normalizeHash(hash);
		if (!id || !$('#wf-sn-tabs').length) {
			return false;
		}

		if ($('#wf-sn-tabs a[href="#' + id + '"]').length && $('#' + id).hasClass('wf-sn-tab')) {
			activateMainTab(id);
			return true;
		}

		var $target = $('#' + id);
		var $panel = $target.closest('.wf-sn-tab');
		if (!$target.length || !$panel.length) {
			return false;
		}

		activateMainTab($panel.attr('id'));
		window.setTimeout(function() {
			var top = $target.offset().top - 32;
			$('html, body').scrollTop(top > 0 ? top : 0);
		}, 0);
		return true;
	}

	if ($('#wf-sn-tabs').length) {
		// Manual tab switching only — do not use jQuery UI tabs on #wf-sn-tabs (panels live in #sn_tabscont).
		$('#wf-sn-tabs').fadeIn('fast');

		if (window.location.hash) {
			openHashTarget(window.location.hash);
		}

		$(window).on('hashchange', function() {
			openHashTarget(window.location.hash);
		});

		$('#wf-sn-tabs').find('a').on('click', function(e) {
			e.preventDefault();
			var tabtarget = $(this).attr('id').replace('-tab', '');
			activateMainTab(tabtarget);
		});

		// Same-page links (notices, overview cards). Subtab bars keep their own handlers.
		$(document).on('click', 'a[href*="#"]', function(e) {
			if ($(this).closest('#wf-sn-tabs, #wf-sn-cf-subtabs, #wf-sn-el-subtabs').length) {
				return;
			}
			var href = $(this).attr('href') || '';
			var hashIndex = href.indexOf('#');
			if (hashIndex < 0) {
				return;
			}
			var link = document.createElement('a');
			link.href = href;
			if (link.pathname !== window.location.pathname || link.search !== window.location.search) {
				return;
			}
			if (openHashTarget(href.substring(hashIndex))) {
				e.preventDefault();
			}
		});
	}

	// Cloud Firewall subtabs — manual switching only (panels are siblings, not jQuery UI tab panels).
	function activateCfFirewallSubtab($tab) {
		if (!$tab || !$tab.length) {
			return;
		}
		$('#wf-sn-cf-subtabs .nav-tab').removeClass('nav-tab-active');
		$tab.addClass('nav-tab-active');
		$('#sn-firewall-settings-form .wf-sn-subtab').hide();
		var targetId = $tab.data('target') || $tab.attr('href');
		if (targetId) {
			$(targetId).show();
		}
	}

	if ($('#wf-sn-cf-subtabs').length) {
		$('#sn-firewall-settings-form .wf-sn-subtab').hide();
		var $cfActive = $('#wf-sn-cf-subtabs .nav-tab-active').first();
		if (!$cfActive.length) {
			$cfActive = $('#wf-sn-cf-subtabs .nav-tab').first();
		}
		activateCfFirewallSubtab($cfActive);

		$('#wf-sn-cf-subtabs').on('click', 'a.nav-tab', function(e) {
			e.preventDefault();
			activateCfFirewallSubtab($(this));
		});
	}
});
