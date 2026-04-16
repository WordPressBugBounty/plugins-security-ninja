/* globals jQuery:true, ajaxurl:true, wf_sn:true */
/*
* Security Ninja PRO
* Main backend JS
* (c) WP Security Ninja, 2012 - 2026
*/

function sn_block_ui(content_el) {
	jQuery('html.wp-toolbar').addClass('sn-overlay-active');
	jQuery('#wpadminbar').addClass('sn-overlay-active');
	jQuery('#sn_overlay .wf-sn-overlay-outer').css('height', (jQuery(window).height() - 200) + 'px');
	jQuery('#sn_overlay').show();
	
	if (content_el) {
		jQuery(content_el, '#sn_overlay').show();
	}
}



function sn_unblock_ui(content_el) {
	jQuery('html.wp-toolbar').removeClass('sn-overlay-active');
	jQuery('#wpadminbar').removeClass('sn-overlay-active');
	jQuery('#sn_overlay').hide();
	
	if (content_el) {
		jQuery(content_el, '#sn_overlay').hide();
	}
}








jQuery(document).ready(function () {
	var snTestDescriptions = null;
	var snTestDescriptionsPromise = null;

	/**
	 * Load security test long descriptions once (cached). Uses same nonce as run tests.
	 * @returns {jQuery.Promise}
	 */
	function ensureTestDescriptions() {
		if (snTestDescriptions) {
			return jQuery.Deferred().resolve(snTestDescriptions).promise();
		}
		if (snTestDescriptionsPromise) {
			return snTestDescriptionsPromise;
		}
		snTestDescriptionsPromise = jQuery.ajax({
			type: 'POST',
			url: ajaxurl,
			data: {
				action: 'sn_get_test_descriptions',
				_ajax_nonce: wf_sn.nonce_run_tests
			},
			dataType: 'json'
		}).then(function (response) {
			snTestDescriptionsPromise = null;
			if (response && response.success && response.data && response.data.tests) {
				snTestDescriptions = response.data.tests;
			} else {
				snTestDescriptions = {};
			}
			return snTestDescriptions;
		}, function () {
			snTestDescriptionsPromise = null;
			snTestDescriptions = {};
			return snTestDescriptions;
		});
		return snTestDescriptionsPromise;
	}

	if (jQuery('#security-ninja').length) {
		ensureTestDescriptions();
	}

	// Signing up for the newsletter
	jQuery('.ml-block-form').on('submit', function(e) {
		e.preventDefault();

		jQuery.ajax({
			type: 'POST',
			url: jQuery(this).attr('action'),
			data: jQuery(this).serialize(),
			success: function(response) {
				if (response.success) {
					jQuery.post(ajaxurl, {
						'_ajax_nonce': wf_sn.nonce_dismiss_pointer,
						'action': 'wf_sn_dismiss_review',
						'signed_up': true
					});

					jQuery('.ml-block-form').replaceWith('<p>Thank you for signing up.</p>');
				} else {
					jQuery('.ml-block-form').after('<p>There was a problem signing you up to the newsletter. Please try again.</p>');
				}
			},
			error: function() {
				jQuery('.ml-block-form').after('<p>There was a problem signing you up to the newsletter. Please try again.</p>');
			}
		});
	});




	// Iterate and expand all details on Tests page
	jQuery(document).on('click', '.secnin_expand_all_details', function (e) {
		e.preventDefault();
		jQuery("#security-ninja .sn-details a").each(function () {
			jQuery(this).trigger('click');
		});		
	});

	// Reset Secret Access URL functionality
	jQuery(document).on('submit', '#sn-reset-secret-url-form', function (e) {
		e.preventDefault();
		
		var $form = jQuery(this);
		var $button = $form.find('#secnin-reset-secret-url');
		
		// Confirm the action
		if (!confirm(wf_sn.strings.reset_secret_url_confirm)) {
			return;
		}
		
		// Disable button and show loading
		$button.prop('disabled', true).val(wf_sn.strings.resetting);
		
		// Make AJAX request
		jQuery.ajax({
			type: 'POST',
			url: ajaxurl,
			data: {
				action: 'sn_reset_secret_url',
				_wpnonce: wf_sn.nonce_install_routines
			},
			success: function(response) {
				if (response.success) {
					// Reload page to show WordPress notice
					window.location.reload();
				} else {
					alert('Error: ' + (response.data ? response.data.message : wf_sn.strings.error_unknown));
					$button.val(wf_sn.strings.reset_button_text).prop('disabled', false);
				}
			},
			error: function() {
				alert('Error: ' + wf_sn.strings.error_failed);
				$button.val(wf_sn.strings.reset_button_text).prop('disabled', false);
			}
		});
	});





	// RUN SELECTED TESTS
	jQuery(document).on('click', '#run-selected-tests', function (e) {
		e.preventDefault();
		jQuery('#run-selected-tests').attr('disabled', true);
		jQuery('.runtestsbn.spinner').addClass('is-active');
		

		// finds all selected tests, stores in array and sets visual testing styles
		let checkedtests = [];
		let thistestid = '';
		jQuery("input[name='sntest[]']").each(function () {
			if (this.checked) {
				thistestid = jQuery(this).val();
				jQuery('.test_' + thistestid).addClass('testing');
				jQuery('.test_' + thistestid + ' .spinner').addClass('is-active');
				jQuery('.test_' + thistestid + ' .sn-result-details').hide();
				checkedtests.push(thistestid);
			}
		});
		// Lets start with the first test
		do_test(0, checkedtests, self);
		
		jQuery('#run-selected-tests').attr('disabled', false);
		jQuery('.runtestsbn.spinner').removeClass('is-active');

	});
	
	
	// QUICK FILTER - ALL
	jQuery(document).on('click', '#sn-quickselect-all', function (e) {
		e.preventDefault();
		jQuery('#security-ninja :checkbox').prop("checked", true);
		// Trigger selected
		jQuery('#security-ninja tr.test').fadeIn('fast');
	});
	
	
	// QUICK FILTER - FAILED
	jQuery(document).on('click', '#sn-quickselect-failed', function (e) {
		e.preventDefault();
		// Hide all
		jQuery('#security-ninja :checkbox').prop("checked", false);
		// Trigger selected
		jQuery('#security-ninja .wf-sn-test-row-status-0 :checkbox').prop("checked", true);
		// hide the rest
		jQuery('#security-ninja .wf-sn-test-row-status-null').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-10').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-5').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-0').fadeIn('fast');
	});
	
	
	// QUICK FILTER - WARNING
	jQuery(document).on('click', '#sn-quickselect-warning', function (e) {
		e.preventDefault();
		// Hide all
		jQuery('#security-ninja :checkbox').prop("checked", false);
		// Trigger selected
		jQuery('#security-ninja .wf-sn-test-row-status-5 :checkbox').prop("checked", true);
		// hide the rest
		jQuery('#security-ninja .wf-sn-test-row-status-null').fadeOut('fast');
		
		jQuery('#security-ninja .wf-sn-test-row-status-10').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-0').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-5').fadeIn('fast');
	});
	
	
	// QUICK FILTER - OK
	jQuery(document).on('click', '#sn-quickselect-okay', function (e) {
		e.preventDefault();
		// Hide all
		jQuery('#security-ninja :checkbox').prop("checked", false);
		// Trigger selected
		jQuery('#security-ninja .wf-sn-test-row-status-10 :checkbox').prop("checked", true);
		// hide the rest
		jQuery('#security-ninja .wf-sn-test-row-status-0').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-5').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-10').fadeIn('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-null').fadeOut('fast');
		
	});
	
	
	// QUICK FILTER - UNTESTED
	jQuery(document).on('click', '#sn-quickselect-untested', function (e) {
		e.preventDefault();
		// Hide all
		jQuery('#security-ninja :checkbox').prop("checked", false);
		// Trigger selected
		jQuery('#security-ninja .wf-sn-test-row-status-null :checkbox').prop("checked", true);
		// hide the rest
		jQuery('#security-ninja .wf-sn-test-row-status-0').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-5').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-10').fadeOut('fast');
		jQuery('#security-ninja .wf-sn-test-row-status-null').fadeIn('fast');
		
	});
	
	// stepid = integer
	// data = array of tests
	function do_test(stepid, data, self) {
		
		let testid = data[stepid];
		
		// Add testing class and spinner animation
		jQuery('.test_' + testid).addClass('testing');
		jQuery('.test_' + testid + ' .spinner').addClass('is-active');
		jQuery('.test_' + testid + ' .sn-result-details').hide();
		
		// Add a small delay to make the testing animation visible
		setTimeout(function() {
			jQuery.ajax({
				type: 'POST',
				url: ajaxurl,
				data: {
					'_ajax_nonce': wf_sn.nonce_run_tests,
					'testarr': data,
					'action': 'sn_run_single_test',
					'stepid': stepid
				},
				dataType: "json",
				success: function (response) {
					
					// Remove testing state
					jQuery('.test_' + testid + ' .spinner').removeClass('is-active');
					jQuery('.test_' + testid).removeClass('testing');
					
					// Update the status icon in the second column
					if (response.data.status_icon) {
						jQuery('.test_' + testid + ' td:nth-child(2)').html(response.data.status_icon);
					}
					
					var outputmsg = response.data.msg;
					
					if (response.data.details) {
						outputmsg = outputmsg + ' ' + response.data.details;
					}
					
					jQuery('.test_' + testid + ' .sn-result-details').replaceWith('<span class="sn-result-details">' + outputmsg + '</span>').fadeIn('slow');
					
					// Remove old status classes and add new one
					jQuery('.test_' + testid).removeClass(
						'wf-sn-test-row-status-0').removeClass('wf-sn-test-row-status-5').removeClass('wf-sn-test-row-status-10').removeClass('wf-sn-test-row-status-null').addClass('wf-sn-test-row-status-' + response.data.status);
					
					// Enhanced completion animation for ALL tests (not just untested ones)
					jQuery('.test_' + testid).addClass('test-completed');
					setTimeout(function() {
						jQuery('.test_' + testid).removeClass('test-completed');
					}, 4000); // Increased duration for better visibility
					
					// Add persistent highlight for tests that changed status
					if (response.data.status_changed) {
						if (response.data.change_direction === 'improved') {
							jQuery('.test_' + testid).addClass('status-improved');
						} else if (response.data.change_direction === 'declined') {
							jQuery('.test_' + testid).addClass('status-declined');
						} else {
							jQuery('.test_' + testid).addClass('status-changed');
						}
						// Keep the highlight until page reload
					}
						
					jQuery('.test_' + testid + ' input[type="checkbox"]').prop('checked', false);
					
					// Enhanced statistics update with animations
					if (response.data.scores) {
						updateStatisticsWithAnimation(response.data.scores);
					}
					
					if ('-1' == response.data.nexttest) {
						// Testing completed
						// All tests completed
					} else {
						if (parseInt(response.data.nexttest) > 0) {
							// Continue with next test
							setTimeout(function() {
								do_test(parseInt(response.data.nexttest), data, self);
							}, 500); // Small delay between tests for better UX
						}
					}
					
				}
			}).fail(function (response) {
				// Error handling - remove testing state on error
				jQuery('.test_' + testid + ' .spinner').removeClass('is-active');
				jQuery('.test_' + testid).removeClass('testing');
				// Test failed silently
			});
		}, 200); // Small delay to show testing animation
	}
	
	// Enhanced statistics update function with animations
	function updateStatisticsWithAnimation(scores) {
		if (!scores || !scores.output) return;
		
		// Create temporary container to parse the new HTML
		var tempDiv = jQuery('<div>').html(scores.output);
		
		// Update each counter with animation
		jQuery('#counters span.edge').each(function() {
			var $counter = jQuery(this);
			var $val = $counter.find('.val');
			var counterType = '';
			
			// Determine counter type
			if ($counter.hasClass('good')) counterType = 'good';
			else if ($counter.hasClass('warning')) counterType = 'warning';
			else if ($counter.hasClass('bad')) counterType = 'bad';
			else if ($counter.hasClass('score')) counterType = 'score';
			
			// Find corresponding new value
			var newCounter = tempDiv.find('span.edge.' + counterType);
			if (newCounter.length) {
				var newVal = newCounter.find('.val').text();
				var currentVal = $val.text();
				
				// Only animate if value changed
				if (newVal !== currentVal) {
					// Add animation classes
					$counter.addClass('updating');
					$val.addClass('updating');
					
					// Update the value
					$val.text(newVal);
					
					// Remove animation classes after animation completes
					setTimeout(function() {
						$counter.removeClass('updating');
						$val.removeClass('updating');
					}, 500);
				}
			}
		});
		
		// Also update the entire testscores container as fallback
		if (scores.output) {
			jQuery('#testscores').html(scores.output);
		}
	}
		
		
		jQuery('.wfsn-dismiss-review-notice, .wfsn-review-notice .notice-dismiss').on('click', function () {
			if (!jQuery(this).hasClass('wfsn-reviewlink')) {
				event.preventDefault();
			}
			jQuery.post(ajaxurl, {
				'_ajax_nonce': wf_sn.nonce_dismiss_pointer,
				'action': 'wf_sn_dismiss_review'
			});
			jQuery('.wfsn-review-notice').slideUp().remove();
		});
		
		
		// Asks before importing settings
		jQuery(document).on('click', '#wf-import-settings-button', function () {
			if (!confirm('Are you sure you want to import and overwrite the current settings?')) { //i8n
				return false;
			}
			else {
				return true;
			}
		});
		
		// abort scan by refreshing
		jQuery('#abort-scan').on('click', function (e) {
			e.preventDefault();
			window.location.reload();
		}); // abort scan
		
		
		
		// show test details/help/fix dialog
		
		jQuery(document).on('click', '#sn_tests .sn-details a', function (e) {
			e.preventDefault();

			var $link = jQuery(this);
			$link.remove();
			var test_id = $link.data('test-id');
			var test_status = $link.data('test-status');

			jQuery(document).trigger('sn_test_details_dialog_open', [ test_id, test_status ] );

			var target = '.tdesc-test-id-' + test_id;

			jQuery('.' + test_id + '.testtimedetails').prepend('<div class="spinner is-active"></div>');

			jQuery.ajax({
				type: 'POST',
				url: ajaxurl,
				data: {
					'_ajax_nonce': wf_sn.nonce_run_tests,
					'action': 'sn_get_single_test_details',
					'testid': test_id
				},
				dataType: 'json',
				success: function (response) {
					jQuery('.' + test_id + '.testtimedetails .spinner').remove();
					if (response.success) {
						if (response.data.runtime) {
							jQuery('.' + test_id + '.testtimedetails .runtime').html('Runtime: ' + response.data.runtime + ' ' + 'sec');
						}

						if (response.data.timestamp) {
							jQuery('.' + test_id + '.testtimedetails .lasttest').html('Last test: ' + response.data.timestamp);
						}

						if (response.data.timestamp) {
							jQuery('.' + test_id + '.testtimedetails .score').html('Score: ' + response.data.score);
						}
						if (response.data.timestamp) {
							jQuery('.' + test_id + '.testtimedetails .status').html('Status: ' + response.data.status);
						}

						jQuery('.' + test_id + '.testtimedetails').show();
					}
				},
				error: function () {
					jQuery('.' + test_id + '.testtimedetails .spinner').remove();
				}
			});

			ensureTestDescriptions().then(function (tests) {
				var entry = tests && tests[ test_id ];
				var name = entry && entry.title ? entry.title : '';
				var descHtml = entry && entry.html ? entry.html : '';
				if (!name && !descHtml) {
					name = 'Unknown test ID'; // @i8n
					descHtml = '<p>' + jQuery('<div/>').text('Help is not available for this test. Make sure you have the latest version installed.').html() + '</p>'; // @i8n
				}
				var parts = [];
				parts.push('<span class="ui-helper-hidden-accessible"><input type="text"></span><span class="spinner is-active"></span>');
				parts.push('<h3 class="wf-sn-test-help-title">' + jQuery('<div/>').text(name).html() + '</h3>');
				parts.push('<div class="test_description">' + descHtml + '</div>');
				parts.push('<div id="auto-fixer-content-cont"><hr><h3>Auto Fixer</h3><div id="auto-fixer-content"></div></div>'); // @i8n
				jQuery(target).slideUp().html(parts.join('')).slideDown('slow');
			});

			return false;
		}); // show test details (inline expand)
		
		
		
	});