/* globals jQuery:true, ajaxurl:true, wf_sn_cs:true */
/**
 * Security Ninja - Core Scanner
 * (c) 2014 Web factory Ltd
 * 2019 Larsik Corp
 */

jQuery( document ).ready( function( $ ) {

		var coreScannerResultsLoading = false;

		function loadCachedResults() {
			if ( window.location.hash !== '#sn_core' ) {
				return;
			}
			if ( ! $( '#wf-sn-core-scanner-response' ).length ) {
				return;
			}
			if ( coreScannerResultsLoading ) {
				return;
			}
			coreScannerResultsLoading = true;
			$( '#wf-sn-core-scanner-response' ).html( '<p class="description"><span class="spinner is-active"></span> ' + ( wf_sn_cs.strings.loading || 'Loading…' ) + '</p>' ).show();
			$.post(
				ajaxurl,
				{
					action: 'sn_core_get_cached_results',
					_ajax_nonce: wf_sn_cs.nonce
				},
				function (response) {
					coreScannerResultsLoading = false;
					var $container = $( '#wf-sn-core-scanner-response' );
					if ( ! $container.length ) {
						return;
					}
					if ( response.success && response.data ) {
						if ( response.data.no_results ) {
							$container.html( '<p class="description">' + ( response.data.message || wf_sn_cs.strings.no_scan_yet ) + '</p>' );
							return;
						}
						if ( response.data.out ) {
							$container.empty().append( response.data.out ).slideDown();
						}
						if ( response.data.last_scan ) {
							$( '#wf-sn-core-scan-details #last_scan' ).html( response.data.last_scan ).slideDown();
						}
						if ( response.data.files_checked ) {
							$( '#wf-sn-core-scan-details #files_checked' ).html( response.data.files_checked ).slideDown();
						}
						if ( response.data.wp_version ) {
							$( '#wf-sn-core-scan-details #wp_version' ).html( response.data.wp_version ).slideDown();
						}
						if ( response.data.next_scan ) {
							$( '#wf-sn-core-scan-details #next_scan' ).html( response.data.next_scan ).slideDown();
						}
					} else {
						$container.html( '<p class="description">' + ( wf_sn_cs.strings.ajax_error || 'An error occurred.' ) + '</p>' );
					}
				},
				'json'
			).fail( function () {
				coreScannerResultsLoading = false;
				$( '#wf-sn-core-scanner-response' ).html( '<p class="description">' + ( wf_sn_cs.strings.ajax_error || 'An error occurred.' ) + '</p>' );
			} );
		}

		function maybeLoadCoreScannerResults() {
			if ( window.location.hash === '#sn_core' ) {
				loadCachedResults();
			}
		}

		$( window ).on( 'hashchange', maybeLoadCoreScannerResults );
		$( document ).on( 'click', '#wf-sn-tabs a[href="#sn_core"]', maybeLoadCoreScannerResults );
		maybeLoadCoreScannerResults();

		$( 'button.sn-show-source' ).on(
			"click",
			function () {
				$( $( this ).attr( 'href' ) ).dialog(
					'option',
					{
						title: wf_sn_cs.strings.file_source + ': ' + $( this ).attr( 'data-file' ),
						file_path: $( this ).attr( 'data-file' ),
						file_hash: $( this ).attr( 'data-hash' )
					}
				).dialog( 'open' );
				return false;
			}
		);

		// Restore a file
		$( document ).on(
			'click',
			'a.sn-restore-source',
			function (e) {
				e.preventDefault();
				if ( ! confirm( wf_sn_cs.strings.confirm_restore )) {
					return false;
				}
				jQuery( this ).attr( 'disabled', 'disabled' );
				var filename  = jQuery( this ).attr( 'data-file' );
				var filehash  = jQuery( this ).attr( 'data-hash' );
				var filenonce = jQuery( this ).attr( 'data-nonce' );
				jQuery.post(
					ajaxurl,
					{
						action      : 'sn_core_restore_file_do',
						_ajax_nonce : wf_sn_cs.nonce,
						filename: filename,
						hash: filehash,
						nonce: filenonce
					},
					function (response) {

						if (response === 1) {
							jQuery( '[data-hash="' + filehash + '"]' ).closest( 'li' ).fadeOut(
								"slow",
								function () {
									jQuery( this ).remove();
									get_latest_update( true );
								}
							);
						} else {
							jQuery( '#wf-sn-core-scanner-response' ).append( '<p class="error">Error deleting file</p>' );
							jQuery( this ).removeAttr( 'disabled' );
						}
					},
					'json'
				);
			}
		);

		// Delete a file
		$( document ).on(
			'click',
			'button.sn-delete-source, a.sn-delete-source',
			function (e) {
				e.preventDefault();
				if ( ! confirm( wf_sn_cs.strings.confirm_delete )) {
					return false;
				}
				jQuery( this ).attr( 'disabled', 'disabled' );
				var filename  = jQuery( this ).attr( 'data-file' );
				var filehash  = jQuery( this ).attr( 'data-hash' );
				var filenonce = jQuery( this ).attr( 'data-nonce' );
				jQuery.post(
					ajaxurl,
					{
						action      : 'sn_core_delete_file_do',
						_ajax_nonce : wf_sn_cs.nonce,
						filename: filename,
						hash: filehash,
						nonce: filenonce
					},
					function (response) {
						if (response.success) {
							jQuery( '[data-hash="' + filehash + '"]' ).closest( 'li' ).fadeOut(
								"slow",
								function () {
									jQuery( this ).remove();
								}
							);
						} else {
							alert( wf_sn_cs.strings.error_occurred + ': ' + response );
							jQuery( this ).attr( 'disabled', '' );
						}
					},
					'json'
				);
			}
		);

		// Delete ALL files
		$( document ).on(
			'click',
			'button.sn-delete-all-files',
			function (e) {
				e.preventDefault();
				if ( ! confirm( wf_sn_cs.strings.confirm_delete_all )) {
					return false;
				}
				jQuery( this ).attr( 'disabled', 'disabled' );

				jQuery.ajax(
					{
						url: ajaxurl,
						type: 'POST',
						data: {
							'action'      : 'sn_core_delete_all_unknowns',
							'_ajax_nonce' : wf_sn_cs.delete_all_nonce
						},
						success: function () {
							window.location.reload();
						},
						error: function () {
							alert( wf_sn_cs.strings.ajax_error );
						}
					}
				);
			}
		);

		function get_latest_update(forceupdate) {
			jQuery( '#wf-sn-core-scanner-response' ).show();
			jQuery( '#wf-sn-core-scanner-response #sn-cs-results' ).slideUp();
			jQuery( '#wf-sn-core-scanner-response .spinner' ).addClass( 'is-active' );
			var data = {
				action: 'sn_core_run_scan',
				_ajax_nonce: wf_sn_cs.nonce
			};
			if (forceupdate) {
				data.doupdate = true;
			}
			$.post(
				ajaxurl,
				data,
				function (response) {
					jQuery( '#wf-sn-core-scan-details .spinner' ).removeClass( 'is-active' );
					if (response.data.out) {
						jQuery( '#wf-sn-core-scanner-response' ).replaceWith( response.data.out ).slideDown();

						jQuery( '#wf-sn-core-scan-details #files_checked' ).html( response.data.files_checked ).slideDown();
						jQuery( '#wf-sn-core-scan-details #wp_version' ).html( response.data.wp_version ).slideDown();

					}
					if (response.data.last_scan) {
						jQuery( '#wf-sn-core-scan-details #last_scan' ).html( response.data.last_scan ).slideDown();
					}
				},
				'json'
			);
		}

		// Run AJAX core scan and display returned results
		$( document ).on(
			'click',
			'#sn-run-core-scan',
			function (e) {
				e.preventDefault();
				jQuery( '#wf-sn-core-scanner-response .spinner' ).addClass( 'is-active' );
				jQuery.post(
					ajaxurl,
					{
						action: 'sn_core_run_scan',
						_ajax_nonce: wf_sn_cs.nonce,
						datatype: 'json',
						doupdate: true
					},
					function (response) {
						jQuery( '#wf-sn-core-scanner-response .spinner' ).removeClass( 'is-active' );
						if (response.data.out) {
							jQuery( '#wf-sn-core-scanner-response' ).append( response.data.out ).slideDown();
						}
						if (response.data.last_scan) {
							jQuery( '#wf-sn-core-scanner-response #last_scan' ).html( response.data.last_scan ).slideDown();

						}
						if (response.data.files_checked) {
							jQuery( '#wf-sn-core-scanner-response #files_checked' ).html( response.data.files_checked ).slideDown();
						}
						if (response.data.wp_version) {
							jQuery( '#wf-sn-core-scanner-response #wp_version' ).html( response.data.wp_version ).slideDown();
						}
						if (response.data.next_scan) {
							jQuery( '#wf-sn-core-scanner-response #next_scan' ).html( response.data.next_scan ).slideDown();
						}
						location.reload();
					}
				);
			}
		);
} );