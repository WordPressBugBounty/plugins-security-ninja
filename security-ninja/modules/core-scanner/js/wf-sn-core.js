/* globals jQuery:true, ajaxurl:true, wf_sn_cs:true */
/**
 * Security Ninja - Core Scanner
 */

jQuery( document ).ready( function( $ ) {

	var coreScannerResultsLoading = false;

	function formatStatCount( n ) {
		return parseInt( n, 10 ).toLocaleString();
	}

	function updateTabBadge( count ) {
		var $tab = $( '#wf-sn-tabs a[href="#sn_core"]' );
		if ( ! $tab.length ) {
			return;
		}
		$tab.find( '.warn-count' ).remove();
		if ( count && parseInt( count, 10 ) > 0 ) {
			$tab.append( '<span class="warn-count">' + parseInt( count, 10 ) + '</span>' );
		}
	}

	function toggleReportLink( reportUrl ) {
		var $wrap = $( '#sn-cs-report-link-wrap' );
		var $link = $( '#sn-cs-report-link' );
		if ( ! $wrap.length || ! $link.length ) {
			return;
		}
		if ( reportUrl ) {
			$wrap.removeClass( 'is-hidden' ).addClass( 'is-visible' );
			$link.attr( 'href', reportUrl ).removeAttr( 'aria-disabled' );
		} else {
			$wrap.removeClass( 'is-visible' ).addClass( 'is-hidden' );
			$link.attr( 'href', '#' ).attr( 'aria-disabled', 'true' );
		}
	}

	function patchSummaryStats( stats ) {
		if ( ! stats ) {
			return;
		}
		$.each( stats, function( key, value ) {
			$( '.sn-cs-stat[data-stat="' + key + '"] .sn-cs-stat-count' ).text( formatStatCount( value ) );
		} );
	}

	function patchBanner( data ) {
		var $banner = $( '.sn-cs-banner' );
		if ( ! $banner.length || ! data.banner_text ) {
			return;
		}
		$banner.removeClass( 'sn-cs-banner-clean sn-cs-banner-issues' ).addClass( data.banner_class || 'sn-cs-banner-clean' );
		$banner.find( 'strong' ).text( data.banner_text );
	}

	function patchFindingsWrap( wrapClass ) {
		var $wrap = $( '#sn-cs-results' );
		if ( ! $wrap.length || ! wrapClass ) {
			return;
		}
		$wrap.attr( 'class', wrapClass );
	}

	function pruneEmptyGroupHeaders( $tbody ) {
		$tbody.find( 'tr.sn-cs-group-header' ).each( function() {
			var $header = $( this );
			var hasFiles = false;
			$header.nextUntil( 'tr.sn-cs-group-header' ).each( function() {
				if ( $( this ).is( '[data-file-short]' ) ) {
					hasFiles = true;
					return false;
				}
			} );
			if ( ! hasFiles ) {
				$header.remove();
			}
		} );
	}

	function pruneEmptySections() {
		$( '#sn-cs-results .sn-cs-section' ).each( function() {
			var $section = $( this );
			if ( $section.find( 'tr[data-file-short]' ).length === 0 ) {
				$section.remove();
			}
		} );

		var $results = $( '#sn-cs-results' );
		if ( $results.length && $results.find( '.sn-cs-section' ).length === 0 ) {
			$results.remove();
		}
	}

	function showNoProblemsFound() {
		var $container = $( '#wf-sn-core-scanner-response' );
		if ( ! $container.length || $container.find( '.noerrorsfound' ).length ) {
			return;
		}
		$container.append(
			'<div class="sncard noerrorsfound">' + wf_sn_cs.strings.no_problems_found + '</div>'
		);
	}

	function applyRowActionResponse( data ) {
		if ( ! data ) {
			return;
		}

		$( '.sn-cs-findings-table tr.sn-cs-row-processing' ).removeClass( 'sn-cs-row-processing' );

		if ( data.file_shorts && data.file_shorts.length ) {
			$.each( data.file_shorts, function( i, fileShort ) {
				$( 'tr[data-file-short]' ).filter( function() {
					return $( this ).attr( 'data-file-short' ) === fileShort;
				} ).remove();
			} );
		}

		$( '.sn-cs-findings-table tbody' ).each( function() {
			pruneEmptyGroupHeaders( $( this ) );
		} );

		pruneEmptySections();

		if ( data.stats ) {
			patchSummaryStats( data.stats );
		}

		if ( typeof data.stats !== 'undefined' && data.stats.unknown !== undefined ) {
			$( '.sn-cs-section[data-section="unknown"] h4' ).each( function() {
				var label = $( this ).text().replace( /\s*\([\d,]+\)\s*$/, '' );
				$( this ).text( label + ' (' + formatStatCount( data.stats.unknown ) + ')' );
			} );
		}

		patchBanner( data );
		patchFindingsWrap( data.findings_wrap_class );

		if ( ! data.has_issues ) {
			showNoProblemsFound();
		}

		toggleReportLink( data.report_url || '' );

		if ( typeof data.issue_count !== 'undefined' ) {
			updateTabBadge( data.issue_count );
			$( '#sn-run-core-scan' ).attr( 'data-issue-count', data.issue_count );
		}

		if ( data.ignored_html !== undefined ) {
			var $ignored = $( '#sn-cs-ignored-files' );
			if ( data.ignored_html === '' ) {
				$ignored.remove();
			} else if ( $ignored.length ) {
				$ignored.replaceWith( data.ignored_html );
			} else {
				var $resultsWrap = $( '#sn-cs-results' );
				if ( $resultsWrap.length ) {
					$resultsWrap.after( data.ignored_html );
				} else {
					$( '#wf-sn-core-scanner-response' ).append( data.ignored_html );
				}
			}
		}

		if ( data.unknown_html !== undefined ) {
			var $unknown = $( '.sn-cs-section[data-section="unknown"]' );
			if ( data.unknown_html === '' ) {
				$unknown.remove();
				pruneEmptySections();
			} else if ( $unknown.length ) {
				$unknown.replaceWith( data.unknown_html );
			} else {
				var $resultsInner = $( '#sn-cs-results' );
				if ( $resultsInner.length ) {
					$resultsInner.prepend( data.unknown_html );
				}
			}
		}
	}

	function applyCoreScanResponse( data ) {
		if ( ! data ) {
			return;
		}

		var $container = $( '#wf-sn-core-scanner-response' );
		if ( ! $container.length ) {
			return;
		}

		if ( data.no_results ) {
			$container.removeAttr( 'data-sn-cs-loaded' ).html( '<p class="description">' + ( data.message || wf_sn_cs.strings.no_scan_yet ) + '</p>' );
			toggleReportLink( '' );
			updateTabBadge( 0 );
			return;
		}

		if ( data.out ) {
			$( '#sn-cs-scan-meta-static' ).remove();
			$container.attr( 'data-sn-cs-loaded', '1' ).html( data.out );
		} else if ( data.last_scan || data.files_checked ) {
			var scanParts = [];
			if ( data.last_scan ) {
				scanParts.push( data.last_scan );
			}
			if ( data.files_checked ) {
				scanParts.push( data.files_checked );
			}
			if ( scanParts.length ) {
				var $scanDetails = $( '#sn-cs-scan-details' );
				if ( $scanDetails.length ) {
					$scanDetails.text( scanParts.join( ' · ' ) );
				}
			}
		}

		if ( data.wp_version ) {
			$( '#wp_version' ).html( data.wp_version );
		}
		if ( data.next_scan ) {
			$( '#next_scan' ).html( data.next_scan );
		}

		toggleReportLink( data.report_url || '' );

		if ( typeof data.issue_count !== 'undefined' ) {
			updateTabBadge( data.issue_count );
			$( '#sn-run-core-scan' ).attr( 'data-issue-count', data.issue_count );
		}
	}

	function loadCachedResults( force ) {
		if ( window.location.hash !== '#sn_core' ) {
			return;
		}
		if ( ! $( '#wf-sn-core-scanner-response' ).length ) {
			return;
		}
		if ( coreScannerResultsLoading ) {
			return;
		}
		if ( ! force && $( '#wf-sn-core-scanner-response' ).attr( 'data-sn-cs-loaded' ) === '1' ) {
			return;
		}

		coreScannerResultsLoading = true;
		$( '.sn-cs-scan-spinner' ).addClass( 'is-active' );

		$.post(
			ajaxurl,
			{
				action: 'sn_core_get_cached_results',
				_ajax_nonce: wf_sn_cs.nonce
			},
			function( response ) {
				coreScannerResultsLoading = false;
				$( '.sn-cs-scan-spinner' ).removeClass( 'is-active' );
				if ( response.success && response.data ) {
					if ( response.data.no_results ) {
						applyCoreScanResponse( response.data );
						return;
					}
					applyCoreScanResponse( response.data );
				} else {
					$( '#wf-sn-core-scanner-response' ).html( '<p class="description">' + ( wf_sn_cs.strings.ajax_error || 'An error occurred.' ) + '</p>' );
				}
			},
			'json'
		).fail( function() {
			coreScannerResultsLoading = false;
			$( '.sn-cs-scan-spinner' ).removeClass( 'is-active' );
			$( '#wf-sn-core-scanner-response' ).html( '<p class="description">' + ( wf_sn_cs.strings.ajax_error || 'An error occurred.' ) + '</p>' );
		} );
	}

	function runCoreScan( $button ) {
		var $btn = $button || $( '#sn-run-core-scan' );
		$btn.prop( 'disabled', true );
		$( '.sn-cs-scan-spinner' ).addClass( 'is-active' );

		$.post(
			ajaxurl,
			{
				action: 'sn_core_run_scan',
				_ajax_nonce: wf_sn_cs.nonce,
				doupdate: true
			},
			function( response ) {
				$btn.prop( 'disabled', false );
				$( '.sn-cs-scan-spinner' ).removeClass( 'is-active' );
				if ( response.success && response.data ) {
					applyCoreScanResponse( response.data );
				} else {
					var msg = ( response.data && response.data.message ) ? response.data.message : wf_sn_cs.strings.ajax_error;
					SnDialog.alert({ message: msg });
				}
			},
			'json'
		).fail( function() {
			$btn.prop( 'disabled', false );
			$( '.sn-cs-scan-spinner' ).removeClass( 'is-active' );
			SnDialog.alert({ message: wf_sn_cs.strings.ajax_error });
		} );
	}

	$( window ).on( 'hashchange', function() {
		if ( window.location.hash === '#sn_core' ) {
			loadCachedResults( false );
		}
	} );
	$( document ).on( 'click', '#wf-sn-tabs a[href="#sn_core"]', function() {
		loadCachedResults( false );
	} );

	$( document ).on( 'click', '#sn-cs-report-link', function( e ) {
		if ( $( this ).attr( 'aria-disabled' ) === 'true' ) {
			e.preventDefault();
		}
	} );

	$( document ).on( 'click', '#sn-run-core-scan', function( e ) {
		e.preventDefault();
		runCoreScan( $( this ) );
	} );

	$( document ).on( 'click', '.sn-cs-view-file', function( e ) {
		e.preventDefault();
		var href = $( this ).data( 'href' );
		if ( href ) {
			window.open( href, '_blank', 'noopener,noreferrer' );
		}
	} );

	$( document ).on( 'click', '.sn-restore-source', function( e ) {
		e.preventDefault();
		var $el = $( this );
		SnDialog.confirm({
			message: wf_sn_cs.strings.confirm_restore
		}).then(function( ok ) {
			if ( ! ok ) {
				return;
			}
			var $row = $el.closest( 'tr' );
			$row.addClass( 'sn-cs-row-processing' );
			$.post(
				ajaxurl,
				{
					action: 'sn_core_restore_file_do',
					_ajax_nonce: wf_sn_cs.nonce,
					filename: $el.attr( 'data-file' ),
					hash: $el.attr( 'data-hash' ),
					nonce: $el.attr( 'data-nonce' )
				},
				function( response ) {
					if ( response.success ) {
						applyRowActionResponse( response.data );
					} else {
						SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
						$row.removeClass( 'sn-cs-row-processing' );
					}
				},
				'json'
			).fail( function() {
				SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
				$row.removeClass( 'sn-cs-row-processing' );
			} );
		});
	} );

	$( document ).on( 'click', '.sn-delete-source', function( e ) {
		e.preventDefault();
		var $el = $( this );
		SnDialog.confirm({
			message: wf_sn_cs.strings.confirm_delete,
			danger: true
		}).then(function( ok ) {
			if ( ! ok ) {
				return;
			}
			var $row = $el.closest( 'tr' );
			$row.addClass( 'sn-cs-row-processing' );
			$.post(
				ajaxurl,
				{
					action: 'sn_core_delete_file_do',
					_ajax_nonce: wf_sn_cs.nonce,
					filename: $el.attr( 'data-file' ),
					hash: $el.attr( 'data-hash' ),
					nonce: $el.attr( 'data-nonce' )
				},
				function( response ) {
					if ( response.success ) {
						applyRowActionResponse( response.data );
					} else {
						SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
						$row.removeClass( 'sn-cs-row-processing' );
					}
				},
				'json'
			).fail( function() {
				SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
				$row.removeClass( 'sn-cs-row-processing' );
			} );
		});
	} );

	function getIgnoreConfirmMessage( severity ) {
		if ( severity === 'critical' && wf_sn_cs.strings.confirm_ignore_critical ) {
			return wf_sn_cs.strings.confirm_ignore_critical;
		}
		if ( severity === 'warning' && wf_sn_cs.strings.confirm_ignore_warning ) {
			return wf_sn_cs.strings.confirm_ignore_warning;
		}
		if ( wf_sn_cs.strings.confirm_ignore_notice ) {
			return wf_sn_cs.strings.confirm_ignore_notice;
		}
		return wf_sn_cs.strings.confirm_ignore_warning || 'Ignore this file?';
	}

	$( document ).on( 'click', '.sn-cs-ignore-file', function( e ) {
		e.preventDefault();
		var $el = $( this );
		var severity = $el.attr( 'data-severity' ) || 'warning';
		SnDialog.confirm({
			message: getIgnoreConfirmMessage( severity )
		}).then(function( ok ) {
			if ( ! ok ) {
				return;
			}
			var $row = $el.closest( 'tr' );
			$row.addClass( 'sn-cs-row-processing' );
			$el.prop( 'disabled', true );
			$.post(
				ajaxurl,
				{
					action: 'sn_core_ignore_file',
					_ajax_nonce: wf_sn_cs.nonce,
					file_short: $el.attr( 'data-file-short' ),
					hash: $el.attr( 'data-hash' ),
					nonce: $el.attr( 'data-nonce' )
				},
				function( response ) {
					$el.prop( 'disabled', false );
					if ( response.success ) {
						applyRowActionResponse( response.data );
					} else {
						var msg = ( response.data && response.data.message ) ? response.data.message : wf_sn_cs.strings.error_occurred;
						SnDialog.alert({ message: msg });
						$row.removeClass( 'sn-cs-row-processing' );
					}
				},
				'json'
			).fail( function() {
				$el.prop( 'disabled', false );
				SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
				$row.removeClass( 'sn-cs-row-processing' );
			} );
		});
	} );

	$( document ).on( 'click', '.sn-cs-unignore-file', function( e ) {
		e.preventDefault();
		var $el = $( this );
		SnDialog.confirm({
			message: wf_sn_cs.strings.confirm_unignore || 'Stop ignoring this file?'
		}).then(function( ok ) {
			if ( ! ok ) {
				return;
			}
			$el.prop( 'disabled', true );
			$.post(
				ajaxurl,
				{
					action: 'sn_core_unignore_file',
					_ajax_nonce: wf_sn_cs.nonce,
					file_short: $el.attr( 'data-file-short' ),
					hash: $el.attr( 'data-hash' ),
					nonce: $el.attr( 'data-nonce' )
				},
				function( response ) {
					$el.prop( 'disabled', false );
					if ( response.success ) {
						applyRowActionResponse( response.data );
					} else {
						var msg = ( response.data && response.data.message ) ? response.data.message : wf_sn_cs.strings.error_occurred;
						SnDialog.alert({ message: msg });
					}
				},
				'json'
			).fail( function() {
				$el.prop( 'disabled', false );
				SnDialog.alert({ message: wf_sn_cs.strings.error_occurred });
			} );
		});
	} );

	$( document ).on( 'click', 'button.sn-delete-all-files', function( e ) {
		e.preventDefault();
		var $btn = $( this );
		SnDialog.confirm({
			message: wf_sn_cs.strings.confirm_delete_all,
			danger: true
		}).then(function( ok ) {
			if ( ! ok ) {
				return;
			}
			var $section = $btn.closest( '.sn-cs-section' );
			$section.find( 'tr[data-file-short]' ).addClass( 'sn-cs-row-processing' );
			$btn.prop( 'disabled', true );
			$.post(
				ajaxurl,
				{
					action: 'sn_core_delete_all_unknowns',
					_ajax_nonce: wf_sn_cs.delete_all_nonce
				},
				function( response ) {
					$btn.prop( 'disabled', false );
					$section.find( 'tr[data-file-short]' ).removeClass( 'sn-cs-row-processing' );
					if ( response.success ) {
						applyRowActionResponse( response.data );
					} else {
						var msg = ( response.data && response.data.message ) ? response.data.message : wf_sn_cs.strings.ajax_error;
						SnDialog.alert({ message: msg });
					}
				},
				'json'
			).fail( function() {
				$btn.prop( 'disabled', false );
				$section.find( 'tr[data-file-short]' ).removeClass( 'sn-cs-row-processing' );
				SnDialog.alert({ message: wf_sn_cs.strings.ajax_error });
			} );
		});
	} );

} );
