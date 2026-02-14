/* globals jQuery:true, ajaxurl:true, wf_sn_el:true, datatables_object:true, eventstable:true */
/**
 * Security Ninja - Events Logger
 * (c) Web factory Ltd, 2015
 * Larsik Corp 2020 -
 */

var eventstable;
var eventsTableInitialized = false;

function isEventsTabFocused() {
	if ( ! jQuery( '#sn-el-datatable' ).length ) {
		return false;
	}
	if ( ! jQuery( '#wf-sn-tabs' ).length ) {
		return true;
	}
	return window.location.hash === '#sn_logger';
}

function initEventsDataTable( forceFocus ) {
	if ( eventsTableInitialized ) {
		return;
	}
	if ( ! jQuery( '#sn-el-datatable' ).length ) {
		return;
	}
	if ( ! forceFocus && ! isEventsTabFocused() ) {
		return;
	}

	eventsTableInitialized = true;
	eventstable = jQuery( '#sn-el-datatable' ).DataTable( {
		processing: true,
		language: {
			processing: 'Loading…'
		},
		serverSide: true,
		pageLength: 25,
		ajax: {
			url: ajaxurl,
			type: 'POST',
			data: function( d ) {
				d.action = 'get_events_data';
				d.nonce = datatables_object.nonce;
				d.action_filter = jQuery( '#sn-el-action-filter' ).val();
			},
			error: function( xhr, error, code ) {
				var errorMsg = '<strong>Error loading data:</strong><br>Status: ' + xhr.status + ' (' + xhr.statusText + ')<br>Error: ' + error + '<br>Code: ' + code + '<br>Response: ' + xhr.responseText;
				jQuery( '#datatable-error' ).html( errorMsg ).show();
			}
		},
		columns: [
			{ data: 'timestamp', title: 'Time' },
			{ data: 'action', title: 'Action' },
			{ data: 'user_id', title: 'User' },
			{ data: 'description', title: 'Event' },
			{ data: 'details', title: 'Details', orderable: false }
		],
		order: [[ 0, 'desc' ]],
		columnDefs: [{
			targets: 4,
			data: null,
			defaultContent: '<button>Detail</button>'
		}]
	} );

	function loadActionFilter() {
		jQuery.post( ajaxurl, {
			action: 'get_events_actions',
			nonce: datatables_object.nonce
		}, function( response ) {
			if ( response.success && response.data.actions ) {
				var select = jQuery( '#sn-el-action-filter' );
				select.empty();
				select.append( '<option value="">All Actions</option>' );
				response.data.actions.forEach( function( action ) {
					select.append( '<option value="' + action + '">' + action + '</option>' );
				} );
			}
		} );
	}
	loadActionFilter();

	jQuery( '#sn-el-action-filter' ).on( 'change', function() {
		eventstable.ajax.reload();
	} );

	jQuery( '#sn-el-reset-filter' ).on( 'click', function() {
		jQuery( '#sn-el-action-filter' ).val( '' );
		eventstable.ajax.reload();
	} );

	jQuery( '#sn-el-datatable tbody' ).on( 'click', 'button', function( e ) {
		e.preventDefault();
		var tr = jQuery( this ).closest( 'tr' );
		var row = eventstable.row( tr );
		if ( row.child.isShown() ) {
			row.child.hide();
			tr.removeClass( 'shown' );
			jQuery( this ).removeClass( 'open' );
		} else {
			var details = tr.find( '.details-content' ).html();
			row.child( details ).show();
			tr.addClass( 'shown' );
			jQuery( this ).addClass( 'open' );
		}
	} );
}

jQuery( document ).ready( function( $ ) {
	// Tab switching (Events Logger subtabs).
	$( '#wf-sn-el-subtabs a' ).on( 'click', function( e ) {
		e.preventDefault();
		$( '#wf-sn-el-subtabs a' ).removeClass( 'nav-tab-active' );
		$( '.wf-sn-el-subtab' ).hide();
		$( this ).addClass( 'nav-tab-active' );
		var target = $( this ).attr( 'href' );
		$( target ).show();
	} );

	function maybeInitEventsDataTable() {
		if ( window.location.hash !== '#sn_logger' ) {
			return;
		}
		initEventsDataTable( true );
	}

	jQuery( window ).on( 'hashchange', maybeInitEventsDataTable );
	jQuery( document ).on( 'click', '#wf-sn-tabs a[href="#sn_logger"]', function() {
		maybeInitEventsDataTable();
	} );
	maybeInitEventsDataTable();

	jQuery( '#sn-el-truncate' ).on( 'click', function( e ) {
		e.preventDefault();
		var answer = confirm( 'Are you sure you want to delete all log entries?' );
		if ( answer ) {
			var data = {
				action: 'sn_el_truncate_log',
				_ajax_nonce: wf_sn_el.nonce
			};
			$.post( ajaxurl, data, function( response ) {
				if ( ! response ) {
					alert( 'Bad AJAX response. Please reload the page.' );
				} else {
					alert( 'All log entries have been deleted.' );
					window.location.reload();
				}
			} );
		}
	} );
} );
