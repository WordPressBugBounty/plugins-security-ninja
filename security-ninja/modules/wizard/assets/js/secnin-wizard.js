/* globals jQuery, ajaxurl, whizzie_params */
'use strict';

const Whizzie = ( function( $ ) {
	let currentStep = '';
	let stepPointer = '';

	function getWizardWrap() {
		return $( '.whizzie-wrap' );
	}

	function setWizardBusy( isBusy ) {
		const $wrap = getWizardWrap();
		if ( isBusy ) {
			$wrap.addClass( 'spinning' ).attr( 'aria-busy', 'true' );
		} else {
			$wrap.removeClass( 'spinning' ).attr( 'aria-busy', 'false' );
		}
	}

	function stopWizardSpinning() {
		setWizardBusy( false );
	}

	function clearWizardNotices() {
		$( '.secnin-wizard-notices' ).empty();
	}

	function showWizardNotice( message ) {
		const $container = $( '.secnin-wizard-notices' );
		if ( ! $container.length ) {
			return;
		}
		const text = message || whizzie_params.generic_error;
		const $notice = $( '<div />', {
			class: 'notice notice-error secnin-notice',
		} );
		$notice.append( $( '<p />' ).text( text ) );
		$container.empty().append( $notice );
		$container[0].scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
	}

	function getAjaxErrorMessage( data ) {
		if ( ! data ) {
			return '';
		}
		if ( typeof data === 'string' ) {
			return data;
		}
		if ( data.message ) {
			return data.message;
		}
		return '';
	}

	function runWizardAjax( action, onSuccess ) {
		clearWizardNotices();
		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			dataType: 'json',
			data: {
				action: action,
				_ajax_nonce: whizzie_params.nonce,
			},
		} )
			.done( function( response ) {
				if ( response && response.success ) {
					onSuccess();
				} else {
					stopWizardSpinning();
					let msg = getAjaxErrorMessage( response && response.data );
					if ( ! msg ) {
						msg = whizzie_params.generic_error;
					}
					showWizardNotice( msg );
				}
			} )
			.fail( function( jqXHR, textStatus, errorThrown ) {
				stopWizardSpinning();
				let msg = whizzie_params.network_error;
				if ( jqXHR.responseJSON && jqXHR.responseJSON.data ) {
					const fromJson = getAjaxErrorMessage( jqXHR.responseJSON.data );
					if ( fromJson ) {
						msg = fromJson;
					}
				} else if ( textStatus && errorThrown ) {
					msg = textStatus + ': ' + errorThrown;
				}
				showWizardNotice( msg );
			} );
	}

	function getNavStatusLabel( $navItem ) {
		const i18n = whizzie_params.i18n || {};
		if ( $navItem.hasClass( 'done-step' ) ) {
			return i18n.nav_completed || 'Completed step';
		}
		if ( $navItem.hasClass( 'active-step' ) ) {
			return i18n.nav_current || 'Current step';
		}
		return i18n.nav_upcoming || 'Upcoming step';
	}

	function updateWizardProgressNav( stepId ) {
		const $navItems = $( '.whizzie-nav li' );
		$navItems.each( function() {
			const $item = $( this );
			const isActive = $item.hasClass( 'nav-step-' + stepId );
			if ( isActive ) {
				$item.attr( 'aria-current', 'step' );
			} else {
				$item.removeAttr( 'aria-current' );
			}
			$item.find( '.secnin-wizard-nav-status' ).text( getNavStatusLabel( $item ) );
		} );
	}

	const callbacks = {
		do_next_step: function() {
			doNextStep();
		},

		activate_firewall: function() {
			runWizardAjax( 'secnin_activate_firewall', function() {
				doNextStep();
			} );
		},

		activate_events: function() {
			runWizardAjax( 'secnin_activate_events', function() {
				doNextStep();
			} );
		},

		activate_vulnerabilities: function() {
			runWizardAjax( 'secnin_activate_vulnerabilities', function() {
				doNextStep();
			} );
		},

		activate_login_protection: function() {
			runWizardAjax( 'secnin_activate_login_protection', function() {
				doNextStep();
			} );
		},

		activate_default_fixes: function() {
			runWizardAjax( 'secnin_activate_default_fixes', function() {
				doNextStep();
			} );
		},

		activate_woocommerce: function() {
			runWizardAjax( 'secnin_activate_woocommerce', function() {
				doNextStep();
			} );
		},
	};

	function setStepHeight() {
		let maxHeight = 0;

		$( '.whizzie-menu li.step' ).each( function() {
			$( this ).attr( 'data-height', $( this ).innerHeight() );
			if ( $( this ).innerHeight() > maxHeight ) {
				maxHeight = $( this ).innerHeight();
			}
		} );

		$( '.whizzie-menu li .detail' ).each( function() {
			$( this ).attr( 'data-height', $( this ).innerHeight() );
			$( this ).addClass( 'scale-down' );
		} );

		$( '.whizzie-menu li.step' ).css( 'height', maxHeight );
	}

	function initializeSteps() {
		$( '.whizzie-menu li.step:first-child' ).addClass( 'active-step' );
		$( '.whizzie-nav li:first-child' ).addClass( 'active-step' );
		getWizardWrap().addClass( 'loaded' ).attr( 'aria-busy', 'false' );
		updateWizardProgressNav( $( '.whizzie-menu li.step:first-child' ).data( 'step' ) );
	}

	function handleMoreInfoClick() {
		$( '.whizzie-wrap' ).on( 'click', '.more-info', function( e ) {
			e.preventDefault();
			const parent = $( this ).parent().parent();
			parent.toggleClass( 'show-detail' );
			const detail = parent.find( '.detail' );
			const maxHeight = parent.data( 'height' );

			if ( parent.hasClass( 'show-detail' ) ) {
				parent
					.animate(
						{
							height: maxHeight + detail.data( 'height' ),
						},
						500,
						function() {
							detail.toggleClass( 'scale-down' );
						}
					)
					.css( 'overflow', 'visible' );
			} else {
				parent
					.animate(
						{
							height: maxHeight,
						},
						500,
						function() {
							detail.toggleClass( 'scale-down' );
						}
					)
					.css( 'overflow', 'visible' );
			}
		} );
	}

	function handleWizardExitClick( selector ) {
		$( '.whizzie-wrap' ).on( 'click', selector, function( e ) {
			e.preventDefault();
			const href = $( this ).data( 'href' ) || $( this ).attr( 'href' );
			if ( ! href || '#' === href ) {
				return;
			}
			setWizardBusy( true );
			runWizardAjax( 'secnin_wizard_all_done', function() {
				window.location.href = href;
			} );
		} );
	}

	function handleDoItClick() {
		$( '.whizzie-wrap' ).on( 'click', '.do-it', function( e ) {
			e.preventDefault();
			stepPointer = $( this ).data( 'step' );
			currentStep = $( '.step-' + stepPointer );
			setWizardBusy( true );

			const cbName = $( this ).data( 'callback' );
			if ( cbName && typeof callbacks[ cbName ] !== 'undefined' ) {
				callbacks[ cbName ]();
				return false;
			}
			return true;
		} );
	}

	function secninWindowLoaded() {
		setStepHeight();
		initializeSteps();
		handleMoreInfoClick();
		handleWizardExitClick( '.secnin-wizard-finish' );
		handleWizardExitClick( '.secnin-wizard-exit' );
		handleDoItClick();
	}

	function doNextStep() {
		currentStep.removeClass( 'active-step' );
		$( '.nav-step-' + stepPointer ).removeClass( 'active-step' );
		currentStep.addClass( 'done-step' );
		$( '.nav-step-' + stepPointer ).addClass( 'done-step' );
		currentStep.fadeOut( 500, function() {
			currentStep = currentStep.next();
			stepPointer = currentStep.data( 'step' );
			currentStep.fadeIn();
			currentStep.addClass( 'active-step' );
			$( '.nav-step-' + stepPointer ).addClass( 'active-step' );
			updateWizardProgressNav( stepPointer );
			stopWizardSpinning();
		} );
	}

	return {
		init: function() {
			$( secninWindowLoaded );
		},
		callback: function() {
			// Reserved for extensions.
		},
	};
}( jQuery ) );

jQuery( document ).ready( function() {
	Whizzie.init();
} );
