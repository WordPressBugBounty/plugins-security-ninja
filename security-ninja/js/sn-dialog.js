/**
 * Security Ninja shared dialog helper.
 *
 * Uses native <dialog>.showModal() when available, with a div overlay fallback.
 * Escape / backdrop cancel; Enter activates the default button.
 *
 * @package Security_Ninja
 */
( function ( window, document ) {
	'use strict';

	if ( window.SnDialog ) {
		return;
	}

	var l10n = window.snDialogL10n || {};
	var ROOT_ID = 'sn-dialog-root';
	var active = null;

	function t( key, fallback ) {
		return ( l10n && l10n[ key ] ) ? String( l10n[ key ] ) : fallback;
	}

	function supportsNativeDialog() {
		return typeof window.HTMLDialogElement !== 'undefined' &&
			typeof document.createElement( 'dialog' ).showModal === 'function';
	}

	function getFocusable( root ) {
		if ( ! root ) {
			return [];
		}
		var nodes = root.querySelectorAll(
			'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
		);
		return Array.prototype.slice.call( nodes ).filter( function ( el ) {
			return el.offsetParent !== null || el === document.activeElement;
		} );
	}

	function clearActive() {
		document.body.classList.remove( 'sn-dialog-open' );
		if ( ! active ) {
			return;
		}
		document.removeEventListener( 'keydown', active.onKeyDown, true );
		if ( active.root && active.root.parentNode ) {
			active.root.parentNode.removeChild( active.root );
		}
		if ( active.previousFocus && typeof active.previousFocus.focus === 'function' ) {
			try {
				active.previousFocus.focus();
			} catch ( e ) { /* ignore */ }
		}
		active = null;
	}

	function settle( result ) {
		var resolve = active && active.resolve;
		var onClose = active && active.onClose;
		if ( typeof onClose === 'function' ) {
			try {
				onClose();
			} catch ( e ) { /* ignore */ }
		}
		clearActive();
		if ( typeof resolve === 'function' ) {
			resolve( result );
		}
	}

	function buildShell( opts ) {
		var useNative = supportsNativeDialog();
		var root = document.createElement( useNative ? 'dialog' : 'div' );
		root.id = ROOT_ID;
		root.className = 'sn-dialog-root' + ( useNative ? ' sn-dialog-root--native' : ' sn-dialog-root--fallback' );
		root.setAttribute( 'role', 'dialog' );
		root.setAttribute( 'aria-modal', 'true' );
		if ( opts.titleId ) {
			root.setAttribute( 'aria-labelledby', opts.titleId );
		}

		if ( ! useNative ) {
			var backdrop = document.createElement( 'div' );
			backdrop.className = 'sn-dialog-backdrop';
			backdrop.setAttribute( 'data-sn-backdrop', '1' );
			root.appendChild( backdrop );
		}

		var panel = document.createElement( 'div' );
		panel.className = 'sn-dialog-panel' + ( opts.size === 'large' ? ' sn-dialog-panel--large' : '' ) + ( opts.danger ? ' is-danger' : '' );
		root.appendChild( panel );

		return { root: root, panel: panel, useNative: useNative };
	}

	function appendHeader( panel, title, titleId ) {
		if ( ! title ) {
			return;
		}
		var header = document.createElement( 'div' );
		header.className = 'sn-dialog-header';
		var h = document.createElement( 'h2' );
		h.className = 'sn-dialog-title';
		h.id = titleId;
		h.textContent = String( title );
		header.appendChild( h );
		panel.appendChild( header );
	}

	function appendBodyText( panel, message ) {
		var body = document.createElement( 'div' );
		body.className = 'sn-dialog-body';
		var p = document.createElement( 'p' );
		p.className = 'sn-dialog-message';
		p.textContent = String( message == null ? '' : message );
		body.appendChild( p );
		panel.appendChild( body );
		return body;
	}

	function appendBodyContent( panel, opts ) {
		var body = document.createElement( 'div' );
		body.className = 'sn-dialog-body';
		if ( opts.bodyNode && opts.bodyNode.nodeType ) {
			body.appendChild( opts.bodyNode );
		} else if ( opts.bodyHtml != null ) {
			body.innerHTML = String( opts.bodyHtml );
		}
		panel.appendChild( body );
		return body;
	}

	function appendActions( panel, buttons ) {
		var actions = document.createElement( 'div' );
		actions.className = 'sn-dialog-actions';
		var defaultBtn = null;
		buttons.forEach( function ( btn ) {
			var el = document.createElement( 'button' );
			el.type = 'button';
			el.className = 'button' + ( btn.primary ? ' button-primary' : '' ) + ( btn.danger ? ' sn-dialog-btn-danger' : '' );
			el.textContent = String( btn.label );
			el.setAttribute( 'data-sn-action', btn.id );
			if ( btn.default ) {
				el.setAttribute( 'data-sn-default', '1' );
				defaultBtn = el;
			}
			el.addEventListener( 'click', function () {
				settle( btn.value );
			} );
			actions.appendChild( el );
		} );
		panel.appendChild( actions );
		return defaultBtn || actions.querySelector( '[data-sn-default]' ) || actions.querySelector( 'button' );
	}

	function openShell( shell, defaultBtn, resolve, onClose ) {
		document.body.appendChild( shell.root );

		var onKeyDown = function ( e ) {
			if ( ! active || active.root !== shell.root ) {
				return;
			}
			if ( e.key === 'Escape' || e.keyCode === 27 ) {
				e.preventDefault();
				e.stopPropagation();
				settle( active.cancelValue );
				return;
			}
			if ( e.key === 'Tab' || e.keyCode === 9 ) {
				var focusable = getFocusable( shell.panel );
				if ( ! focusable.length ) {
					e.preventDefault();
					return;
				}
				var first = focusable[ 0 ];
				var last = focusable[ focusable.length - 1 ];
				if ( e.shiftKey && document.activeElement === first ) {
					e.preventDefault();
					last.focus();
				} else if ( ! e.shiftKey && document.activeElement === last ) {
					e.preventDefault();
					first.focus();
				}
				return;
			}
			if ( e.key === 'Enter' || e.keyCode === 13 ) {
				var tag = ( document.activeElement && document.activeElement.tagName ) ? document.activeElement.tagName.toLowerCase() : '';
				if ( tag === 'textarea' || tag === 'select' || ( tag === 'button' && document.activeElement !== defaultBtn ) ) {
					return;
				}
				if ( defaultBtn && tag !== 'button' && tag !== 'a' ) {
					e.preventDefault();
					defaultBtn.click();
				}
			}
		};

		active = {
			root: shell.root,
			panel: shell.panel,
			resolve: resolve,
			cancelValue: null,
			previousFocus: document.activeElement,
			onKeyDown: onKeyDown,
			onClose: typeof onClose === 'function' ? onClose : null,
		};

		document.addEventListener( 'keydown', onKeyDown, true );

		shell.root.addEventListener( 'click', function ( e ) {
			if ( e.target === shell.root || ( e.target && e.target.getAttribute && e.target.getAttribute( 'data-sn-backdrop' ) === '1' ) ) {
				settle( active ? active.cancelValue : null );
			}
		} );

		if ( shell.useNative ) {
			shell.root.addEventListener( 'cancel', function ( e ) {
				e.preventDefault();
				settle( active ? active.cancelValue : null );
			} );
			shell.root.showModal();
		} else {
			shell.root.classList.add( 'is-open' );
			document.body.classList.add( 'sn-dialog-open' );
		}

		if ( defaultBtn && typeof defaultBtn.focus === 'function' ) {
			window.setTimeout( function () {
				defaultBtn.focus();
			}, 0 );
		}
	}

	function confirm( options ) {
		options = options || {};
		return new Promise( function ( resolve ) {
			if ( active ) {
				settle( active.cancelValue );
			}
			var titleId = 'sn-dialog-title-' + String( Date.now() );
			var shell = buildShell( { titleId: titleId, danger: !! options.danger } );
			appendHeader( shell.panel, options.title || '', titleId );
			appendBodyText( shell.panel, options.message );
			var defaultBtn = appendActions( shell.panel, [
				{
					id: 'cancel',
					label: options.cancelText || t( 'cancel', 'Cancel' ),
					value: false,
					primary: false,
					default: false,
				},
				{
					id: 'confirm',
					label: options.confirmText || t( 'ok', 'OK' ),
					value: true,
					primary: true,
					danger: !! options.danger,
					default: true,
				},
			] );
			openShell( shell, defaultBtn, resolve, null );
			if ( active ) {
				active.cancelValue = false;
			}
		} );
	}

	function alert( options ) {
		options = options || {};
		return new Promise( function ( resolve ) {
			if ( active ) {
				settle( active.cancelValue );
			}
			var titleId = 'sn-dialog-title-' + String( Date.now() );
			var shell = buildShell( { titleId: titleId } );
			appendHeader( shell.panel, options.title || '', titleId );
			appendBodyText( shell.panel, options.message );
			var defaultBtn = appendActions( shell.panel, [
				{
					id: 'ok',
					label: options.confirmText || t( 'ok', 'OK' ),
					value: undefined,
					primary: true,
					default: true,
				},
			] );
			openShell( shell, defaultBtn, function () {
				resolve();
			}, null );
			if ( active ) {
				active.cancelValue = undefined;
			}
		} );
	}

	function open( options ) {
		options = options || {};
		return new Promise( function ( resolve ) {
			if ( active ) {
				settle( active.cancelValue );
			}
			var titleId = 'sn-dialog-title-' + String( Date.now() );
			var shell = buildShell( { titleId: titleId, size: options.size || '' } );
			if ( ! options.hideTitle ) {
				appendHeader( shell.panel, options.title || '', titleId );
			}
			appendBodyContent( shell.panel, options );
			var buttons;
			if ( options.buttons === false ) {
				buttons = [];
			} else if ( Array.isArray( options.buttons ) ) {
				buttons = options.buttons;
			} else {
				buttons = [ { id: 'close', label: t( 'close', 'Close' ), primary: true, default: true } ];
			}
			var mapped = buttons.map( function ( btn, index ) {
				return {
					id: btn.id || ( 'btn-' + index ),
					label: btn.label || t( 'close', 'Close' ),
					value: btn.id || ( 'btn-' + index ),
					primary: !! btn.primary || ( buttons.length && ! buttons.some( function ( b ) { return b.primary; } ) && index === buttons.length - 1 ),
					danger: !! btn.danger,
					default: !! btn.default || ( buttons.length && index === buttons.length - 1 && ! buttons.some( function ( b ) { return b.default; } ) ),
				};
			} );
			var defaultBtn = mapped.length ? appendActions( shell.panel, mapped ) : null;
			openShell( shell, defaultBtn, resolve, options.onClose );
			if ( active ) {
				active.cancelValue = null;
			}
		} );
	}

	function close( result ) {
		if ( ! active ) {
			return;
		}
		settle( typeof result !== 'undefined' ? result : active.cancelValue );
	}

	/**
	 * Intercept form submits / clicks that need confirmation.
	 */
	function bindConfirmSubmit() {
		document.addEventListener( 'click', function ( e ) {
			var target = e.target;
			if ( ! target || ! target.closest ) {
				return;
			}
			var btn = target.closest( '.sn-confirm-submit' );
			if ( ! btn ) {
				return;
			}
			if ( btn.getAttribute( 'data-sn-confirmed' ) === '1' ) {
				btn.removeAttribute( 'data-sn-confirmed' );
				return;
			}
			var message = btn.getAttribute( 'data-sn-confirm' );
			if ( ! message ) {
				return;
			}
			e.preventDefault();
			e.stopPropagation();
			confirm( {
				message: message,
				danger: btn.getAttribute( 'data-sn-danger' ) === '1',
				confirmText: btn.getAttribute( 'data-sn-confirm-text' ) || t( 'ok', 'OK' ),
				cancelText: btn.getAttribute( 'data-sn-cancel-text' ) || t( 'cancel', 'Cancel' ),
			} ).then( function ( ok ) {
				if ( ! ok ) {
					return;
				}
				btn.setAttribute( 'data-sn-confirmed', '1' );
				var form = btn.form || ( btn.closest && btn.closest( 'form' ) );
				if ( btn.tagName === 'BUTTON' || ( btn.tagName === 'INPUT' && ( btn.type === 'submit' || btn.type === 'button' || btn.type === 'image' ) ) ) {
					if ( form && typeof form.requestSubmit === 'function' ) {
						form.requestSubmit( btn );
					} else if ( form ) {
						form.submit();
					} else {
						btn.click();
					}
				} else if ( form ) {
					form.submit();
				} else {
					btn.click();
				}
			} );
		}, true );
	}

	bindConfirmSubmit();

	window.SnDialog = {
		confirm: confirm,
		alert: alert,
		open: open,
		close: close,
	};
}( window, document ) );
