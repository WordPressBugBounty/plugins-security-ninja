/* globals jQuery:true, ajaxurl:true, wf_sn:true */
/* Functions are loaded on entire WP admin */





/* Resets Freemius activation via ajax call. */
jQuery(document).on('click', '.secninfs-reset-activation', function (e) {
  
  e.preventDefault();
  
  jQuery('.wrap').prepend('<div class="secning-loading-popup"><p>Please wait<span class="spinner is-active"></span></p></div>');
  
  jQuery(".secning-loading-popup").toggle();
  var nonce = jQuery('#wfsn-secninfs-reset-activation-nonce').val();

  jQuery.ajax({
    url: ajaxurl,
    type: 'POST',
    data: {
      action      :'wfsn_freemius_reset_activation',
      _ajax_nonce : nonce
    },
    success: function( response ) {
      window.location.reload();
    },
    error: function( response ) {
      window.location.reload();
    }
  });
  
});



/* Loads the latest events (if any) in the sidebar */
jQuery(document).ready(function($) {







  if (jQuery('#sn_sidebar_latest').length > 0) {
    // Add a spinner to the target DIV
    jQuery('#sn_sidebar_latest').html('<div class="spinner" style="visibility: visible;"></div>');

    jQuery.ajax({
      url: ajaxurl,
      type: 'POST',
      data: {
        action: 'sn_sidebar_latest_events',
        nonce: wf_sn.nonce_latest_events
      },
      success: function(response) {
        if (response.success) {
          jQuery('#sn_sidebar_latest').html(response.data);
        } else {
          if (typeof console !== 'undefined') {
            console.error('Error:', response.data);
          }
        }
      },
      error: function(jqXHR, textStatus, errorThrown) {
        if (typeof console !== 'undefined') {
          console.error('AJAX Error:', textStatus, errorThrown);
        }
      }
    });
  }



});

