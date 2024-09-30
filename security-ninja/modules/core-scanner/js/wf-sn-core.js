/* globals jQuery:true, ajaxurl:true, wf_sn_cs:true */
/*
* Security Ninja - Scheduled Scanner add-on
* (c) 2014. Web factory Ltd
* 2019. Larsik Corp
*/

jQuery(document).ready(function($) {
  
  // get the updates
  get_latest_update();
 
  $('button.sn-show-source').on("click",function() {
    $($(this).attr('href')).dialog('option', {
      title: wf_sn_cs.strings.file_source+': ' + $(this).attr('data-file'),
      file_path: $(this).attr('data-file'),
      file_hash: $(this).attr('data-hash')
    }).dialog('open');
    return false;
  });
  
  // Restore a file
  $(document).on('click', 'button.sn-restore-source', function(e) {
    e.preventDefault();
    if (!confirm(wf_sn_cs.strings.confirm_restore)) {
      return false;
    }
    jQuery(this).attr('disabled', 'disabled');
    var filename = jQuery(this).attr('data-file');
    var filehash = jQuery(this).attr('data-hash');
    jQuery.post(ajaxurl, {
      action      : 'sn_core_restore_file_do',
      _ajax_nonce : wf_sn_cs.nonce,
      filename: filename,
      filehash: filehash
    }, function(response) {
      if (response.success) {
        jQuery('[data-hash="'+filehash+'"]').closest('li').fadeOut("slow", function() {
          jQuery(this).remove();
          get_latest_update(true);
        });
        jQuery('#wf-sn-core-scanner-response').append('<p>' + response.data.message + '</p>');
      } 
      else {
        jQuery('#wf-sn-core-scanner-response').append('<p class="error">' + wf_sn_cs.strings.error_occurred + ': ' + response.data.message + '</p>');
        jQuery(this).removeAttr('disabled');
      }
    }, 'json');
  });
  
  // Delete a file
  $(document).on('click', 'button.sn-delete-source', function(e) {
    e.preventDefault();
    if (!confirm(wf_sn_cs.strings.confirm_delete)) {
      return false;
    }
    jQuery(this).attr('disabled', 'disabled');
    var filename = jQuery(this).attr('data-file');
    var filehash = jQuery(this).attr('data-hash');
    jQuery.post(ajaxurl, {
      action      : 'sn_core_delete_file_do',
      _ajax_nonce : wf_sn_cs.nonce,
      filename: filename,
      filehash: filehash
    }, function(response) {
      if (response.success) {
        jQuery('[data-hash="'+filehash+'"]').closest('li').fadeOut("slow", function() {
          jQuery(this).remove();
        });
      } 
      else {
        alert(wf_sn_cs.strings.error_occurred+ ': ' + response);
        jQuery(this).attr('disabled', '');
      }
    }, 'json');
  });
  
  // Delete ALL files
  $(document).on('click', 'button.sn-delete-all-files', function(e) {
    e.preventDefault();
    if (!confirm(wf_sn_cs.strings.confirm_delete_all)) {
      return false;
    }
    jQuery(this).attr('disabled', 'disabled');

    jQuery.ajax({
      url: ajaxurl,
      type: 'POST',
      data: {
      'action'      : 'sn_core_delete_all_unknowns',
      '_ajax_nonce' : wf_sn_cs.delete_all_nonce
    },
    success: function() {
      window.location.reload();
    },
    error: function() {
      alert(wf_sn_cs.strings.ajax_error);
    }
  });
});
  

  function get_latest_update(forceupdate) {
    jQuery('#wf-sn-core-scanner-response').show();
    jQuery('#wf-sn-core-scanner-response #sn-cs-results').slideUp();
    jQuery('#wf-sn-core-scanner-response #last_scan').slideUp();
    jQuery('#wf-sn-core-scanner-response .spinner').addClass('is-active');
    var data = {
      action: 'sn_core_run_scan',
      _ajax_nonce: wf_sn_cs.nonce
    };
    if (forceupdate) {
      data.doupdate = true;
    }
    $.post(ajaxurl, data, function(response) {
      jQuery('#wf-sn-core-scanner-response .spinner').removeClass('is-active');
      if (response.data.out) {
        jQuery('#wf-sn-core-scanner-response').append(response.data.out).slideDown();
      }
      if (response.data.last_scan) {
        jQuery('#wf-sn-core-scanner-response #last_scan').html(response.data.last_scan).slideDown();
      }
    }, 'json');
  }
    
  // Run AJAX core scan and display returned results
  $(document).on('click', '#sn-run-core-scan', function(e) {
    e.preventDefault();
    jQuery('#wf-sn-core-scanner-response #sn-cs-results').slideUp();
    jQuery('#wf-sn-core-scanner-response #last_scan').slideUp();
    jQuery('#wf-sn-core-scanner-response .spinner').addClass('is-active');
    jQuery.post(ajaxurl, {
      action: 'sn_core_run_scan',
      _ajax_nonce: wf_sn_cs.nonce,
      datatype: 'json',
      doupdate: true
    }, function(response) {
      jQuery('#wf-sn-core-scanner-response .spinner').removeClass('is-active');
      if (response.data.out) {
        jQuery('#wf-sn-core-scanner-response').append(response.data.out).slideDown();
      }
      if (response.data.last_scan) {
        jQuery('#wf-sn-core-scanner-response #last_scan').html(response.data.last_scan).slideDown();
      }
    });
  });
});