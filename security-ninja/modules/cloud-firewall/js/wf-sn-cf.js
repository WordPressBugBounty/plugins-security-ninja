/* globals jQuery:true, ajaxurl:true, wf_sn_cf:true, wf_sn:true, sn_block_ui:true, alert:true */
/*
* Security Ninja PRO
* (c) 2018. Web factory Ltd
*/

jQuery(document).ready(function ($) {

  // Handle tab switching
  $('#wf-sn-cf-subtabs .nav-tab').on('click', function(e) {
    e.preventDefault();
    $('#wf-sn-cf-subtabs .nav-tab').removeClass('nav-tab-active');
    $('.wf-sn-subtab').hide();

    
    $(this).addClass('nav-tab-active');
    var targetId = $(this).attr('href');
    $(targetId).show();
  });

  // Function to toggle sub-inputs
  function toggleSubInputs(checkbox, subInputClass) {
    if (checkbox.is(':checked')) {
        $(subInputClass).removeClass('sn-disabled');
    } else {
        $(subInputClass).addClass('sn-disabled');
    }
  }



  // Select all countries button
  $('#select_all_countries').click(function (e) {
    e.preventDefault();
    $('#wf_sn_cf_blocked_countries option').prop('selected', true);
    $('#wf_sn_cf_blocked_countries').trigger('change');
  });

  $('#select_no_countries').click(function (e) {
    e.preventDefault();
    $('#wf_sn_cf_blocked_countries option').prop('selected', false);
    $('#wf_sn_cf_blocked_countries').trigger('change');
  });

  $('#sn_cf').on('click', '.testresults h3', function (e) {
    e.preventDefault();
    $(this).parents('.testresults').toggleClass('opened').find('table');
  });

  // Select2 on country dropdown
  $('#wf_sn_cf_blocked_countries').select2({
    multiple: true,
    dropdownAutoWidth: true,
    closeOnSelect: false,
    theme: 'classic'
  });

  // Show modal on button click
  $('#sn-enable-firewall-overlay').on('click', function (e) {
    e.preventDefault();
    $('#sn-firewall-modal').show();
  });

  // Close modal on close button
  $('.sn-modal-close').on('click', function () {
    $('#sn-firewall-modal').hide();
  });

  // Close modal on clicking outside the modal
  $(document).on('click', function (e) {
    if ($(e.target).is('#sn-firewall-modal')) {
      $('#sn-firewall-modal').hide();
    }
  });

  // Handle Continue button click
  $('#sn-modal-continue,#sn-modal-skip').on('click', function () {
    var isSkip = $(this).attr('id') === 'sn-modal-skip';

    // Disable the buttons and input field
    $('#sn-modal-continue').attr('disabled', 'disabled');
    $('#sn-modal-skip').attr('disabled', 'disabled');
    $('#sn-firewall-email').attr('disabled', 'disabled');
    
    $('#sn-unblock-message').html('<img title="Loading ..." src="' + wf_sn.sn_plugin_url + 'images/ajax-loader.gif" alt="Loading...">');
    $('#sn-unblock-message').removeClass('sn-unblock-message-bad');
    $('#sn-unblock-message').removeClass('sn-unblock-message-good');

    if (!isSkip) {
      // Only send email if continue button was clicked
      var email = $('#sn-firewall-email').val();
      var data = {
        action: 'sn_send_unblock_email',
        email: email,
        _ajax_nonce: wf_sn_cf.nonce
      };

      $.ajax({
        type: 'POST',
        url: ajaxurl,
        data: data,
        success: function (response) {
          $('#sn-firewall-status').text('Unblock email sent successfully. Enabling firewall...');
          enableFirewall();
        },
        error: function (jqXHR, textStatus, errorThrown) {
          console.error('AJAX Error:', textStatus, errorThrown);
          console.error('Response:', jqXHR.responseText);
          $('#sn-unblock-message').html('An error occurred while sending the unblock email.');
          $('#sn-unblock-message').addClass('sn-unblock-message-bad');
          // Re-enable the buttons and input
          $('#sn-modal-continue').removeAttr('disabled');
          $('#sn-modal-skip').removeAttr('disabled');
          $('#sn-firewall-email').removeAttr('disabled');
        }
      });
    } else {
      // Skip email and enable firewall directly
      enableFirewall();
    }
  });

  function enableFirewall() {
    $.ajax({
      type: 'POST',
      url: ajaxurl,
      data: {
        action: 'sn_enable_firewall',
        _ajax_nonce: wf_sn_cf.nonce
      },
      success: function (response) {
        $('#sn-unblock-message').hide();
        $('#sn-firewall-status').text('Firewall enabled successfully. Reloading...');
        setTimeout(function () {
          window.location.reload();
        }, 2000);
      },
      error: function (jqXHR, textStatus, errorThrown) {
        console.error('AJAX Error:', textStatus, errorThrown);
        console.error('Response:', jqXHR.responseText);
        $('#sn-unblock-message').html('An error occurred. The firewall could not be enabled.');
        $('#sn-unblock-message').addClass('sn-unblock-message-bad');
        // Re-enable the buttons and input
        $('#sn-modal-continue').removeAttr('disabled');
        $('#sn-modal-skip').removeAttr('disabled');
        $('#sn-firewall-email').removeAttr('disabled');
      }
    });
  }

  // Close button for firewall overlay
  $('#sn-close-firewall').on('click', function (e) {
    e.preventDefault();
    window.location.reload();
  });

  // Send unlock code
  $('#sn-send-unlock-code').on('click', function (e) {
    e.preventDefault();
    var data = {
      action: 'sn_send_unblock_email',
      email: $('#sn-ublock-email').val(),
      _ajax_nonce: wf_sn_cf.nonce
    };

    $('#sn-unblock-message').html('<img title="Loading ..." src="' + wf_sn.sn_plugin_url + 'images/ajax-loader.gif" alt="Loading...">');
    $('#sn-unblock-message').removeClass('sn-unblock-message-bad');
    $('#sn-unblock-message').removeClass('sn-unblock-message-good');

    $.get(ajaxurl, data, function (response) {
      if (response !== '1') {
        $('#sn-unblock-message').html('An error occurred and the message could not be sent.');
        $('#sn-unblock-message').addClass('sn-unblock-message-bad');
      } else {
        $('#sn-unblock-message').html('Email sent successfully.');
        $('#sn-unblock-message').addClass('sn-unblock-message-good');
      }
    }, 'html').fail(function () {
      $('#sn-unblock-message').html('An error occurred. The email could not be sent.');
      $('#sn-unblock-message').addClass('sn-unblock-message-bad');
    });
  });

  // Clear firewall blacklist
  $('#sn-firewall-blacklist-clear').on('click', function (e) {
    e.preventDefault();

    var data = {
      action: 'sn_clear_blacklist',
      email: $('#sn-ublock-email').val(),
      _ajax_nonce: wf_sn_cf.nonce
    };

    $('#sn-firewall-blacklist-clear').remove();
    $('#sn-firewall-blacklist').append('<img title="Loading ..." src="' + wf_sn.sn_plugin_url + 'images/ajax-loader.gif" alt="Loading...">');

    $.get(ajaxurl, data, function (response) {
      if (response !== '1') {
        alert('Undocumented error. Page will automatically reload.');
        window.location.reload();
      } else {
        alert('List has been cleared.');
        $('#sn-firewall-blacklist').html('No locally banned IPs');
      }
    }, 'html').fail(function () {
      alert('Undocumented error. Page will automatically reload.');
      window.location.reload();
    });
  });

  // Disable firewall
  $('#sn-disable-firewall').on('click', function () {
    $('#wf_sn_cf_active').val(0);
    $('#sn-firewall-settings-form').submit();
  });

  // Test IP
  $('#wf-cf-do-test-ip').on('click', function (e) {
    e.preventDefault();

    var data = {
      action: 'sn_test_ip',
      ip: $('#wf-cf-ip-test').val(),
      _ajax_nonce: wf_sn_cf.nonce
    };

    $.post(ajaxurl, data, function (response) {
      if (response.data && response.success) {
        jQuery('#wf-cf-do-test-ip-result').html(response.data);
        // alert(response.data);
      } else {
        jQuery('#wf-cf-do-test-ip-result').html(response.data);

        //        alert('An undocumented error has occurred. Page will automatically reload.');
        window.location.reload();
      }
    }, 'json');
  });
});
