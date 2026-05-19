/* globals jQuery:true, ajaxurl:true, wf_sn_cf:true, sn_block_ui:true, alert:true */
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
    
    $('#sn-unblock-message').html('<img title="Loading ..." src="' + wf_sn_cf.sn_plugin_url + 'images/ajax-loader.gif" alt="Loading...">');
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

    $('#sn-unblock-message').html('<img title="Loading ..." src="' + wf_sn_cf.sn_plugin_url + 'images/ajax-loader.gif" alt="Loading...">');
    $('#sn-unblock-message').removeClass('sn-unblock-message-bad');
    $('#sn-unblock-message').removeClass('sn-unblock-message-good');

    $.ajax({
      type: 'POST',
      url: ajaxurl,
      data: data,
      dataType: 'json',
      success: function (response) {
        if (response && response.success) {
          $('#sn-unblock-message').html('Email sent successfully.');
          $('#sn-unblock-message').addClass('sn-unblock-message-good');
        } else {
          $('#sn-unblock-message').html('An error occurred and the message could not be sent.');
          $('#sn-unblock-message').addClass('sn-unblock-message-bad');
        }
      },
      error: function () {
        $('#sn-unblock-message').html('An error occurred. The email could not be sent.');
        $('#sn-unblock-message').addClass('sn-unblock-message-bad');
      }
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

  // --- IP Management tab ---
  if ($('#sn-cf-ip-table').length && typeof wf_sn_cf.ip_entries !== 'undefined') {
    var ipMgmt = {
      entries: wf_sn_cf.ip_entries || [],
      perPage: 25,
      page: 1,
      strings: wf_sn_cf.strings || {},
      pendingRemove: null,
      ipRuleMode: null,
      ipRuleOldIp: null,
      loadingCount: 0,

      init: function () {
        var self = this;
        this.renderTable();
        $('#sn-cf-ip-search').on('input', function () {
          self.page = 1;
          self.renderTable();
        });
        $('#sn-cf-add-ip-rule').on('click', function (e) {
          e.preventDefault();
          self.openAddModal();
        });
        $('#sn-cf-copy-blacklisted').on('click', function (e) {
          e.preventDefault();
          self.copyList('blacklisted');
        });
        $('#sn-cf-copy-whitelisted').on('click', function (e) {
          e.preventDefault();
          self.copyList('whitelisted');
        });
        $('#sn-cf-ip-table-body').on('click', '.sn-cf-edit-ip', function (e) {
          e.preventDefault();
          self.openEditModal($(this).data('ip'), $(this).data('list-type'));
        });
        $('#sn-cf-ip-table-body').on('click', '.sn-cf-copy-ip', function (e) {
          e.preventDefault();
          self.copyText($(this).data('ip'));
        });
        $('#sn-cf-ip-table-body').on('click', '.sn-cf-remove-ip', function (e) {
          e.preventDefault();
          self.openRemoveModal($(this).data('ip'), $(this).data('list-type'));
        });
        $('#sn-cf-ip-pagination').on('click', 'button', function (e) {
          e.preventDefault();
          self.page = parseInt($(this).data('page'), 10);
          self.renderTable();
        });
        $('#sn-cf-ip-rule-save').on('click', function (e) {
          e.preventDefault();
          self.submitIpRule();
        });
        $('#sn-cf-ip-rule-cancel, .sn-cf-ip-rule-modal-close').on('click', function (e) {
          e.preventDefault();
          self.closeIpRuleModal();
        });
        $('#sn-cf-ip-rule-modal').on('click', function (e) {
          if ($(e.target).is('#sn-cf-ip-rule-modal')) {
            self.closeIpRuleModal();
          }
        });
        $('#sn-cf-remove-ip-confirm').on('click', function (e) {
          e.preventDefault();
          self.confirmRemove();
        });
        $('#sn-cf-remove-ip-cancel, .sn-cf-remove-ip-modal-close').on('click', function (e) {
          e.preventDefault();
          self.closeRemoveModal();
        });
        $('#sn-cf-remove-ip-modal').on('click', function (e) {
          if ($(e.target).is('#sn-cf-remove-ip-modal')) {
            self.closeRemoveModal();
          }
        });
        $(document).on('keydown.snCfIpModals', function (e) {
          if ($('#sn-cf-ip-rule-modal').is(':visible')) {
            if (e.key === 'Escape') {
              e.preventDefault();
              self.closeIpRuleModal();
            }
            if (e.key === 'Enter' && !$(e.target).is('textarea')) {
              e.preventDefault();
              self.submitIpRule();
            }
            return;
          }
          if (!$('#sn-cf-remove-ip-modal').is(':visible')) {
            return;
          }
          if (e.key === 'Escape') {
            e.preventDefault();
            self.closeRemoveModal();
          }
          if (e.key === 'Enter') {
            e.preventDefault();
            self.confirmRemove();
          }
        });
      },

      filteredEntries: function () {
        var search = ($('#sn-cf-ip-search').val() || '').toLowerCase().trim();
        return this.entries.filter(function (entry) {
          if (search && entry.ip.toLowerCase().indexOf(search) === -1) {
            return false;
          }
          return true;
        });
      },

      renderTable: function () {
        var filtered = this.filteredEntries();
        var totalPages = Math.max(1, Math.ceil(filtered.length / this.perPage));
        if (this.page > totalPages) {
          this.page = totalPages;
        }
        var start = (this.page - 1) * this.perPage;
        var pageEntries = filtered.slice(start, start + this.perPage);
        var $body = $('#sn-cf-ip-table-body');
        $body.empty();

        if (!pageEntries.length) {
          $body.append(
            '<tr class="sn-cf-ip-empty"><td colspan="4">' +
              (this.strings.no_entries || 'No IP entries match your filters.') +
              '</td></tr>'
          );
        } else {
          var self = this;
          pageEntries.forEach(function (entry) {
            $body.append(self.rowHtml(entry));
          });
        }

        this.renderPagination(filtered.length, totalPages);

        if (this.loadingCount > 0) {
          $('#sn-cf-ip-table-body button, #sn-cf-ip-pagination button').prop('disabled', true);
        }
      },

      detailsHtml: function (entry) {
        var sources = (entry.sources || []).join(', ');
        var lines =
          '<span class="sn-cf-ip-detail-line"><strong>' +
          (this.strings.source_label || 'Source:') +
          '</strong> ' +
          this.escapeHtml(sources) +
          '</span>' +
          '<span class="sn-cf-ip-detail-line"><strong>' +
          (this.strings.expires_label || 'Expires:') +
          '</strong> ' +
          this.escapeHtml(entry.expires_text || '') +
          '</span>' +
          '<span class="sn-cf-ip-detail-line"><strong>' +
          (this.strings.last_visit_label || 'Last visit:') +
          '</strong> ' +
          this.escapeHtml(entry.last_visit_text || '—') +
          '</span>';
        return '<div class="sn-cf-ip-details">' + lines + '</div>';
      },

      rowHtml: function (entry) {
        var statusClass =
          entry.status === 'whitelisted'
            ? 'sn-cf-status-whitelisted'
            : 'sn-cf-status-blacklisted';
        var statusLabel =
          entry.status === 'whitelisted'
            ? this.strings.status_whitelisted || 'Whitelisted'
            : this.strings.status_blacklisted || 'Blacklisted';
        var copyLabel = this.strings.copy_ip || 'Copy IP';
        var editLabel = this.strings.edit || 'Edit';
        var removeLabel = this.strings.remove || 'Remove';
        var editBtn = '';
        var removeBtn = '';
        if (entry.editable && entry.list_type) {
          editBtn =
            '<button type="button" class="button button-small sn-cf-icon-btn sn-cf-edit-ip" data-ip="' +
            this.escapeAttr(entry.ip) +
            '" data-list-type="' +
            this.escapeAttr(entry.list_type) +
            '" title="' +
            this.escapeAttr(editLabel) +
            '" aria-label="' +
            this.escapeAttr(editLabel) +
            '"><span class="dashicons dashicons-edit" aria-hidden="true"></span></button>';
          removeBtn =
            '<button type="button" class="button button-small sn-cf-icon-btn sn-cf-remove-ip" data-ip="' +
            this.escapeAttr(entry.ip) +
            '" data-list-type="' +
            this.escapeAttr(entry.list_type) +
            '" title="' +
            this.escapeAttr(removeLabel) +
            '" aria-label="' +
            this.escapeAttr(removeLabel) +
            '"><span class="dashicons dashicons-trash" aria-hidden="true"></span></button>';
        }
        return (
          '<tr class="sn-cf-ip-row" data-ip="' +
          this.escapeAttr(entry.ip) +
          '" data-status="' +
          this.escapeAttr(entry.status) +
          '">' +
          '<td class="column-ip"><code class="sn-cf-ip-address">' +
          this.escapeHtml(entry.ip) +
          '</code></td>' +
          '<td class="column-status"><span class="sn-cf-status-badge ' +
          statusClass +
          '">' +
          statusLabel +
          '</span></td>' +
          '<td class="column-details">' +
          this.detailsHtml(entry) +
          '</td>' +
          '<td class="column-actions sn-cf-ip-row-actions">' +
          editBtn +
          '<button type="button" class="button button-small sn-cf-icon-btn sn-cf-copy-ip" data-ip="' +
          this.escapeAttr(entry.ip) +
          '" title="' +
          this.escapeAttr(copyLabel) +
          '" aria-label="' +
          this.escapeAttr(copyLabel) +
          '"><span class="dashicons dashicons-admin-page" aria-hidden="true"></span></button>' +
          removeBtn +
          '</td></tr>'
        );
      },

      renderPagination: function (total, totalPages) {
        var $pag = $('#sn-cf-ip-pagination');
        $pag.empty();
        if (totalPages <= 1) {
          return;
        }

        var $wrap = $('<div class="sn-cf-ip-pagination-pages" role="navigation" aria-label="IP list pagination"></div>');
        var self = this;

        if (this.page > 1) {
          $wrap.append(
            $('<button type="button" class="button sn-cf-ip-page-nav"></button>')
              .attr('data-page', this.page - 1)
              .html('&larr; ' + (this.strings.prev || 'Prev'))
          );
        }

        for (var p = 1; p <= totalPages; p++) {
          var $btn = $('<button type="button" class="button sn-cf-ip-page-num"></button>')
            .attr('data-page', p)
            .text(String(p));
          if (p === this.page) {
            $btn.addClass('sn-cf-ip-page-current');
          }
          $wrap.append($btn);
        }

        if (this.page < totalPages) {
          $wrap.append(
            $('<button type="button" class="button sn-cf-ip-page-nav"></button>')
              .attr('data-page', this.page + 1)
              .html((this.strings.next || 'Next') + ' &rarr;')
          );
        }

        $pag.append($wrap);
      },

      setEntries: function (entries) {
        this.entries = entries || [];
        this.renderTable();
      },

      showNotice: function (message, isError) {
        var $n = $('#sn-cf-ip-notice');
        $n.text(message || '').toggleClass('sn-cf-ip-notice-error', !!isError);
      },

      setLoading: function (isLoading) {
        if (isLoading) {
          this.loadingCount += 1;
        } else {
          this.loadingCount = Math.max(0, this.loadingCount - 1);
        }
        var busy = this.loadingCount > 0;
        var $wrap = $('#sn-cf-ip-table-wrap');
        $wrap.toggleClass('sn-cf-ip-table-wrap--loading', busy);
        $('#sn-cf-ip-table-loading').attr('aria-hidden', busy ? 'false' : 'true').prop('hidden', !busy);
        $('#sn-cf-ip-table').attr('aria-busy', busy ? 'true' : 'false');
        $('#sn-cf-ip-search').prop('disabled', busy);
        $('#sn-cf-add-ip-rule').prop('disabled', busy);
        $('#sn-cf-ip-table-body button, #sn-cf-ip-pagination button').prop('disabled', busy);
      },

      handleEntriesResponse: function (response, fallbackError) {
        if (response && response.success && response.data && response.data.data) {
          this.setEntries(response.data.data.entries);
          this.showNotice(response.data.message || 'Saved.');
          return true;
        }
        this.showNotice(
          (response && response.data && response.data.message) || fallbackError,
          true
        );
        return false;
      },

      postEntriesAction: function (postData, fallbackError) {
        var self = this;
        this.setLoading(true);
        return $.post(ajaxurl, postData, null, 'json')
          .done(function (response) {
            self.handleEntriesResponse(response, fallbackError);
          })
          .fail(function () {
            self.showNotice(fallbackError, true);
          })
          .always(function () {
            self.setLoading(false);
          });
      },

      copyList: function (status) {
        var listType = status === 'blacklisted' ? 'blacklist' : 'whitelist';
        var ips = this.entries
          .filter(function (e) {
            return e.editable && e.list_type === listType;
          })
          .map(function (e) {
            return e.ip;
          });
        var host = wf_sn_cf.site_host || window.location.hostname;
        var label =
          status === 'blacklisted' ? 'Blacklisted IPs' : 'Whitelisted IPs';
        var header = '# WP Security Ninja - ' + label + ' (' + host + ')\n';
        this.copyText(header + ips.join('\n'));
      },

      copyText: function (text) {
        var self = this;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            self.showNotice(self.strings.copied || 'Copied to clipboard.');
          }).catch(function () {
            self.fallbackCopy(text);
          });
        } else {
          self.fallbackCopy(text);
        }
      },

      fallbackCopy: function (text) {
        var $ta = $('<textarea>').val(text).appendTo('body').select();
        try {
          document.execCommand('copy');
          this.showNotice(this.strings.copied || 'Copied to clipboard.');
        } catch (err) {
          this.showNotice(this.strings.copy_failed || 'Could not copy.', true);
        }
        $ta.remove();
      },

      openAddModal: function () {
        this.ipRuleMode = 'add';
        this.ipRuleOldIp = null;
        $('#sn-cf-ip-rule-modal-title').text(this.strings.add_rule || 'Add IP rule');
        $('#sn-cf-ip-rule-bulk-wrap').show();
        $('#sn-cf-ip-rule-edit-wrap').hide();
        $('#sn-cf-ip-rule-textarea').val('');
        $('#sn-cf-ip-rule-input').val('');
        $('input[name="sn_cf_ip_rule_list_type"][value="blacklist"]').prop('checked', true);
        $('#sn-cf-ip-rule-modal').show();
        window.setTimeout(function () {
          $('#sn-cf-ip-rule-textarea').trigger('focus');
        }, 0);
      },

      openEditModal: function (ip, listType) {
        this.ipRuleMode = 'edit';
        this.ipRuleOldIp = ip;
        $('#sn-cf-ip-rule-modal-title').text(this.strings.edit_rule || 'Edit IP rule');
        $('#sn-cf-ip-rule-bulk-wrap').hide();
        $('#sn-cf-ip-rule-edit-wrap').show();
        $('#sn-cf-ip-rule-textarea').val('');
        $('#sn-cf-ip-rule-input').val(ip);
        $('input[name="sn_cf_ip_rule_list_type"][value="' + listType + '"]').prop('checked', true);
        $('#sn-cf-ip-rule-modal').show();
        window.setTimeout(function () {
          $('#sn-cf-ip-rule-input').trigger('focus');
        }, 0);
      },

      closeIpRuleModal: function () {
        this.ipRuleMode = null;
        this.ipRuleOldIp = null;
        $('#sn-cf-ip-rule-modal').hide();
        $('#sn-cf-ip-rule-textarea').blur();
        $('#sn-cf-ip-rule-input').blur();
      },

      submitIpRule: function () {
        var listType = $('input[name="sn_cf_ip_rule_list_type"]:checked').val();
        var self = this;
        var postData = {
          list_type: listType,
          _ajax_nonce: wf_sn_cf.nonce
        };

        if (this.ipRuleMode === 'edit' && this.ipRuleOldIp) {
          var ip = ($('#sn-cf-ip-rule-input').val() || '').trim();
          if (!ip) {
            this.showNotice(
              this.strings.invalid_ip || 'Please enter a valid IP address or CIDR range.',
              true
            );
            return;
          }
          postData.action = 'sn_cf_edit_ip_rule';
          postData.ip = ip;
          postData.old_ip = this.ipRuleOldIp;
        } else {
          var ips = $('#sn-cf-ip-rule-textarea').val() || '';
          if (!ips.trim()) {
            this.showNotice(
              this.strings.invalid_ip || 'Please enter a valid IP address or CIDR range.',
              true
            );
            return;
          }
          postData.action = 'sn_cf_bulk_add_ip_rules';
          postData.ips = ips;
        }

        this.closeIpRuleModal();
        this.postEntriesAction(postData, 'Request failed.');
      },

      openRemoveModal: function (ip, listType) {
        var listLabel =
          listType === 'whitelist'
            ? this.strings.list_whitelist || 'whitelist'
            : this.strings.list_blacklist || 'blacklist';
        var template = this.strings.remove_confirm || 'Remove %1$s from the %2$s?';
        var message = template.replace('%1$s', ip).replace('%2$s', listLabel);

        var currentIp = $('#sn-cf-current-user-ip').val();
        if (listType === 'whitelist' && currentIp && ip === currentIp) {
          message +=
            '<br><br><strong>' +
            (this.strings.confirm_remove_ip ||
              'Removing your current IP from the whitelist may lock you out.') +
            '</strong>';
        }

        this.pendingRemove = { ip: ip, listType: listType };
        $('#sn-cf-remove-ip-message').html(message);
        $('#sn-cf-remove-ip-modal').show();
        window.setTimeout(function () {
          $('#sn-cf-remove-ip-confirm').trigger('focus');
        }, 0);
      },

      closeRemoveModal: function () {
        this.pendingRemove = null;
        $('#sn-cf-remove-ip-modal').hide();
        $('#sn-cf-remove-ip-confirm').blur();
      },

      confirmRemove: function () {
        if (!this.pendingRemove) {
          return;
        }
        var ip = this.pendingRemove.ip;
        var listType = this.pendingRemove.listType;
        var self = this;
        this.closeRemoveModal();
        this.postEntriesAction(
          {
            action: 'sn_cf_remove_ip_rule',
            ip: ip,
            list_type: listType,
            _ajax_nonce: wf_sn_cf.nonce
          },
          'Could not remove IP.'
        );
      },

      escapeHtml: function (str) {
        return $('<div/>').text(str).html();
      },

      escapeAttr: function (str) {
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/"/g, '&quot;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
      }
    };

    ipMgmt.init();
  }
});
