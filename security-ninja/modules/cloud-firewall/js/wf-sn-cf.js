/* globals jQuery:true, ajaxurl:true, wf_sn_cf:true, sn_block_ui:true, alert:true, confirm:true */
/*
* Security Ninja PRO
* (c) 2018. Web factory Ltd
*/

jQuery(document).ready(function ($) {

  // Firewall subtabs are initialized in sn-global.js (no Select2 dependency).

  // Function to toggle sub-inputs
  function toggleSubInputs(checkbox, subInputClass) {
    if (checkbox.is(':checked')) {
        $(subInputClass).removeClass('sn-disabled');
    } else {
        $(subInputClass).addClass('sn-disabled');
    }
  }



  // Select all countries button. type="button" so Enter in other fields does not fire this.
  $('#select_all_countries').click(function (e) {
    e.preventDefault();
    var message = (wf_sn_cf.strings && wf_sn_cf.strings.block_all_countries) ? wf_sn_cf.strings.block_all_countries : 'Block all countries?';
    if (!window.confirm(message)) {
      return;
    }
    $('#wf_sn_cf_blocked_countries_confirm_all').val('1');
    $('#wf_sn_cf_blocked_countries option').prop('selected', true);
    $('#wf_sn_cf_blocked_countries').trigger('change');
  });

  $('#select_no_countries').click(function (e) {
    e.preventDefault();
    $('#wf_sn_cf_blocked_countries_confirm_all').val('0');
    $('#wf_sn_cf_blocked_countries option').prop('selected', false);
    $('#wf_sn_cf_blocked_countries').trigger('change');
  });

  $('#wf-cf-ip-test').on('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      $('#wf-cf-do-test-ip').trigger('click');
    }
  });

  $('#sn-cf-ip-search').on('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
    }
  });

  $('#wf_sn_cf_ip_source').on('change', function () {
    var $selected = $(this).find('option:selected');
    var desc = $selected.data('desc') || '';
    $('#wf_sn_cf_ip_source_desc').text(desc);
    $('.sn-cf-ip-source-preview-table tbody tr').removeClass('is-selected');
    $('.sn-cf-ip-source-preview-table tbody tr').eq(this.selectedIndex).addClass('is-selected');
  });

  $('#sn_cf').on('click', '.testresults h3', function (e) {
    e.preventDefault();
    $(this).parents('.testresults').toggleClass('opened').find('table');
  });

  // Select2 on country dropdown (guard: some themes deregister the global select2 handle).
  var $blockedCountries = $('#wf_sn_cf_blocked_countries');
  if ($blockedCountries.length && $.fn.select2) {
    $blockedCountries.select2({
      multiple: true,
      dropdownAutoWidth: true,
      closeOnSelect: false,
      theme: 'classic',
      dropdownParent: $blockedCountries.closest('#sn_cf_settings').length ? $blockedCountries.closest('#sn_cf_settings') : $(document.body)
    });
  }

  // Show enable-firewall dialog
  $('#sn-enable-firewall-overlay').on('click', function (e) {
    e.preventDefault();
    var $host = $('#sn-firewall-modal');
    var panel = $host.find('.sn-modal-content').get(0);
    if (!panel || typeof SnDialog === 'undefined') {
      $host.show();
      return;
    }
    SnDialog.open({
      hideTitle: true,
      bodyNode: panel,
      buttons: false,
      onClose: function () {
        $host.append(panel);
      }
    });
  });

  // Close enable-firewall dialog
  $(document).on('click', '.sn-modal-close', function () {
    if (typeof SnDialog !== 'undefined') {
      SnDialog.close();
    }
    $('#sn-firewall-modal').hide();
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
        $('#sn-cf-remove-ip-confirm').on('click', function (e) {
          e.preventDefault();
          self.confirmRemove();
        });
        $('#sn-cf-remove-ip-cancel, .sn-cf-remove-ip-modal-close').on('click', function (e) {
          e.preventDefault();
          self.closeRemoveModal();
        });
        $(document).on('keydown.snCfIpModals', function (e) {
          if (!self.ipRuleMode) {
            return;
          }
          if (e.key === 'Escape') {
            e.preventDefault();
            self.closeIpRuleModal();
          }
          if (e.key === 'Enter' && !$(e.target).is('textarea')) {
            e.preventDefault();
            self.submitIpRule();
          }
        });
      },

      filteredEntries: function () {
        var search = ($('#sn-cf-ip-search').val() || '').toLowerCase().trim();
        return this.entries.filter(function (entry) {
          if (!search) {
            return true;
          }
          if (entry.ip.toLowerCase().indexOf(search) !== -1) {
            return true;
          }
          if (entry.note && String(entry.note).toLowerCase().indexOf(search) !== -1) {
            return true;
          }
          return false;
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
          this.escapeHtml(entry.last_visit_text || '-') +
          '</span>';
        if (entry.note) {
          lines +=
            '<span class="sn-cf-ip-detail-line"><strong>' +
            (this.strings.note_label || 'Note:') +
            '</strong> ' +
            this.escapeHtml(entry.note) +
            '</span>';
        }
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
        $('#sn-cf-ip-rule-note').val('');
        $('input[name="sn_cf_ip_rule_list_type"][value="blacklist"]').prop('checked', true);
        this.showIpRuleDialog();
        window.setTimeout(function () {
          $('#sn-cf-ip-rule-textarea').trigger('focus');
        }, 0);
      },

      openEditModal: function (ip, listType) {
        this.ipRuleMode = 'edit';
        this.ipRuleOldIp = ip;
        var existing = null;
        for (var i = 0; i < this.entries.length; i++) {
          if (this.entries[i].ip === ip) {
            existing = this.entries[i];
            break;
          }
        }
        $('#sn-cf-ip-rule-modal-title').text(this.strings.edit_rule || 'Edit IP rule');
        $('#sn-cf-ip-rule-bulk-wrap').hide();
        $('#sn-cf-ip-rule-edit-wrap').show();
        $('#sn-cf-ip-rule-textarea').val('');
        $('#sn-cf-ip-rule-input').val(ip);
        $('#sn-cf-ip-rule-note').val(existing && existing.note ? existing.note : '');
        $('input[name="sn_cf_ip_rule_list_type"][value="' + listType + '"]').prop('checked', true);
        this.showIpRuleDialog();
        window.setTimeout(function () {
          $('#sn-cf-ip-rule-input').trigger('focus');
        }, 0);
      },

      showIpRuleDialog: function () {
        var $host = $('#sn-cf-ip-rule-modal');
        var panel = $host.find('.sn-modal-content').get(0);
        if (!panel || typeof SnDialog === 'undefined') {
          $host.show();
          return;
        }
        var self = this;
        SnDialog.open({
          hideTitle: true,
          bodyNode: panel,
          buttons: false,
          onClose: function () {
            $host.append(panel);
            self.ipRuleMode = null;
            self.ipRuleOldIp = null;
          }
        });
      },

      closeIpRuleModal: function () {
        this.ipRuleMode = null;
        this.ipRuleOldIp = null;
        if (typeof SnDialog !== 'undefined') {
          SnDialog.close();
        }
        $('#sn-cf-ip-rule-modal').hide();
        $('#sn-cf-ip-rule-textarea').blur();
        $('#sn-cf-ip-rule-input').blur();
        $('#sn-cf-ip-rule-note').blur();
      },

      submitIpRule: function () {
        var listType = $('input[name="sn_cf_ip_rule_list_type"]:checked').val();
        var note = ($('#sn-cf-ip-rule-note').val() || '').trim();
        var self = this;
        var postData = {
          list_type: listType,
          note: note,
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
            '\n\n' +
            (this.strings.confirm_remove_ip ||
              'Removing your current IP from the whitelist may lock you out.');
        }

        this.pendingRemove = { ip: ip, listType: listType };
        var self = this;
        SnDialog.confirm({
          title: this.strings.remove_title || 'Remove IP rule',
          message: message,
          danger: true,
          confirmText: this.strings.remove || 'Remove'
        }).then(function (ok) {
          if (!ok) {
            self.pendingRemove = null;
            return;
          }
          self.confirmRemove();
        });
      },

      closeRemoveModal: function () {
        this.pendingRemove = null;
        if (typeof SnDialog !== 'undefined') {
          SnDialog.close();
        }
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

  // Early Firewall (beta) AJAX controls.
  function secninWafExtendedMsg(text, isError) {
    var $el = $('#secnin-waf-extended-msg');
    if (!$el.length) {
      return;
    }
    $el.text(text || '');
    $el.css('color', isError ? '#b32d2e' : '');
  }

  function secninWafExtendedFailMessage(xhr, fallback) {
    var msg = '';
    if (xhr && xhr.responseJSON) {
      if (xhr.responseJSON.data && xhr.responseJSON.data.message) {
        msg = xhr.responseJSON.data.message;
      } else if (xhr.responseJSON.message) {
        msg = xhr.responseJSON.message;
      }
    }
    if (!msg && xhr && typeof xhr.responseText === 'string' && xhr.responseText) {
      var text = xhr.responseText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      if (text && text.length < 300 && text.indexOf('{') !== 0) {
        msg = text;
      } else {
        try {
          var parsed = JSON.parse(xhr.responseText);
          if (parsed && parsed.data && parsed.data.message) {
            msg = parsed.data.message;
          }
        } catch (e) {
          // ignore
        }
      }
    }
    if (!msg && xhr && xhr.status) {
      msg = fallback + ' (HTTP ' + xhr.status + ')';
    }
    return msg || fallback;
  }

  function secninWafExtendedPost(action, extra) {
    var data = $.extend(
      {
        action: action,
        _ajax_nonce: wf_sn_cf.nonce
      },
      extra || {}
    );
    return $.ajax({
      url: ajaxurl,
      type: 'POST',
      dataType: 'json',
      data: data
    });
  }

  var secninWafVerifyTimer = null;
  var secninWafBusy = false;

  function secninWafBusyButtons(busy) {
    secninWafBusy = !!busy;
    $('#secnin-waf-spinner').toggleClass('is-active', secninWafBusy);
    $('#secnin-waf-install, #secnin-waf-verify, #secnin-waf-uninstall').prop('disabled', secninWafBusy);
    if (!secninWafBusy && $('#secnin-waf-verify').is(':visible') && $('#secnin-waf-verify').data('secnin-not-ready')) {
      $('#secnin-waf-verify').prop('disabled', true);
    }
  }

  function secninWafStrings() {
    return (wf_sn_cf && wf_sn_cf.waf_strings) ? wf_sn_cf.waf_strings : {};
  }

  function secninWafWarnUnsaved() {
    var $form = $('#wf_sn_cf_form, form#sn_cf_form, form[name="wf_sn_cf"]').first();
    if (!$form.length) {
      return false;
    }
    return !!$form.data('secnin-dirty');
  }

  function secninWafScheduleVerifyReady(ui) {
    if (secninWafVerifyTimer) {
      window.clearTimeout(secninWafVerifyTimer);
      secninWafVerifyTimer = null;
    }
    if (!ui || !ui.show_verify || ui.verify_ready) {
      return;
    }
    var readyAt = parseInt(ui.ready_at, 10) || 0;
    if (readyAt <= 0) {
      return;
    }
    var waitMs = Math.max(0, (readyAt * 1000) - Date.now());
    secninWafVerifyTimer = window.setTimeout(function () {
      $('#secnin-waf-verify').data('secnin-not-ready', false);
      if (!secninWafBusy) {
        $('#secnin-waf-verify').prop('disabled', false);
      }
    }, waitMs);
  }

  function secninWafApplyUi(ui, fallbackMessage, fallbackError) {
    if (!ui) {
      secninWafBusyButtons(false);
      if (fallbackMessage) {
        secninWafExtendedMsg(fallbackMessage, !!fallbackError);
      }
      return;
    }

    $('#secnin-waf-mode-label').text(ui.mode_label || '');
    $('#secnin-waf-status-label').text(ui.status_label || '');

    if (ui.prepend) {
      $('#secnin-waf-prepend-path').text(ui.prepend).prop('hidden', false);
      $('#secnin-waf-prepend-label').text(ui.prepend_label || '').prop('hidden', !ui.prepend_label);
      $('#secnin-waf-prepend-empty').prop('hidden', true);
    } else {
      $('#secnin-waf-prepend-path').prop('hidden', true);
      $('#secnin-waf-prepend-label').prop('hidden', true);
      $('#secnin-waf-prepend-empty').prop('hidden', false);
    }

    if (ui.last_verify) {
      $('#secnin-waf-last-verify-value').text(ui.last_verify);
      $('#secnin-waf-last-verify-row').prop('hidden', false);
    } else {
      $('#secnin-waf-last-verify-row').prop('hidden', true);
    }

    if (ui.detail) {
      $('#secnin-waf-detail-label').text(ui.detail_label || '');
      $('#secnin-waf-detail-value').text(ui.detail);
      $('#secnin-waf-detail-row').prop('hidden', false);
    } else {
      $('#secnin-waf-detail-row').prop('hidden', true);
    }

    if (ui.status === 'failed_safe' && ui.detail) {
      $('#secnin-waf-error').prop('hidden', false).find('p').text(ui.detail);
    } else if (ui.status !== 'failed_safe') {
      $('#secnin-waf-error').prop('hidden', true);
    }

    $('#secnin-waf-install').prop('hidden', !ui.show_enable);
    $('#secnin-waf-verify').prop('hidden', !ui.show_verify).text(ui.verify_label || 'Verify').attr('data-ready-at', ui.ready_at || 0);
    $('#secnin-waf-uninstall').prop('hidden', !ui.show_disable);
    $('#secnin-waf-verify').data('secnin-not-ready', !!(ui.show_verify && !ui.verify_ready));

    secninWafBusyButtons(false);
    secninWafScheduleVerifyReady(ui);
    secninWafExtendedMsg(ui.message || fallbackMessage || '', !!(ui.message_is_error || fallbackError));

    if (ui.installed) {
      $('[data-dismissible="secnin-early-firewall-notice-forever"]').hide();
    }
  }

  function secninWafHandleResponse(resp, fallbackOk, fallbackErr) {
    var data = resp && resp.data ? resp.data : {};
    var ui = data.ui || null;
    if (resp && resp.success) {
      secninWafApplyUi(ui, (data && data.message) ? data.message : fallbackOk, false);
      return;
    }
    secninWafApplyUi(ui, (data && data.message) ? data.message : fallbackErr, true);
  }

  $('form').filter(function () {
    return $(this).find('[name^="wf_sn_cf"]').length > 0;
  }).on('change input', 'input, select, textarea', function () {
    $(this).closest('form').data('secnin-dirty', true);
  });

  function secninWafDoInstall(wafAction) {
    var s = secninWafStrings();
    secninWafBusyButtons(true);
    secninWafExtendedMsg(s.installing || 'Installing…');
    secninWafExtendedPost('sn_waf_extended_install', { waf_action: wafAction })
      .done(function (resp) {
        secninWafHandleResponse(resp, s.installed || 'Installed.', s.install_failed || 'Install failed.');
      })
      .fail(function (xhr) {
        secninWafBusyButtons(false);
        secninWafExtendedMsg(secninWafExtendedFailMessage(xhr, s.install_request_failed || 'Install request failed.'), true);
      });
  }

  $('#secnin-waf-install').on('click', function (e) {
    e.preventDefault();
    var $btn = $(this);
    var wafAction = $btn.data('action') || 'chain';
    var prepend = $btn.data('prepend') || '';
    var s = secninWafStrings();

    if (secninWafWarnUnsaved()) {
      secninWafExtendedMsg(s.unsaved_warning || 'You have unsaved firewall form changes.', true);
    }

    if (wafAction === 'confirm_non_waf') {
      var msg = (s.confirm_chain || 'Enable Early Firewall and chain this existing prepend file?') +
        (prepend ? ('\n\n' + prepend) : '');
      if (typeof SnDialog !== 'undefined' && SnDialog.confirm) {
        SnDialog.confirm({
          title: s.confirm_title || 'Confirm chaining',
          message: msg,
          confirmText: s.confirm_ok || 'Enable',
          cancelText: s.confirm_cancel || 'Cancel'
        }).then(function (ok) {
          if (ok) {
            secninWafDoInstall('confirm_non_waf');
          }
        });
        return;
      }
      if (!window.confirm(msg)) {
        return;
      }
    }
    secninWafDoInstall(wafAction);
  });

  $('#secnin-waf-verify').on('click', function (e) {
    e.preventDefault();
    if ($(this).data('secnin-not-ready')) {
      return;
    }
    var s = secninWafStrings();
    secninWafBusyButtons(true);
    secninWafExtendedMsg(s.verifying || 'Verifying…');
    secninWafExtendedPost('sn_waf_extended_verify')
      .done(function (resp) {
        secninWafHandleResponse(resp, s.verified || 'Verified.', s.verify_failed || 'Verify failed.');
      })
      .fail(function (xhr) {
        secninWafBusyButtons(false);
        secninWafExtendedMsg(secninWafExtendedFailMessage(xhr, s.verify_request_failed || 'Verify request failed.'), true);
      });
  });

  $('#secnin-waf-uninstall').on('click', function (e) {
    e.preventDefault();
    var s = secninWafStrings();
    secninWafBusyButtons(true);
    secninWafExtendedMsg(s.disabling || 'Disabling…');
    secninWafExtendedPost('sn_waf_extended_uninstall')
      .done(function (resp) {
        secninWafHandleResponse(resp, s.disabled || 'Disabled.', s.disable_failed || 'Disable failed.');
      })
      .fail(function (xhr) {
        secninWafBusyButtons(false);
        secninWafExtendedMsg(secninWafExtendedFailMessage(xhr, s.disable_request_failed || 'Disable request failed.'), true);
      });
  });

  (function initEarlyFirewallPanel() {
    var $verify = $('#secnin-waf-verify');
    if (!$verify.length || $verify.prop('hidden')) {
      return;
    }
    var readyAt = parseInt($verify.attr('data-ready-at'), 10) || 0;
    var notReady = !!$verify.prop('disabled') || (readyAt > 0 && Date.now() < readyAt * 1000);
    $verify.data('secnin-not-ready', notReady);
    if (notReady) {
      secninWafScheduleVerifyReady({
        show_verify: true,
        verify_ready: false,
        ready_at: readyAt
      });
    }
  })();
});
