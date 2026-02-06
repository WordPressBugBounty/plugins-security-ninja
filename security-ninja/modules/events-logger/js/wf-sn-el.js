/* globals jQuery:true, ajaxurl:true, wf_sn_el:true, datatables_object:true */
/*
 * Security Ninja - Events Logger add-on
 * (c) Web factory Ltd, 2015
 * Larsik Corp 2020 - 
 */

jQuery(document).ready(function ($) {
    // Tab switching functionality
    $('#wf-sn-el-subtabs a').on('click', function(e) {
        e.preventDefault();
        
        // Remove active class from all tabs and content
        $('#wf-sn-el-subtabs a').removeClass('nav-tab-active');
        $('.wf-sn-el-subtab').hide();
        
        // Add active class to clicked tab
        $(this).addClass('nav-tab-active');
        
        // Show corresponding content
        var target = $(this).attr('href');
        $(target).show();
    });



    // Initialize DataTable
    eventstable = jQuery('#sn-el-datatable').DataTable({
        "processing": true,
        "serverSide": true,
        "pageLength": 25,
        "ajax": {
            "url": ajaxurl,
            "type": "POST",
            "data": function(d) {
                d.action = "get_events_data";
                d.nonce = datatables_object.nonce;
                d.action_filter = jQuery('#sn-el-action-filter').val();
            },
            "error": function(xhr, error, code) {
                var errorMsg = "<strong>Error loading data:</strong><br>" +
                             "Status: " + xhr.status + " (" + xhr.statusText + ")<br>" +
                             "Error: " + error + "<br>" +
                             "Code: " + code + "<br>" +
                             "Response: " + xhr.responseText;
                jQuery('#datatable-error').html(errorMsg).show();
            }
        },
        "columns": [
            { "data": "timestamp", "title": "Time" },
            { "data": "action", "title": "Action" },
            { "data": "user_id", "title": "User" },
            { "data": "description", "title": "Event" },
            { "data": "details", "title": "Details", "orderable": false }
        ],
        "order": [[ 0, "desc" ]],
        "columnDefs": [{
            "targets": 4,
            "data": null,
            "defaultContent": "<button>Detail</button>"
        }]
    });

    // Load available actions for the filter dropdown
    function loadActionFilter() {
        jQuery.post(ajaxurl, {
            action: 'get_events_actions',
            nonce: datatables_object.nonce
        }, function(response) {
            if (response.success && response.data.actions) {
                var select = jQuery('#sn-el-action-filter');
                select.empty(); // Clear all options including the loading one
                
                // Add "All Actions" option first
                select.append('<option value="">All Actions</option>');
                
                // Add all the action options
                response.data.actions.forEach(function(action) {
                    select.append('<option value="' + action + '">' + action + '</option>');
                });
            }
        });
    }

    // Load actions on page load
    loadActionFilter();

    // Handle action filter change
    jQuery('#sn-el-action-filter').on('change', function() {
        eventstable.ajax.reload();
    });

    // Handle reset filter button
    jQuery('#sn-el-reset-filter').on('click', function() {
        jQuery('#sn-el-action-filter').val('');
        eventstable.ajax.reload();
    });

    // Child rows in the event log table
    // Expand details if available
    $('#sn-el-datatable tbody').on('click', 'button', function (e) {
        e.preventDefault();
        var tr = $(this).closest('tr');
        var row = eventstable.row(tr);
        if (row.child.isShown()) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
            $(this).removeClass('open');
        } else {
            // Open this row
            var details = tr.find('.details-content').html();
            row.child(details).show();
            tr.addClass('shown');
            $(this).addClass('open');
        }
    });

    // truncate log table
    $('#sn-el-truncate').on('click', function (e) {
        e.preventDefault();

        var answer = confirm("Are you sure you want to delete all log entries?"); // @i8n
        if (answer) {
            var data = {
                action: 'sn_el_truncate_log',
                _ajax_nonce: wf_sn_el.nonce
            };
            $.post(ajaxurl, data, function (response) {
                if (!response) {
                    alert('Bad AJAX response. Please reload the page.'); // @i8n
                } else {
                    alert('All log entries have been deleted.'); // @i8n
                    window.location.reload();
                }
            });
        }
    });
});