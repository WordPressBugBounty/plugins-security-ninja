/* globals secnin_ajax: true, jQuery:true */
/**
 * Manual Vulnerability Scan JavaScript
 * Security Ninja Premium
 * 
 * @author  Lars Koudal
 * @since   v0.0.1
 * @version v1.0.0  Friday, January 12th, 2024.
 */

jQuery(document).ready(function($) {
    // Manual vulnerability scan functionality
    $('#secnin-manual-vuln-scan').on('click', function() {
        var $button = $(this);
        var $status = $('#secnin-scan-status');

        // Disable button and show loading
        $button.prop('disabled', true);
        $button.html(secnin_ajax.strings.scanning);
        $status.html(secnin_ajax.strings.scanning_for_vulns).show();

        // Make AJAX request
        $.ajax({
            url: secnin_ajax.ajaxurl,
            type: 'POST',
            data: {
                action: 'secnin_manual_vuln_scan',
                nonce: secnin_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $status.html(secnin_ajax.strings.scan_completed).removeClass('error').addClass('success');
                    
                    // Reload the page after a short delay to show updated results
                    setTimeout(function() {
                        location.reload();
                    }, 1500);
                } else {
                    $status.html(secnin_ajax.strings.scan_failed + ' ' + response.data.message).removeClass('success').addClass('error');
                }
            },
            error: function(response) {
                $status.html(secnin_ajax.strings.scan_failed + ' ' + response.data.message).removeClass('success').addClass('error');
            },
            complete: function() {
                // Re-enable button
                $button.prop('disabled', false);
                $button.html(secnin_ajax.strings.run_scan);
            }
        });
    });

    // Download all vulnerability files functionality
    $('.download-all-vuln-files').on('click', function(e) {
        e.preventDefault();
        
        var $button = $(this);
        var originalText = $button.text();
        
        // Disable button and show loading
        $button.prop('disabled', true);
        $button.html(secnin_ajax.strings.downloading || 'Downloading...');
        
        // Make AJAX request to download all files
        $.ajax({
            url: secnin_ajax.ajaxurl,
            type: 'POST',
            data: {
                action: 'secnin_download_all_vuln_files',
                nonce: secnin_ajax.nonce
            },
            success: function(response) {
                if (response.success) {
                    $button.html(secnin_ajax.strings.download_completed || 'Downloaded!');
                    $button.removeClass('button-primary').addClass('button button-success');
                    
                    // Reload the page after a short delay to show updated status
                    setTimeout(function() {
                        location.reload();
                    }, 1500);
                } else {
                    $button.html(secnin_ajax.strings.download_failed || 'Download Failed');
                    $button.removeClass('button-primary').addClass('button-secondary');
                }
            },
            error: function() {
                $button.html(secnin_ajax.strings.download_failed || 'Download Failed');
                $button.removeClass('button-primary').addClass('button-secondary');
            },
            complete: function() {
                // Re-enable button after a delay
                setTimeout(function() {
                    $button.prop('disabled', false);
                    $button.html(originalText);
                    $button.removeClass('button-secondary button-success').addClass('button-primary');
                }, 2000);
            }
        });
    });
}); 