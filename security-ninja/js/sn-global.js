/* globals jQuery:true, ajaxurl:true, wf_sn:true */
/* Functions are loaded on Security Ninja WP admin pages */


/* Loads the latest events (if any) in the sidebar */
jQuery(document).ready(function($) {


jQuery(document).on('click', '.secnin-welcome-notice .closeme', function() {
  jQuery('.secnin-welcome-notice').slideUp();
});

});

