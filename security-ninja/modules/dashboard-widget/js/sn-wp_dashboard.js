/* globals jQuery:true, dashboardData:true, ajaxurl:true */
jQuery(document).ready(function($) {
    'use strict';

    /**
     * Fetch RSS feed data via AJAX with proper caching and error handling
     */
    async function fetchRSSFeed() {
        const feedContainer = $('#secnin-dashboard-feed');
        if (!feedContainer.length) {
            return;
        }

        // Show loading state
        feedContainer.empty().append($('<div class="secnin-loading"></div>').text('Loading latest news...'));

        try {
            const response = await $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'secnin_fetch_rss_feed',
                    nonce: dashboardData.nonce || '',
                    limit: 2
                },
                timeout: 10000,
                dataType: 'json'
            });

            if (response.success && response.data && Array.isArray(response.data) && response.data.length > 0) {
                displayRSSFeed(response.data);
            } else {
                feedContainer.hide();
            }
        } catch (error) {
            feedContainer.hide();
        }
    }

    /**
     * Display RSS feed content with proper security measures
     */
    function displayRSSFeed(posts) {
        const feedContainer = $('#secnin-dashboard-feed');
        if (!feedContainer.length) {
            return;
        }

        feedContainer.empty();

        // Create posts list
        const ul = $('<ul class="secnin-rss-list"></ul>');
        
        if (posts && Array.isArray(posts) && posts.length > 0) {
            posts.forEach(post => {
                // Validate post data
                if (!post || typeof post.title !== 'string' || typeof post.link !== 'string') {
                    return;
                }

                const li = $('<li class="secnin-rss-item"></li>');
                
                // Create link with UTM parameters - use text() for security
                const link = $('<a class="secnin-rss-link"></a>')
                    .attr('href', appendUTMParameters(post.link))
                    .attr('target', '_blank')
                    .attr('rel', 'noopener noreferrer')
                    .text(post.title);
                
                li.append(link);
                ul.append(li);
            });
        }
        
        feedContainer.append(ul);

        // Add blog link
        if (dashboardData.blog_link) {
            const blogLink = $('<a class="secnin-blog-link"></a>')
                .attr('href', appendUTMParameters(dashboardData.blog_link))
                .attr('target', '_blank')
                .attr('rel', 'noopener noreferrer')
                .text('Visit wpsecurityninja.com/blog/');
            
            feedContainer.append(blogLink);
        }

        // Show with smooth animation and fade in
        feedContainer.addClass('secnin-rss-feed--visible').fadeIn();
    }

    /**
     * Append UTM parameters to URLs for tracking with proper validation
     */
    function appendUTMParameters(url) {
        if (!url || typeof url !== 'string' || !dashboardData) {
            return url || '';
        }

        // Basic URL validation
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return url;
        }

        const separator = url.includes('?') ? '&' : '?';
        const utmParams = [
            `utm_source=${encodeURIComponent(dashboardData.utm_source || 'security_ninja')}`,
            `utm_medium=${encodeURIComponent(dashboardData.utm_medium || 'plugin')}`,
            `utm_content=${encodeURIComponent(dashboardData.utm_content || 'dashboard_widget')}`,
            `utm_campaign=${encodeURIComponent(dashboardData.utm_campaign || 'security_ninja')}`
        ].join('&');
        
        return url + separator + utmParams;
    }

    // Initialize RSS feed
    fetchRSSFeed();
});
