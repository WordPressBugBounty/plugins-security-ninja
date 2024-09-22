/* globals jQuery:true, dashboardData:true */
jQuery(document).ready(function($) {
    async function fetchRSSFeed() {
        const cacheKey = 'rss_feed_cache';
        const cacheExpiry = 259200000; // 3 days in milliseconds
        const now = new Date().getTime();

        const cachedData = localStorage.getItem(cacheKey);
        const cachedTime = localStorage.getItem(cacheKey + '_time');

        if (cachedData && cachedTime && now - cachedTime < cacheExpiry) {
            displayRSSFeed(JSON.parse(cachedData));
            return;
        }

        try {
            const response = await fetch('https://secnin.b-cdn.net/feed/?limit=2');
            if (!response.ok) {
                throw new Error(`Network response was not ok. Status: ${response.status}`);
            }
            const data = await response.text();
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(data, "text/xml");

            const items = xmlDoc.getElementsByTagName('item');
            const latestPosts = [];
            for (let i = 0; i < Math.min(2, items.length); i++) {
                const title = items[i].getElementsByTagName('title')[0].textContent;
                const link = items[i].getElementsByTagName('link')[0].textContent;
                const description = items[i].getElementsByTagName('description')[0].textContent;

                const div = document.createElement('div');
                div.innerHTML = description;
                const textContent = div.textContent || div.innerText || "";
                const excerpt = textContent.replace(/<[^>]+>/g, '').substring(0, 255) + '...';

                latestPosts.push({ title, link, excerpt });
            }

            localStorage.setItem(cacheKey, JSON.stringify(latestPosts));
            localStorage.setItem(cacheKey + '_time', now);

            displayRSSFeed(latestPosts);
        } catch (error) {
            console.error('Error fetching RSS feed:', error);
            displayErrorMessage(error);
        }
    }

    function displayRSSFeed(posts) {
        const feedContainer = $('#secnin-dashboard-feed');
        if (!feedContainer.length) {
            console.error('Feed container not found');
            return;
        }

        feedContainer.empty();

        const hr = $('<hr>');
        feedContainer.append(hr);

        const headline = $('<h3><strong></strong></h3>').html(`<strong>${dashboardData.headline}</strong>`);
        feedContainer.append(headline);

        const ul = $('<ul>');
        ul.addClass('wp-block-latest-posts');
        posts.forEach(post => {
            const li = $('<li>');
            li.addClass('wp-block-latest-posts__list-item');
            const link = $('<a>').attr('href', appendUTMParameters(post.link)).attr('target', '_blank').text(post.title);
            const excerpt = $('<p>').text(post.excerpt).addClass('wp-block-latest-posts__excerpt');
            li.append(link);
            li.append(excerpt);
            ul.append(li);
        });
        feedContainer.append(ul);

        const blogLink = $('<a>').attr('href', appendUTMParameters(dashboardData.blog_link)).attr('target', '_blank').text(' Visit wpsecurityninja.com/blog/');
        blogLink.addClass('wp-block-button__link');
        feedContainer.append(blogLink);
    }

    function appendUTMParameters(url) {
        const separator = url.includes('?') ? '&' : '?';
        const utmParams = `${separator}utm_source=${dashboardData.utm_source}&utm_medium=${dashboardData.utm_medium}&utm_content=${dashboardData.utm_content}&utm_campaign=${dashboardData.utm_campaign}`;
        return url + utmParams;
    }

    function displayErrorMessage(error) {
        const feedContainer = $('#secnin-dashboard-feed');
        if (!feedContainer.length) {
            console.error('Feed container not found');
            return;
        }

        feedContainer.empty();

        const errorMessage = $('<p>').text('Unable to fetch the latest posts.');
        const errorDetails = $('<p>').text(`Error: ${error.message}`);
        const blogLink = $('<a>').attr('href', appendUTMParameters(dashboardData.blog_link)).attr('target', '_blank').text(' Visit wpsecurityninja.com/blog/');
        blogLink.addClass('wp-block-button__link');
        
        feedContainer.append(errorMessage);
        feedContainer.append(errorDetails);
        feedContainer.append(blogLink);
    }

    fetchRSSFeed();
});
