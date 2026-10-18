(() => {
    'use strict';
    const root = document.getElementById('analytics');
    const id = root?.dataset.measurementId;
    // Even a fragment-only access code must never reach a third-party tag.
    if (!/^G-[A-Z0-9]{4,20}$/.test(id || '') || window.location.pathname !== '/' ||
        window.location.search || window.location.hash) return;

    const preference = 'quillsign_analytics';
    const secure = window.location.protocol === 'https:' ? '; Secure' : '';
    const disabled = 'ga-disable-' + id;
    const blocked = navigator.globalPrivacyControl === true || navigator.doNotTrack === '1';
    function savedChoice() {
        return document.cookie.split(';').map(x => x.trim()).find(x => x.startsWith(preference + '='))?.split('=')[1];
    }
    function clearAnalyticsCookies() {
        for (const cookie of document.cookie.split(';')) {
            const name = cookie.trim().split('=')[0];
            if (/^_ga(?:_|$)/.test(name)) document.cookie = name + '=; Path=/; Max-Age=0; SameSite=Lax' + secure;
        }
    }
    // Preserve a prior decline even though the page no longer offers controls.
    if (blocked || savedChoice() === 'deny') {
        window[disabled] = true;
        clearAnalyticsCookies();
        return;
    }
    window[disabled] = false;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag('consent', 'default', {
        analytics_storage: 'granted', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'
    });
    window.gtag('js', new Date());
    const page = { page_location: window.location.origin + '/', page_title: 'QuillSign', page_referrer: '' };
    window.gtag('set', page);
    window.gtag('config', id, {
        ...page, send_page_view: false, allow_google_signals: false, allow_ad_personalization_signals: false,
        cookie_domain: 'none', cookie_expires: 15552000, cookie_flags: 'SameSite=Lax;Secure'
    });
    window.gtag('event', 'page_view', { ...page, send_to: id });
    const script = document.createElement('script');
    script.async = true;
    script.referrerPolicy = 'no-referrer';
    script.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(id);
    document.head.appendChild(script);
})();
