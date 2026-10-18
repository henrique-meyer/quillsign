(() => {
    'use strict';
    const root = document.getElementById('analytics');
    const id = root?.dataset.measurementId;
    // Even a fragment-only access code must never reach a third-party tag.
    if (!/^G-[A-Z0-9]{4,20}$/.test(id || '') || window.location.pathname !== '/' ||
        window.location.search || window.location.hash) return;

    const panel = document.getElementById('analytics-choice');
    const settings = document.getElementById('analytics-settings');
    const status = document.getElementById('analytics-status');
    const preference = 'quillsign_analytics';
    const secure = window.location.protocol === 'https:' ? '; Secure' : '';
    const disabled = 'ga-disable-' + id;
    const blocked = navigator.globalPrivacyControl === true || navigator.doNotTrack === '1';
    let started = false;

    function show(open) {
        panel.hidden = !open;
        settings.setAttribute('aria-expanded', String(open));
    }
    function savedChoice() {
        return document.cookie.split(';').map(x => x.trim()).find(x => x.startsWith(preference + '='))?.split('=')[1];
    }
    function save(choice) {
        document.cookie = preference + '=' + choice + '; Path=/; Max-Age=15552000; SameSite=Lax' + secure;
    }
    function clearAnalyticsCookies() {
        for (const cookie of document.cookie.split(';')) {
            const name = cookie.trim().split('=')[0];
            if (/^_ga(?:_|$)/.test(name)) document.cookie = name + '=; Path=/; Max-Age=0; SameSite=Lax' + secure;
        }
    }
    function start() {
        if (started || blocked) return;
        started = true;
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
    }

    settings.hidden = false;
    settings.addEventListener('click', () => { show(panel.hidden); if (!panel.hidden) document.getElementById('analytics-decline').focus(); });
    document.getElementById('analytics-accept').addEventListener('click', () => {
        save('allow'); start(); show(false); settings.focus();
        status.textContent = blocked ? 'Analytics stays off because your browser requests no tracking.' : 'Analytics allowed for this homepage. You can change your choice in Analytics settings.';
    });
    document.getElementById('analytics-decline').addEventListener('click', () => {
        window[disabled] = true;
        save('deny'); clearAnalyticsCookies(); show(false); settings.focus();
        status.textContent = 'Analytics is off.';
        // Unload an already-running tag, including its timers and listeners.
        if (started) window.location.reload();
    });
    const choice = savedChoice();
    if (blocked) { window[disabled] = true; clearAnalyticsCookies(); status.textContent = 'Analytics is off because your browser requests no tracking.'; }
    else if (choice === 'allow') start();
    else if (choice !== 'deny') show(true);
})();
