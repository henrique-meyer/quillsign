import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const script = readFileSync(new URL('../../src/QuillSign/wwwroot/analytics.js', import.meta.url), 'utf8');
function page({ choice, pathname = '/', search = '', hash = '', privacy = false, dnt = '0', id = 'G-TEST123456', cookies = {} } = {}) {
    const jar = new Map(Object.entries(cookies)), scripts = [], writes = [], lookups = [];
    if (choice) jar.set('quillsign_analytics', choice);
    const document = {
        getElementById(key) { lookups.push(key); return key === 'analytics' ? { dataset: { measurementId: id } } : null; },
        createElement(tag) { return { tag }; }, head: { appendChild(node) { scripts.push(node); } },
        get cookie() { return [...jar].map(([key, value]) => key + '=' + value).join('; '); },
        set cookie(value) { writes.push(value); const [name, content] = value.split(';')[0].split('='); if (value.includes('Max-Age=0')) jar.delete(name); else jar.set(name, content); }
    };
    const window = { location: { pathname, search, hash, protocol: 'https:', origin: 'https://example.invalid' } };
    vm.runInNewContext(script, { document, window, navigator: { globalPrivacyControl: privacy, doNotTrack: dnt }, Date, encodeURIComponent });
    return { window, scripts, jar, writes, lookups };
}

test('clean homepage starts without visible controls or a preference cookie', () => {
    for (const choice of [undefined, 'allow']) {
        const p = page({ choice });
        assert.equal(p.scripts.length, 1); assert.deepEqual(p.lookups, ['analytics']);
        assert.equal(p.writes.length, 0); assert.equal(p.jar.get('quillsign_analytics'), choice);
    }
});

test('homepage sends one controlled page view with bounded cookies and advertising disabled', () => {
    const p = page();
    assert.equal(p.scripts.length, 1);
    assert.equal(p.scripts[0].src, 'https://www.googletagmanager.com/gtag/js?id=G-TEST123456'); assert.equal(p.scripts[0].referrerPolicy, 'no-referrer');
    const commands = JSON.parse(JSON.stringify(p.window.dataLayer.map(x => Array.from(x))));
    assert.deepEqual(commands[0], ['consent', 'default', { analytics_storage: 'granted', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' }]);
    const config = commands.find(x => x[0] === 'config')[2];
    assert.equal(config.send_page_view, false); assert.equal(config.allow_google_signals, false); assert.equal(config.allow_ad_personalization_signals, false);
    assert.equal(config.cookie_domain, 'none'); assert.equal(config.cookie_expires, 15552000); assert.equal(config.cookie_flags, 'SameSite=Lax;Secure');
    const events = commands.filter(x => x[0] === 'event'); assert.equal(events.length, 1);
    assert.deepEqual(events[0], ['event', 'page_view', { page_location: 'https://example.invalid/', page_title: 'QuillSign', page_referrer: '', send_to: 'G-TEST123456' }]);
});

test('private paths, queries, fragments and malformed identifiers never initialize', () => {
    for (const choice of [undefined, 'allow']) {
        for (const options of [{ search: '?email=SYNTHETIC_PRIVATE' }, { hash: '#token=SYNTHETIC_PRIVATE' }, { pathname: '/sign/access' }, { pathname: '/find/access' }, { pathname: '/verify' }, { id: 'G-INVALID<script>' }, { id: '' }]) {
            const p = page({ choice, ...options }); assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined); assert.equal(p.writes.length, 0);
        }
    }
});

test('previous declines remain effective and clear only host-only analytics cookies', () => {
    const p = page({ choice: 'deny', cookies: { _ga: 'synthetic', _ga_TEST123456: 'synthetic', 'QuillSign.Sender': 'private' } });
    assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined); assert.equal(p.window['ga-disable-G-TEST123456'], true);
    assert.equal(p.jar.has('_ga'), false); assert.equal(p.jar.has('_ga_TEST123456'), false);
    assert.equal(p.jar.get('QuillSign.Sender'), 'private'); assert.equal(p.jar.get('quillsign_analytics'), 'deny');
    assert.equal(p.writes.length, 2); assert.ok(p.writes.every(x => /Path=\/; Max-Age=0; SameSite=Lax; Secure/.test(x)));
});

test('Global Privacy Control and Do Not Track prevent collection regardless of previous acceptance', () => {
    for (const choice of [undefined, 'allow']) {
        for (const options of [{ privacy: true }, { dnt: '1' }]) {
            const p = page({ choice, ...options, cookies: { _ga: 'synthetic' } });
            assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined);
            assert.equal(p.window['ga-disable-G-TEST123456'], true); assert.equal(p.jar.has('_ga'), false);
        }
    }
});
