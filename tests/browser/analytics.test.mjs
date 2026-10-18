import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const script = readFileSync(new URL('../../src/QuillSign/wwwroot/analytics.js', import.meta.url), 'utf8');
function page({ choice, pathname = '/', search = '', hash = '', privacy = false, dnt = '0', id = 'G-TEST123456' } = {}) {
    const jar = new Map(), scripts = [], writes = [], calls = [];
    if (choice) jar.set('quillsign_analytics', choice);
    const nodes = Object.fromEntries(['analytics', 'analytics-choice', 'analytics-settings', 'analytics-status', 'analytics-accept', 'analytics-decline'].map(key => [key, {
        hidden: true, dataset: { measurementId: id }, textContent: '',
        addEventListener(name, fn) { this[name] = fn; }, setAttribute(name, value) { this[name] = value; }, focus() { calls.push(['focus', key]); }
    }]));
    const document = {
        getElementById(key) { return nodes[key]; }, createElement(tag) { return { tag }; }, head: { appendChild(node) { scripts.push(node); } },
        get cookie() { return [...jar].map(([key, value]) => key + '=' + value).join('; '); },
        set cookie(value) { writes.push(value); const [name, content] = value.split(';')[0].split('='); if (value.includes('Max-Age=0')) jar.delete(name); else jar.set(name, content); }
    };
    const window = { location: { pathname, search, hash, protocol: 'https:', origin: 'https://example.invalid', reload() { calls.push(['reload']); } } };
    vm.runInNewContext(script, { document, window, navigator: { globalPrivacyControl: privacy, doNotTrack: dnt }, Date, encodeURIComponent });
    return { nodes, window, scripts, jar, writes, calls,
        accept() { nodes['analytics-accept'].click(); }, decline() { nodes['analytics-decline'].click(); } };
}

test('unknown choice makes no Google request; decline persists without loading a tag', () => {
    const p = page(); assert.equal(p.nodes['analytics-choice'].hidden, false); assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined);
    p.decline(); assert.equal(p.scripts.length, 0); assert.equal(p.jar.get('quillsign_analytics'), 'deny'); assert.equal(p.nodes['analytics-choice'].hidden, true);
    assert.match(p.writes[0], /Path=\/; Max-Age=15552000; SameSite=Lax; Secure/);
    const returning = page({ choice: 'deny' }); assert.equal(returning.scripts.length, 0); assert.equal(returning.nodes['analytics-choice'].hidden, true);
});

test('explicit acceptance sends exactly one controlled public page view and denies advertising consent', () => {
    const p = page(); p.accept(); p.accept(); assert.equal(p.scripts.length, 1);
    assert.equal(p.scripts[0].src, 'https://www.googletagmanager.com/gtag/js?id=G-TEST123456'); assert.equal(p.scripts[0].referrerPolicy, 'no-referrer');
    const commands = JSON.parse(JSON.stringify(p.window.dataLayer.map(x => Array.from(x))));
    assert.deepEqual(commands[0], ['consent', 'default', { analytics_storage: 'granted', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' }]);
    const config = commands.find(x => x[0] === 'config')[2];
    assert.equal(config.send_page_view, false); assert.equal(config.allow_google_signals, false); assert.equal(config.allow_ad_personalization_signals, false); assert.equal(config.cookie_domain, 'none');
    const events = commands.filter(x => x[0] === 'event'); assert.equal(events.length, 1);
    assert.deepEqual(events[0], ['event', 'page_view', { page_location: 'https://example.invalid/', page_title: 'QuillSign', page_referrer: '', send_to: 'G-TEST123456' }]);
});

test('stored acceptance resumes only on clean homepage; private paths, query and fragment never initialize', () => {
    assert.equal(page({ choice: 'allow' }).scripts.length, 1);
    for (const options of [{ search: '?email=SYNTHETIC_PRIVATE' }, { hash: '#token=SYNTHETIC_PRIVATE' }, { pathname: '/sign/access' }, { pathname: '/find/access' }, { pathname: '/verify' }, { id: 'G-INVALID<script>' }]) {
        const p = page({ choice: 'allow', ...options }); assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined); assert.equal(p.nodes['analytics-accept'].click, undefined);
    }
});

test('withdrawing acceptance disables immediately, clears only analytics cookies and reloads to unload tag', () => {
    const p = page({ choice: 'allow' }); p.jar.set('_ga', 'synthetic'); p.jar.set('_ga_TEST123456', 'synthetic'); p.jar.set('QuillSign.Sender', 'private');
    p.nodes['analytics-settings'].click(); assert.equal(p.nodes['analytics-choice'].hidden, false); assert.equal(p.nodes['analytics-settings']['aria-expanded'], 'true');
    p.decline(); assert.equal(p.window['ga-disable-G-TEST123456'], true); assert.equal(p.jar.has('_ga'), false); assert.equal(p.jar.has('_ga_TEST123456'), false);
    assert.equal(p.jar.get('QuillSign.Sender'), 'private'); assert.equal(p.jar.get('quillsign_analytics'), 'deny'); assert.deepEqual(p.calls.at(-1), ['reload']);
});

test('Global Privacy Control and Do Not Track prevent stored or new acceptance from loading Google', () => {
    for (const options of [{ privacy: true }, { dnt: '1' }]) {
        const p = page({ choice: 'allow', ...options }); p.accept(); assert.equal(p.scripts.length, 0); assert.equal(p.window.dataLayer, undefined); assert.match(p.nodes['analytics-status'].textContent, /browser requests no tracking/);
    }
});
