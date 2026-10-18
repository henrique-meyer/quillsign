import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const script = readFileSync(new URL('../../src/QuillSign/wwwroot/lookup-access.js', import.meta.url), 'utf8');
function page(hash, okay = true) {
    const events = {}, calls = [], order = [];
    const nodes = Object.fromEntries(['lookup-pending', 'lookup-code-form', 'lookup-code', 'lookup-begin', 'lookup-link-status'].map(id => [id, {
        hidden: true, disabled: false, textContent: '', action: '/find/access/Begin',
        setAttribute(name) { this[name] = true; }, focus() { order.push('focus'); },
        addEventListener(name, fn) { this[name] = fn; }
    }]));
    const location = { hash, replace(path) { calls.push(['replace', path]); }, reload() { calls.push(['reload']); } };
    class Form { constructor() { this.data = new Map(); } set(k, v) { this.data.set(k, v); } delete(k) { this.data.delete(k); } }
    vm.runInNewContext(script, {
        window: { location, history: { replaceState(_a, _b, path) { order.push('scrub'); location.hash = ''; calls.push(['scrub', path]); } }, addEventListener(name, fn) { events[name] = fn; } },
        document: { getElementById(id) { order.push('dom'); return nodes[id]; } }, FormData: Form,
        async fetch(url, options) { calls.push(['fetch', url, options.method, options.body.data.get('code'), options.credentials, options.headers.Accept]); return { okay, ok: okay }; }
    });
    return { nodes, calls, events, order, async submit() { await nodes['lookup-code-form'].submit({ preventDefault() {} }); } };
}

test('fragment is scrubbed before DOM work and no request occurs before explicit Continue', async () => {
    const token = 'a'.repeat(1000), p = page('#token=' + token);
    assert.equal(p.order[0], 'scrub'); assert.deepEqual(p.calls, [['scrub', '/find/access']]);
    assert.equal(p.nodes['lookup-code'].disabled, true); assert.equal(p.nodes['lookup-pending'].hidden, true);
    await p.submit(); assert.deepEqual(p.calls[1], ['fetch', '/find/access/Begin', 'POST', token, 'same-origin', 'application/json']);
    assert.deepEqual(p.calls[2], ['replace', '/find/access']);
    await p.submit(); assert.equal(p.calls.filter(x => x[0] === 'fetch').length, 1);
});
test('malformed fragments are scrubbed without reflecting their text or sending a request', () => {
    for (const hash of ['#token=short', '#token=' + 'x'.repeat(3801), '#token=' + 'x'.repeat(43) + '&extra=unsafe', '#secret=<script>']) {
        const p = page(hash); assert.deepEqual(p.calls, [['scrub', '/find/access']]);
        assert.equal(p.nodes['lookup-code-form'].submit, undefined);
        assert.doesNotMatch(p.nodes['lookup-link-status'].textContent, /unsafe|<script>/);
    }
});
test('a failed explicit preparation is not silently replayed', async () => {
    const p = page('#token=' + 'b'.repeat(1000), false); await p.submit(); await p.submit();
    assert.equal(p.calls.filter(x => x[0] === 'fetch').length, 1);
    assert.match(p.nodes['lookup-link-status'].textContent, /could not be prepared/);
});
test('back-forward restoration drops in-memory link state through a clean reload', () => {
    const p = page('#token=' + 'c'.repeat(1000)); p.events.pageshow({ persisted: true });
    assert.deepEqual(p.calls.at(-1), ['replace', '/find/access']);
});
