import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const script = readFileSync(new URL('../../src/QuillSign/wwwroot/js/document-upload.mjs', import.meta.url), 'utf8');
function page(extensions = '.pdf,.png') {
    const nodes = {}, documentEvents = {};
    function element(name) {
        const classes = new Set();
        return nodes[name] = { hidden: true, textContent: '', events: {}, attributes: {},
            classList: { add(x) { classes.add(x); }, remove(x) { classes.delete(x); }, contains(x) { return classes.has(x); } },
            addEventListener(name, handler) { this.events[name] = handler; },
            setAttribute(name, value) { this.attributes[name] = value; },
            focus() { this.focused = true; }, click() { this.clicked = true; } };
    }
    const file = element('file'); file.files = [];
    const error = element('error'), zone = element('zone'), browse = element('browse'), selection = element('selection');
    const instruction = element('instruction'), form = element('form');
    form.dataset = { maximumBytes: '1024', extensions };
    form.querySelector = selector => ({ 'input[type="file"]': file, '[data-upload-error]': error,
        '[data-upload-dropzone]': zone, '[data-upload-browse]': browse, '[data-upload-selection]': selection,
        '[data-upload-instruction]': instruction })[selector];
    vm.runInNewContext(script, { document: { querySelector: () => form,
        addEventListener(name, handler) { documentEvents[name] = handler; } } });
    const event = (files = [], items = [], types = ['Files']) => ({ dataTransfer: { files, items, types },
        preventDefault() { this.prevented = true; }, stopPropagation() { this.stopped = true; } });
    return { ...nodes, documentEvents, event,
        choose(files) { file.files = files; file.events.change(); },
        drop(files, items = []) { const e = event(files, items); zone.events.drop(e); if (!e.stopped) documentEvents.drop(e); return e; },
        submit() { const e = event(); form.events.submit(e); return e; } };
}
const pdf = (name = 'synthetic.pdf', size = 512) => ({ name, size });

test('Browse opens native selection; selecting a valid file does not upload it', () => {
    const p = page(); assert.equal(p.browse.hidden, false); assert.equal(p.file.tabIndex, -1);
    p.browse.events.click(); assert.equal(p.file.clicked, true);
    p.choose([pdf()]); assert.equal(p.error.hidden, true); assert.match(p.selection.textContent, /synthetic.pdf/);
    assert.equal(p.submit().prevented, undefined);
});
test('valid drop fills the same file input and still requires explicit Upload', () => {
    const p = page(), files = [pdf('SYNTHETIC.PDF', 1024)];
    const e = p.drop(files); assert.equal(e.prevented, true); assert.equal(e.stopped, true);
    assert.equal(p.file.files, files); assert.equal(p.error.hidden, true); assert.equal(p.form.submitted, undefined);
    assert.match(p.selection.textContent, /Not uploaded yet/); assert.equal(p.submit().prevented, undefined);
});
test('invalid, oversized and empty selections block submission and recover through Browse', () => {
    for (const files of [[], [pdf(), pdf()], [pdf('disabled.docx')], [pdf('large.pdf', 1025)], [pdf('empty.pdf', 0)]]) {
        const p = page(); p.choose(files); assert.equal(p.error.hidden, false); assert.equal(p.submit().prevented, true);
        assert.equal(p.error.focused, true); assert.equal(p.file.attributes['aria-invalid'], 'true');
        p.choose([pdf()]); assert.equal(p.error.hidden, true); assert.equal(p.submit().prevented, undefined);
    }
});
test('a rejected drop preserves a previous valid choice and does not render filename markup', () => {
    const p = page(), original = [pdf('<img src=x onerror=alert(1)>.pdf')]; p.choose(original);
    assert.match(p.selection.textContent, /<img/);
    for (const files of [[pdf('bad.exe')], [pdf(), pdf()], [pdf('large.pdf', 1025)]]) {
        p.drop(files); assert.equal(p.file.files, original); assert.match(p.error.textContent, /previous selection is unchanged/);
    }
    assert.equal(p.submit().prevented, undefined);
});
test('directory drops fail even when another supported file is included', () => {
    const p = page(); p.drop([pdf()], [{ kind: 'file', webkitGetAsEntry: () => ({ isDirectory: true }) }]);
    assert.match(p.error.textContent, /Folders/); assert.equal(p.file.files.length, 0);
});
test('nested drag targets retain highlighting until the last leave and clear on drop or drag end', () => {
    const p = page(); p.zone.events.dragenter(p.event()); p.zone.events.dragenter(p.event());
    p.zone.events.dragleave(p.event()); assert.equal(p.zone.classList.contains('is-dragging'), true);
    p.zone.events.dragleave(p.event()); assert.equal(p.zone.classList.contains('is-dragging'), false);
    p.zone.events.dragenter(p.event()); p.drop([pdf()]); assert.equal(p.zone.classList.contains('is-dragging'), false);
    p.zone.events.dragenter(p.event()); p.documentEvents.dragend(); assert.equal(p.zone.classList.contains('is-dragging'), false);
});
test('misplaced file drops cannot navigate away; ordinary text drags are left alone', () => {
    const p = page(), misplaced = p.event([pdf()]); p.documentEvents.drop(misplaced);
    assert.equal(misplaced.prevented, true); assert.match(p.error.textContent, /upload area/);
    const text = p.event([], [], ['text/plain']); p.zone.events.drop(text); p.documentEvents.drop(text);
    assert.equal(text.prevented, undefined);
});
test('unsupported FileList assignment retains Browse recovery and the old file', () => {
    const p = page(), original = [pdf()]; p.choose(original);
    Object.defineProperty(p.file, 'files', { get: () => original, set() { throw new Error('not supported'); } });
    p.drop([pdf('other.pdf')]); assert.match(p.error.textContent, /Use Browse files/); assert.equal(p.file.files, original);
});
test('format availability follows the page-provided allowlist', () => {
    const p = page('.pdf,.docx'); p.drop([pdf('synthetic.docx')]); assert.equal(p.error.hidden, true);
    p.drop([pdf('synthetic.png')]); assert.match(p.error.textContent, /not supported/);
});
