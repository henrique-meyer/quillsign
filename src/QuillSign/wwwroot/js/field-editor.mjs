const root = document.querySelector('#field-editor');
const initial = JSON.parse(document.querySelector('#field-data').value);
const $ = id => document.getElementById(id);
const form = $('field-properties'), preview = $('pdf-preview'), overlay = $('field-overlay');
const status = $('save-status'), error = $('field-error'), list = $('field-list'), details = $('selected-field');
const colors = ['#255fa2', '#7a3fa0', '#276746', '#994616', '#963957', '#446769', '#775f00', '#3d467d', '#7a5043', '#4c6439'];
const labels = { Signature: 'Signature', Initials: 'Initials', FullName: 'Full name', DateSigned: 'Date signed', Text: 'Text', Checkbox: 'Checkbox', Date: 'Date' };
const senderTypes = ['Text', 'Checkbox', 'Date'];
let fields = initial.fields, version = initial.version, selected, pageNumber = 1, ready = false;
let generation = 0, saved = 0, saving = false, stopped = false, pendingProperties = false, timer;
if (initial.signers.length) { $('add-owner').value = initial.signers[0].id; }
form.addEventListener('submit', event => { event.preventDefault(); apply(); });
function complain(message) { error.textContent = message; error.hidden = false; }
function clearError() { error.hidden = true; error.textContent = ''; }
function updateStatus() {
    status.textContent = pendingProperties ? 'Property edits are not applied. Choose Apply changes or Discard property edits.' :
        stopped ? 'Edits are unsaved. Export them before reloading.' : generation === saved ? 'All field changes saved.' : 'Unsaved changes…';
}
function canChangeSelection() {
    if (!pendingProperties) return true;
    complain('Apply or discard the current property edits before selecting, adding, duplicating or dragging fields.'); return false;
}
for (const event of ['input', 'change']) details.addEventListener(event, () => { pendingProperties = true; updateStatus(); });
function ownerName(field) { return initial.signers.find(s => s.id === field.signerId)?.fullName || 'Sender'; }
function fieldName(field) { return `${field.label || labels[field.type]} · ${ownerName(field)} · page ${field.page}`; }
function color(field) { const index = initial.signers.findIndex(s => s.id === field.signerId); return index < 0 ? '#56606b' : colors[index] || `hsl(${(index * 137.5) % 360} 45% 35%)`; }
for (const owner of [{ id: null, fullName: 'Sender (before sending)' }, ...initial.signers]) {
    const item = document.createElement('li'); item.textContent = owner.fullName; item.style.setProperty('--owner-color', color({ signerId: owner.id })); $('owner-legend').append(item);
}
function changed() {
    generation++; pendingProperties = false; clearError(); updateStatus();
    clearTimeout(timer); if (!stopped) timer = setTimeout(save, 700);
}
async function save() {
    if (saving || stopped || generation === saved) return;
    saving = true; const sentGeneration = generation;
    status.textContent = 'Saving…';
    try {
        const response = await fetch(`/api/envelopes/${initial.publicId}/fields`, { method: 'PATCH', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-CSRF-TOKEN': form.querySelector('[name="__RequestVerificationToken"]').value },
            body: JSON.stringify({ version, documentId: initial.documentId, fields }) });
        const result = await response.json();
        if (!response.ok || !result.version) throw new Error(result.message || 'Your save could not be confirmed.');
        version = result.version; saved = sentGeneration;
        updateStatus();
    } catch (reason) {
        stopped = true; status.textContent = 'Edits are unsaved. Export them before reloading.';
        complain(`${reason.message} Saving is paused so another draft revision cannot be overwritten.`);
    } finally {
        saving = false;
        if (!stopped && generation !== saved) { clearTimeout(timer); timer = setTimeout(save, 700); }
    }
}
function position(element, field) {
    element.style.left = `${field.x * 100}%`; element.style.top = `${field.y * 100}%`;
    element.style.width = `${field.width * 100}%`; element.style.height = `${field.height * 100}%`;
}
function render() {
    overlay.replaceChildren(); list.replaceChildren();
    for (const field of fields) {
        const item = document.createElement('li'), button = document.createElement('button');
        button.type = 'button'; button.textContent = fieldName(field); button.setAttribute('aria-pressed', field.id === selected);
        button.addEventListener('click', () => { select(field.id); $('field-type').focus(); }); item.append(button); list.append(item);
        if (field.page !== pageNumber || !ready) continue;
        const placed = document.createElement('button'); placed.type = 'button'; placed.className = 'placed-field'; placed.dataset.id = field.id;
        placed.textContent = field.signerId ? (field.label || labels[field.type]) : (field.value === 'true' && field.type === 'Checkbox' ? '☑' : field.value === 'false' && field.type === 'Checkbox' ? '☐' : field.value || field.label || labels[field.type]);
        placed.setAttribute('aria-label', fieldName(field)); placed.setAttribute('aria-pressed', field.id === selected);
        placed.style.setProperty('--owner-color', color(field)); position(placed, field);
        const handle = document.createElement('span'); handle.className = 'resize-handle'; handle.setAttribute('aria-hidden', 'true'); placed.append(handle);
        placed.addEventListener('click', () => select(field.id)); overlay.append(placed);
    }
}
function showSelectedPage() {
    const field = fields.find(f => f.id === selected);
    if (field && field.page !== pageNumber) preview.dispatchEvent(new CustomEvent('pdf-page-request', { detail: { pageNumber: field.page } }));
}
function select(id) { if (!canChangeSelection()) return; selected = id; render(); fillProperties(); showSelectedPage(); }
function fillProperties() {
    pendingProperties = false; updateStatus();
    const field = fields.find(f => f.id === selected); details.hidden = !field; details.disabled = !field;
    if (!field) return;
    for (const key of ['type', 'label', 'page']) $(`field-${key}`).value = field[key] ?? '';
    $('field-owner').value = field.signerId || '';
    for (const key of ['x', 'y', 'width', 'height']) $(`field-${key}`).value = +(field[key] * 100).toFixed(6);
    $('field-required').checked = field.required; $('field-value').value = field.value ?? '';
    $('checkbox-value').checked = field.value === 'true'; valueControls();
}
function valueControls() {
    const sender = !$('field-owner').value, type = $('field-type').value;
    $('sender-value').hidden = !sender;
    $('field-value').hidden = type === 'Checkbox'; $('checkbox-value-label').hidden = type !== 'Checkbox';
    $('value-hint').textContent = type === 'Date' ? 'Enter YYYY-MM-DD, or leave empty to fill before sending.' : 'Fill this before sending. Signers will see it as fixed content.';
}
$('field-owner').addEventListener('change', valueControls); $('field-type').addEventListener('change', valueControls);
function validate(field) {
    if (!field.signerId && !senderTypes.includes(field.type)) return 'Assign this field type to a signer.';
    if (!Number.isInteger(field.page) || field.page < 1 || field.page > initial.pages.length) return 'Choose a document page.';
    if (![field.x, field.y, field.width, field.height].every(Number.isFinite) || field.x < 0 || field.y < 0 || field.width < .0001 || field.height < .0001 || field.x + field.width > 1.000000001 || field.y + field.height > 1.000000001) return 'Keep the entire field inside the page with positive width and height.';
    if (!field.signerId && field.type === 'Date' && field.value !== null) {
        const date = new Date(`${field.value}T00:00:00Z`);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(field.value) || field.value.startsWith('0000-') || !Number.isFinite(date.valueOf()) || date.toISOString().slice(0, 10) !== field.value) return 'Enter a valid date as YYYY-MM-DD.';
    }
    return null;
}
function apply() {
    const old = fields.find(f => f.id === selected); if (!old) return;
    if (!form.reportValidity()) return;
    const type = $('field-type').value, signerId = $('field-owner').value || null;
    const field = { ...old, type, signerId, label: $('field-label').value || null, page: Number($('field-page').value), required: $('field-required').checked,
        value: signerId ? null : type === 'Checkbox' ? String($('checkbox-value').checked) : $('field-value').value || null };
    for (const key of ['x', 'y', 'width', 'height']) field[key] = Number($(`field-${key}`).value) / 100;
    const message = validate(field); if (message) { complain(message); return; }
    fields = fields.map(f => f.id === field.id ? field : f); changed(); render(); fillProperties(); showSelectedPage();
}
$('apply-field').addEventListener('click', apply);
$('discard-properties').addEventListener('click', () => { clearError(); fillProperties(); });
$('add-field').addEventListener('click', () => {
    if (!ready) return;
    if (!canChangeSelection()) return;
    if (fields.length >= Number(root.dataset.maximum)) { complain(`Use at most ${root.dataset.maximum} fields.`); return; }
    const type = $('add-type').value, signerId = $('add-owner').value || null;
    const field = { id: crypto.randomUUID(), type, signerId, page: pageNumber, x: .1, y: .1, width: type === 'Checkbox' ? .05 : .3, height: .06, required: true, label: null, value: !signerId && type === 'Checkbox' ? 'false' : null };
    const message = validate(field); if (message) { complain(message); return; }
    fields.push(field); changed(); select(field.id);
});
$('duplicate-field').addEventListener('click', () => {
    if (!canChangeSelection()) return;
    const field = fields.find(f => f.id === selected); if (!field) return;
    if (fields.length >= Number(root.dataset.maximum)) { complain(`Use at most ${root.dataset.maximum} fields.`); return; }
    const duplicate = { ...field, id: crypto.randomUUID(), x: Math.min(1 - field.width, field.x + .02), y: Math.min(1 - field.height, field.y + .02) };
    fields.push(duplicate); changed(); select(duplicate.id);
});
$('delete-field').addEventListener('click', () => { fields = fields.filter(f => f.id !== selected); selected = null; changed(); render(); fillProperties(); });
$('export-fields').addEventListener('click', () => {
    const properties = pendingProperties ? { fieldId: selected,
        values: Object.fromEntries([...details.querySelectorAll('input, select, textarea')].map(input => [input.id, input.type === 'checkbox' ? input.checked : input.value])) } : null;
    const url = URL.createObjectURL(new Blob([JSON.stringify({ documentId: initial.documentId, version, fields, unappliedProperties: properties }, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'quillsign-field-edits.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
window.addEventListener('beforeunload', event => { if (pendingProperties || generation !== saved) { event.preventDefault(); event.returnValue = ''; } });
preview.addEventListener('pdf-page-loading', () => { ready = false; overlay.hidden = true; $('add-field').disabled = true; });
preview.addEventListener('pdf-page-ready', event => { pageNumber = event.detail.pageNumber; ready = true; overlay.hidden = false; $('add-field').disabled = false; render(); });
function move(event, resizing) {
    if (!canChangeSelection()) return;
    const field = fields.find(f => f.id === event.target.dataset.id); if (!field || !ready) return;
    const rect = overlay.getBoundingClientRect(); if (!rect.width || !rect.height) return;
    if (resizing) {
        field.width = Math.max(.01, Math.min(1 - field.x, event.rect.width / rect.width));
        field.height = Math.max(.01, Math.min(1 - field.y, event.rect.height / rect.height));
    } else {
        field.x = Math.max(0, Math.min(1 - field.width, field.x + event.dx / rect.width));
        field.y = Math.max(0, Math.min(1 - field.height, field.y + event.dy / rect.height));
    }
    position(event.target, field); changed();
}
if (typeof window.interact === 'function') {
    window.interact('.placed-field').draggable({ ignoreFrom: '.resize-handle', listeners: { move: event => move(event, false), end: event => select(event.target.dataset.id) } })
        .resizable({ edges: { right: '.resize-handle', bottom: '.resize-handle' }, listeners: { move: event => move(event, true), end: event => select(event.target.dataset.id) } });
} else complain('Drag and resize are unavailable. Select fields and use the numeric controls.');
status.textContent = 'All field changes saved.'; render();
await import('./pdf-preview.mjs');
