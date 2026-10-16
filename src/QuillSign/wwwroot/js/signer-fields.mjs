const data = document.querySelector('#field-data');
if (data) {
    let { snapshot, marks } = JSON.parse(data.value), selected, busy = false, blocked = false, page = 0;
    const form = document.querySelector('#field-form'), list = document.querySelector('#field-list');
    const save = document.querySelector('#save-field'), clear = document.querySelector('#clear-field');
    const refresh = document.querySelector('#refresh-fields'), next = document.querySelector('#next-field');
    const status = document.querySelector('#save-status'), error = document.querySelector('#save-error');
    const inputArea = document.querySelector('#field-input'), heading = document.querySelector('#field-heading');
    const preview = document.querySelector('#pdf-preview'), overlays = document.querySelector('#signer-overlays');
    const drafts = new Map();
    const isMark = f => f.type === 'Signature' || f.type === 'Initials';
    const label = f => f.label?.trim() || ({ FullName: 'Full name', DateSigned: 'Date signed' }[f.type] || f.type);
    const state = f => f.type === 'DateSigned' ? 'Set by the server at Finish' : f.stale ? 'Reapply or clear: adopted marks changed' : f.filled ? 'Saved' : f.required ? 'Required — missing' : 'Optional — empty';
    const current = () => snapshot.fields.find(f => f.id === selected);
    function message(text, failed = false) {
        error.hidden = !failed; error.textContent = failed ? text : ''; status.textContent = failed ? 'Save not confirmed. Check the error below.' : text;
    }
    function controls() {
        const f = current(); list.disabled = next.disabled = refresh.disabled = busy;
        save.disabled = busy || blocked || !f || f.type === 'DateSigned' || (isMark(f) && (!marks || marks.id !== snapshot.adoptionId));
        clear.disabled = busy || blocked || !f || f.type === 'DateSigned' || (!f.filledAt && !f.stale);
        inputArea.querySelectorAll('input,textarea').forEach(e => e.disabled = busy);
        document.querySelector('#field-progress').textContent = `${snapshot.fields.filter(f => f.required && !f.filled && f.type !== 'DateSigned').length} required entries missing · ${snapshot.fields.filter(f => f.stale).length} entries need reapplication or clearing.`;
    }
    function markImage(f) {
        const img = document.createElement('img'); img.className = 'saved-mark';
        img.src = `data:image/png;base64,${f.type === 'Signature' ? marks.signature : marks.initials}`;
        img.alt = `${f.type} from your current adopted pair`; return img;
    }
    function renderList() {
        list.replaceChildren(...snapshot.fields.map(f => { const option = document.createElement('option'); option.value = f.id;
            option.textContent = `Page ${f.page} · ${label(f)} · ${state(f)}`; return option; }));
        list.value = selected || '';
    }
    function showField(focus = false) {
        const f = current(); inputArea.replaceChildren();
        if (!f) { heading.textContent = 'No fields are assigned to you'; controls(); return; }
        heading.textContent = `${label(f)} — page ${f.page}`;
        document.querySelector('#saved-value').textContent = `${state(f)}${!isMark(f) && f.type !== 'DateSigned' && f.value !== null ? ` · Latest saved value: ${f.type === 'Checkbox' ? f.value === 'true' ? 'Checked' : 'Unchecked' : f.value}` : ''}`;
        save.textContent = isMark(f) ? `Apply ${f.type.toLowerCase()} to this field` : f.type === 'FullName' ? 'Apply my full name' : 'Save this field';
        if (isMark(f)) {
            const p = document.createElement('p'); p.textContent = marks ? 'Your current adopted mark is shown below. Apply it to this field explicitly.' : 'Adopt your signature and initials before applying a mark.';
            inputArea.append(p); if (marks) inputArea.append(markImage(f));
        } else if (f.type === 'FullName' || f.type === 'DateSigned') {
            const p = document.createElement('p'); p.textContent = f.type === 'FullName' ? `Full name from your signer record: ${snapshot.signerName}` : 'Date Signed will be supplied by the server at Finish. It cannot be entered or cleared here.'; inputArea.append(p);
        } else {
            const name = document.createElement('label'); name.htmlFor = 'entry-value'; name.textContent = f.type === 'Checkbox' ? 'Checkbox response (Save records checked or unchecked)' : `Your ${f.type === 'Date' ? 'date (YYYY-MM-DD)' : 'text entry'}`;
            const entry = document.createElement(f.type === 'Text' ? 'textarea' : 'input'); entry.id = 'entry-value';
            if (f.type === 'Text') { entry.maxLength = 4000; entry.rows = 3; } else entry.type = f.type === 'Checkbox' ? 'checkbox' : 'date';
            const value = drafts.has(f.id) ? drafts.get(f.id) : f.value ?? '';
            if (f.type === 'Checkbox') entry.checked = value === 'true'; else entry.value = value;
            entry.addEventListener('input', () => {
                const attempted = f.type === 'Checkbox' ? String(entry.checked) : entry.value;
                if (attempted === (f.value ?? '')) drafts.delete(f.id); else drafts.set(f.id, attempted);
                status.textContent = drafts.has(f.id) ? 'Unsaved entry. Use Save this field to record it.' : 'Entry matches saved state.';
            }); inputArea.append(name, entry);
        }
        renderList(); renderOverlays(); controls();
        if (focus) heading.focus();
    }
    function select(id, focus = false) {
        selected = id; showField(focus); const f = current();
        if (f && !blocked) message(drafts.has(id) ? 'Unsaved entry. Use Save this field to record it.' : state(f));
        if (f && f.page !== page) preview.dispatchEvent(new CustomEvent('pdf-page-request', { detail: { pageNumber: f.page } }));
    }
    function renderOverlays() {
        overlays.replaceChildren();
        for (const f of snapshot.fields.filter(f => f.page === page)) {
            const button = document.createElement('button'); button.type = 'button'; button.className = `signer-overlay${f.id === selected ? ' selected' : ''}${f.stale ? ' stale' : ''}`;
            Object.assign(button.style, { left: `${f.x * 100}%`, top: `${f.y * 100}%`, width: `${f.width * 100}%`, height: `${f.height * 100}%` });
            button.setAttribute('aria-label', `${label(f)}: ${state(f)}. Select field; does not apply.`);
            button.disabled = busy;
            if (isMark(f) && f.filled && marks) button.append(markImage(f));
            else { const span = document.createElement('span'); span.textContent = f.stale ? 'Reapply or clear' : f.type === 'DateSigned' ? 'At Finish' : f.filled ? f.type === 'Checkbox' ? f.value === 'true' ? '☑' : '☐' : f.value : label(f); button.append(span); }
            button.addEventListener('click', () => { select(f.id, true); heading.scrollIntoView({ block: 'center' }); }); overlays.append(button);
        }
    }
    preview.addEventListener('pdf-page-loading', () => { page = 0; overlays.replaceChildren(); });
    preview.addEventListener('pdf-page-ready', e => { page = e.detail.pageNumber; renderOverlays(); });
    list.addEventListener('change', () => select(list.value, true));
    next.addEventListener('click', () => {
        const index = snapshot.fields.findIndex(f => f.id === selected);
        const ordered = [...snapshot.fields.slice(index + 1), ...snapshot.fields.slice(0, index + 1)];
        const f = ordered.find(f => !f.filled && f.type !== 'DateSigned');
        if (f) select(f.id, true); else message('All current entries are saved. Review saved entries next; signing is not complete.');
    });
    async function change(action) {
        if (busy || blocked || !current()) return;
        const f = current(); busy = true; blocked = true; controls(); renderOverlays(); message('Saving this field…');
        const body = new FormData(); body.set('__RequestVerificationToken', form.elements.__RequestVerificationToken.value);
        body.set('FieldId', f.id); body.set('Version', f.version); body.set('Action', action);
        if (action === 'Apply') {
            if (isMark(f)) body.set('AdoptionId', snapshot.adoptionId);
            else if (f.type !== 'FullName') { const input = document.querySelector('#entry-value'); const attempted = f.type === 'Checkbox' ? String(input.checked) : input.value; body.set('Value', attempted); drafts.set(f.id, attempted); }
        }
        try {
            const response = await fetch(form.action, { method: 'POST', body, credentials: 'same-origin', headers: { Accept: 'application/json' } });
            const result = await response.json().catch(() => null);
            if (!response.ok) {
                blocked = response.status !== 400;
                if (result?.field) { snapshot.fields = snapshot.fields.map(x => x.id === result.field.id ? result.field : x); showField(); }
                // Keep the attempt separately; a conflict never becomes an implicit overwrite.
                throw new Error(result?.message || 'Saving could not be confirmed. Your attempted entry is preserved. Refresh saved state before retrying.');
            }
            if (!result?.field) throw new Error('Saving could not be confirmed. Refresh saved state before retrying.');
            snapshot.fields = snapshot.fields.map(x => x.id === f.id ? result.field : x); drafts.delete(f.id); blocked = false;
            message(result.message); showField();
        } catch (e) {
            if (!(e instanceof Error)) blocked = true;
            message(e.message || 'Saving could not be confirmed. Refresh saved state before retrying.', true);
        } finally { busy = false; controls(); renderOverlays(); }
    }
    form.addEventListener('submit', e => { e.preventDefault(); change('Apply'); });
    clear.addEventListener('click', () => change('Clear'));
    refresh.addEventListener('click', async () => {
        if (busy) return; busy = true; controls(); message('Refreshing saved state…');
        try {
            const response = await fetch(`${form.action}?handler=Snapshot`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
            const result = await response.json().catch(() => null); if (!response.ok || !result?.snapshot) throw new Error(result?.message || 'Saved state is unavailable. Reload or request a new invitation.');
            snapshot = result.snapshot; marks = result.marks; blocked = false; showField();
            message('Saved state refreshed. Unsaved entries remain in this browser. Check the latest saved value before saving again.');
        } catch (e) { blocked = true; message(e.message, true); }
        finally { busy = false; controls(); renderOverlays(); }
    });
    window.addEventListener('beforeunload', e => { if (busy || drafts.size) { e.preventDefault(); e.returnValue = ''; } });
    let destination;
    const warning = document.querySelector('#leave-warning');
    document.querySelectorAll('a[data-leave]').forEach(a => a.addEventListener('click', e => {
        if (busy) { e.preventDefault(); return; }
        if (drafts.size) { e.preventDefault(); destination = a.href; warning.hidden = false; document.querySelector('#leave-heading').focus(); }
    }));
    document.querySelector('#stay-fields').addEventListener('click', () => { warning.hidden = true; destination = null; document.querySelector('#entry-value')?.focus(); });
    document.querySelector('#discard-fields').addEventListener('click', () => { if (destination && !busy) { drafts.clear(); location.assign(destination); } });
    selected = snapshot.fields.find(f => f.id === location.hash.slice(1))?.id || snapshot.fields[0]?.id;
    showField();
    // Register page events before PDF.js's asynchronous module initialization.
    import('./pdf-preview.mjs').catch(() => { document.querySelector('#preview-status').textContent = 'The preview is unavailable. Download the document or reload.'; });
}
