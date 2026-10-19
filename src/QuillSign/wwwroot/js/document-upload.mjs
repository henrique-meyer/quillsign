const form = document.querySelector('[data-document-upload]');
if (form) {
    const file = form.querySelector('input[type="file"]');
    const error = form.querySelector('[data-upload-error]');
    const zone = form.querySelector('[data-upload-dropzone]');
    const browse = form.querySelector('[data-upload-browse]');
    const selection = form.querySelector('[data-upload-selection]');
    const maximum = Number(form.dataset.maximumBytes);
    const extensions = form.dataset.extensions.split(',');
    const mib = (maximum / 1048576).toLocaleString(undefined, { maximumFractionDigits: 3 });
    let dragDepth = 0;

    function problem(files) {
        if (files?.length !== 1) return 'Choose one document at a time.';
        const selected = files[0];
        const extension = selected.name.slice(selected.name.lastIndexOf('.')).toLowerCase();
        if (!extensions.includes(extension)) return `This file type is not supported here. Choose ${extensions.join(', ')}.`;
        if (selected.size === 0) return 'This document is empty. Choose a file with content.';
        if (selected.size > maximum) return `This document is too large. Choose a file no larger than ${mib} MiB.`;
        return null;
    }
    function showError(message, focus = false) {
        error.textContent = message ?? '';
        error.hidden = !message;
        file.setAttribute('aria-invalid', message ? 'true' : 'false');
        if (focus && message) error.focus();
    }
    function describe() {
        const selected = file.files?.[0];
        if (selection) selection.textContent = selected
            ? `${selected.name} · ${(selected.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB selected. Not uploaded yet.`
            : 'No document selected.';
    }
    function resetDrag() { dragDepth = 0; zone?.classList.remove('is-dragging'); }
    const hasFiles = event => Array.from(event.dataTransfer?.types ?? []).includes('Files');
    file.addEventListener('change', () => { resetDrag(); describe(); showError(problem(file.files)); });
    form.addEventListener('submit', event => {
        const message = problem(file.files);
        showError(message, true);
        if (message) event.preventDefault();
    });
    describe();
    // Preserve the native required-file fallback when scripting is unavailable.
    form.noValidate = true;
    if (zone && browse) {
        form.querySelector('[data-upload-instruction]').textContent = 'Drag & drop one document here';
        browse.hidden = false;
        zone.classList.add('is-enhanced');
        file.tabIndex = -1;
        browse.addEventListener('click', () => file.click());
        zone.addEventListener('dragenter', event => {
            if (!hasFiles(event)) return;
            event.preventDefault(); dragDepth++; zone.classList.add('is-dragging');
        });
        zone.addEventListener('dragleave', event => {
            if (!dragDepth) return;
            event.preventDefault(); if (--dragDepth === 0) resetDrag();
        });
        zone.addEventListener('dragover', event => {
            if (!hasFiles(event)) return;
            event.preventDefault(); event.dataTransfer.dropEffect = 'copy';
        });
        zone.addEventListener('drop', event => {
            if (!hasFiles(event)) return;
            event.preventDefault(); event.stopPropagation(); resetDrag();
            const transfer = event.dataTransfer;
            const directory = Array.from(transfer.items ?? []).some(item => item.kind === 'file' && item.webkitGetAsEntry?.()?.isDirectory);
            const message = directory ? 'Folders are not supported. Choose one document file.' : problem(transfer.files);
            if (message) { showError(`${message}${file.files?.length ? ' Your previous selection is unchanged.' : ''}`, true); return; }
            try { file.files = transfer.files; }
            catch { showError('Your browser could not select this drop. Use Browse files instead.', true); return; }
            describe(); showError(null);
        });
        // A misplaced file must not navigate away from the private draft.
        document.addEventListener('dragover', event => { if (hasFiles(event)) event.preventDefault(); });
        document.addEventListener('drop', event => {
            if (!hasFiles(event)) return;
            event.preventDefault(); resetDrag();
            showError('Drop your document in the upload area, or use Browse files.', true);
        });
        document.addEventListener('dragend', resetDrag);
    }
}
