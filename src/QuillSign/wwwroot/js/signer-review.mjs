const form = document.querySelector('#finish-form');
if (form) {
    const previewChoice = form.querySelector('input[value="preview"]');
    previewChoice.disabled = true;
    document.querySelector('#pdf-preview')?.addEventListener('pdf-page-ready', () => { previewChoice.disabled = false; });
    form.addEventListener('submit', () => {
        form.querySelector('button[type="submit"]').disabled = true;
    });
}
await import('./pdf-preview.mjs');
