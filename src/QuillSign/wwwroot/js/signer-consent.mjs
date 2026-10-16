const form = document.querySelector('#consent-form');
if (form) {
    // Progressive enhancement only. The server still requires a protected receipt,
    // explicit statements and a signer-reported access method without JavaScript.
    const previewChoice = form.querySelector('input[value="preview"]');
    previewChoice.disabled = true;
    document.querySelector('#pdf-preview')?.addEventListener('pdf-page-ready', () => { previewChoice.disabled = false; });
}
// The preview module uses top-level await. Register before importing so its first
// rendered-page event cannot precede the access-choice listener.
await import('./pdf-preview.mjs');
