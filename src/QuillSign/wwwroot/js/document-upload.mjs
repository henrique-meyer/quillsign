const form = document.querySelector('[data-document-upload]');
if (form) {
    const file = form.querySelector('input[type="file"]');
    const error = form.querySelector('[data-upload-error]');
    const maximum = Number(form.dataset.maximumBytes);
    const extensions = form.dataset.extensions.split(',');
    file.addEventListener('change', () => { error.hidden = true; error.textContent = ''; });
    form.addEventListener('submit', event => {
        const selected = file.files?.[0];
        const extension = selected?.name.slice(selected.name.lastIndexOf('.')).toLowerCase();
        if (file.files?.length !== 1 || !extensions.includes(extension) || selected.size > maximum) {
            event.preventDefault();
            const mib = (maximum / 1048576).toLocaleString(undefined, { maximumFractionDigits: 3 });
            error.textContent = `Choose one supported document (${extensions.join(', ')}) no larger than ${mib} MiB.`;
            error.hidden = false;
            error.focus();
        }
    });
}
