const form = document.querySelector('[data-pdf-upload]');
if (form) {
    const file = form.querySelector('input[type="file"]');
    const error = form.querySelector('[data-upload-error]');
    const maximum = Number(form.dataset.maximumBytes);
    file.addEventListener('change', () => { error.hidden = true; error.textContent = ''; });
    form.addEventListener('submit', event => {
        if (file.files?.[0]?.size > maximum) {
            event.preventDefault();
            const mib = (maximum / 1048576).toLocaleString(undefined, { maximumFractionDigits: 3 });
            error.textContent = `Choose a PDF no larger than ${mib} MiB.`;
            error.hidden = false;
            error.focus();
        }
    });
}
