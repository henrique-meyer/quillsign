import { getDocument, GlobalWorkerOptions, TextLayer, AnnotationMode } from '../vendor/pdfjs/build/pdf.mjs';

const preview = document.querySelector('#pdf-preview');
if (preview) {
    GlobalWorkerOptions.workerSrc = '/vendor/pdfjs/build/pdf.worker.mjs';
    const status = document.querySelector('#preview-status');
    const previous = document.querySelector('#previous-page');
    const next = document.querySelector('#next-page');
    const indicator = document.querySelector('#page-number');
    const zoom = document.querySelector('#pdf-zoom');
    const pageElement = preview.querySelector('.pdf-page');
    const canvas = preview.querySelector('canvas');
    const textContainer = preview.querySelector('.textLayer');
    let pdf, pageNumber = 1, sequence = 0, renderTask, textLayer;
    async function render() {
        const current = ++sequence;
        renderTask?.cancel(); textLayer?.cancel();
        previous.disabled = next.disabled = true;
        status.textContent = 'Loading page…';
        preview.dispatchEvent(new CustomEvent('pdf-page-loading'));
        try {
            const page = await pdf.getPage(pageNumber);
            if (current !== sequence) return;
            const base = page.getViewport({ scale: 1 });
            const scale = zoom.value === 'fit' ? Math.max(0.05, (preview.clientWidth - 24) / base.width) : Number(zoom.value);
            const viewport = page.getViewport({ scale });
            const density = Math.min(window.devicePixelRatio || 1, 2, 16384 / viewport.width, 16384 / viewport.height,
                Math.sqrt(8_000_000 / (viewport.width * viewport.height)));
            canvas.width = Math.max(1, Math.floor(viewport.width * density)); canvas.height = Math.max(1, Math.floor(viewport.height * density));
            canvas.style.width = pageElement.style.width = `${viewport.width}px`;
            canvas.style.height = pageElement.style.height = `${viewport.height}px`;
            pageElement.style.setProperty('--scale-factor', scale);
            pageElement.style.setProperty('--user-unit', page.userUnit);
            textContainer.replaceChildren();
            renderTask = page.render({ canvasContext: canvas.getContext('2d'), viewport,
                transform: density === 1 ? null : [density, 0, 0, density, 0, 0], annotationMode: AnnotationMode.ENABLE });
            await renderTask.promise;
            if (current !== sequence) return;
            const text = await page.getTextContent();
            if (current !== sequence) return;
            textLayer = new TextLayer({ textContentSource: text, container: textContainer, viewport });
            await textLayer.render();
            if (current !== sequence) return;
            indicator.textContent = `Page ${pageNumber} of ${pdf.numPages}`;
            status.textContent = 'Review each page. You can select text or open the PDF separately.';
            previous.disabled = pageNumber <= 1; next.disabled = pageNumber >= pdf.numPages;
            preview.dispatchEvent(new CustomEvent('pdf-page-ready', { detail: { pageNumber } }));
        } catch (error) {
            if (current !== sequence || error?.name === 'RenderingCancelledException' || error?.name === 'AbortException') return;
            status.textContent = preview.dataset.renderError || 'The preview could not be displayed. Open the PDF below, or reload this draft.';
        }
    }
    previous.addEventListener('click', () => { if (pageNumber > 1) { pageNumber--; render(); } });
    next.addEventListener('click', () => { if (pageNumber < pdf.numPages) { pageNumber++; render(); } });
    zoom.addEventListener('change', render);
    preview.addEventListener('pdf-page-request', event => {
        const requested = event.detail?.pageNumber;
        if (Number.isInteger(requested) && requested >= 1 && (!pdf || requested <= pdf.numPages)) {
            pageNumber = requested;
            if (pdf) render();
        }
    });
    let resizeTimer;
    new ResizeObserver(() => {
        if (pdf && zoom.value === 'fit') { clearTimeout(resizeTimer); resizeTimer = setTimeout(render, 120); }
    }).observe(preview);
    try {
        pdf = await getDocument({ url: preview.dataset.url, withCredentials: true, isEvalSupported: false, enableXfa: false,
            cMapUrl: '/vendor/pdfjs/cmaps/', cMapPacked: true, standardFontDataUrl: '/vendor/pdfjs/standard_fonts/',
            wasmUrl: '/vendor/pdfjs/wasm/', disableAutoFetch: true, disableRange: true }).promise;
        pageNumber = Math.min(pageNumber, pdf.numPages);
        await render();
    } catch {
        status.textContent = preview.dataset.loadError || 'The PDF is unavailable or your session expired. Reload the draft, or request a new email link.';
    }
}
