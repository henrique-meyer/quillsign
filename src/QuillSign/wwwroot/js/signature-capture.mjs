import SignaturePad from "../vendor/signature-pad/signature_pad.js";
import { imageDimensions } from "./signature-images.mjs";

const form = document.querySelector("#mark-capture");
const adoptForm = document.querySelector("#adopt-marks");
const byId = id => document.getElementById(id);
const panel = byId("adoption-preview");
const receipt = byId("preview-receipt");
const ack = byId("adoption-ack");
const nameConfirmed = byId("name-confirmed");
const tabs = [...form.querySelectorAll('[role="tab"]')];
const adopt = byId("adopt-button");
const prepare = byId("prepare-preview");
const status = byId("capture-status");
const error = byId("capture-error");
let busy = false, generation = 0, expiryTimer;
const pads = ["signature", "initials"].map(name => {
    const canvas = byId(`${name}-canvas`);
    const pad = new SignaturePad(canvas, { penColor: "#152b3c", minWidth: 1.2, maxWidth: 3, canvasContextOptions: { colorSpace: "srgb" } });
    pad.addEventListener("beginStroke", invalidate);
    byId(`clear-${name}`).addEventListener("click", () => { pad.clear(); invalidate(); status.textContent = `${name === "signature" ? "Signature" : "Initials"} cleared. Prepare a new preview when ready.`; });
    return { canvas, pad, width: 0 };
});

function invalidate() {
    generation++; clearTimeout(expiryTimer); receipt.value = ""; ack.checked = false; nameConfirmed.checked = false; adopt.disabled = true;
    error.hidden = true;
    panel.hidden = true; byId("signature-image").removeAttribute("src"); byId("initials-image").removeAttribute("src");
    status.textContent = "Marks changed. Prepare and review a new saved preview.";
}
function setBusy(value) {
    busy = value;
    for (const control of form.querySelectorAll("input,button")) control.disabled = value;
    for (const { pad } of pads) value ? pad.off() : pad.on();
    prepare.disabled = value; updateAdoption();
}
function resizePads() {
    if (busy || byId("drawn-marks").hidden) return;
    for (const item of pads) {
        const box = item.canvas.getBoundingClientRect(); if (!box.width) continue;
        const ratio = Math.min(Math.max(window.devicePixelRatio || 1, 1), 2, 2048 / box.width);
        const width = Math.round(box.width * ratio), height = Math.round(box.height * ratio);
        if (item.canvas.width === width && item.canvas.height === height) continue;
        const scale = item.width ? box.width / item.width : 1;
        const data = item.pad.toData().map(group => ({ ...group, minWidth: group.minWidth * scale, maxWidth: group.maxWidth * scale,
            points: group.points.map(point => ({ ...point, x: point.x * scale, y: point.y * scale })) }));
        item.canvas.width = width; item.canvas.height = height;
        item.canvas.getContext("2d", { colorSpace: "srgb" }).setTransform(ratio, 0, 0, ratio, 0, 0);
        item.pad.clear(); item.pad.fromData(data); item.width = box.width;
    }
}
const observer = new ResizeObserver(resizePads); for (const { canvas } of pads) observer.observe(canvas);
window.addEventListener("resize", resizePads);
form.addEventListener("input", () => { invalidate(); renderTypedSamples(); });
form.addEventListener("change", invalidate);
// Selecting a tab changes capture mode; only explicit preparation sends images.
function selectTab(tab) {
    if (busy || tab.getAttribute("aria-selected") === "true") return;
    invalidate(); form.elements.Method.value = tab.dataset.method;
    for (const item of tabs) {
        const selected = item === tab;
        item.setAttribute("aria-selected", String(selected)); item.tabIndex = selected ? 0 : -1;
        byId(item.getAttribute("aria-controls")).hidden = !selected;
    }
    resizePads();
}
for (const tab of tabs) {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", event => {
        if (busy || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const index = tabs.indexOf(tab);
        const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
        selectTab(tabs[next]); tabs[next].focus();
    });
}
function updateAdoption() { adopt.disabled = busy || !receipt.value || !ack.checked || !nameConfirmed.checked; }
ack.addEventListener("change", updateAdoption);
nameConfirmed.addEventListener("change", updateAdoption);

function canvas(width, height) {
    const result = document.createElement("canvas"); result.width = width; result.height = height; return result;
}
async function png(surface) {
    const blob = await new Promise(resolve => surface.toBlob(resolve, "image/png"));
    if (!blob || blob.size > 512 * 1024) throw new Error("This mark is too complex. Use a simpler, tightly framed image or draw/type it.");
    return blob;
}
function typed(value, maximum) {
    value = value.trim().normalize("NFC");
    if (!value || value.length > maximum || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) throw new Error("Enter a plain-text name and initials within the stated limits.");
    const surface = canvas(1600, 400); const context = surface.getContext("2d", { colorSpace: "srgb" });
    let size = 110; context.font = `${size}px cursive`;
    size = Math.min(size, size * 1440 / Math.max(context.measureText(value).width, 1));
    if (size < 20) throw new Error("This typed mark is too long to display clearly. Shorten it or use Draw/Upload.");
    context.font = `${size}px cursive`; context.fillStyle = "#152b3c"; context.textBaseline = "middle";
    context.fillText(value, 80, 200); return surface;
}
function renderTypedSamples() {
    for (const [input, target, maximum] of [["typed-name", "typed-signature-sample", 200], ["typed-initials", "typed-initials-sample", 20]]) {
        const surface = byId(target), context = surface.getContext("2d", { colorSpace: "srgb" });
        context.clearRect(0, 0, surface.width, surface.height);
        try { context.drawImage(typed(byId(input).value, maximum), 0, 0); } catch { /* Validation is announced on explicit preparation. */ }
    }
}
async function uploaded(input) {
    const file = input.files[0]; if (!file || file.size > 5 * 1024 * 1024) throw new Error("Choose both images, each no larger than 5 MiB.");
    imageDimensions(new Uint8Array(await file.arrayBuffer()));
    let bitmap;
    try {
        bitmap = await createImageBitmap(file); if (!bitmap.width || !bitmap.height || bitmap.width > 2048 || bitmap.height > 1024) throw new Error("Decoded dimensions exceed 2048 × 1024 pixels.");
        const surface = canvas(bitmap.width, bitmap.height); surface.getContext("2d", { colorSpace: "srgb" }).drawImage(bitmap, 0, 0);
        return await png(surface);
    } catch (problem) { throw new Error(problem.message || "The image could not be decoded. Try another PNG or JPEG."); }
    finally { bitmap?.close(); }
}
form.addEventListener("submit", async event => {
    event.preventDefault(); if (busy) return;
    invalidate(); const current = generation; error.hidden = true; const method = form.elements.Method.value;
    const body = new FormData(); body.append("__RequestVerificationToken", form.elements.__RequestVerificationToken.value); body.append("Method", method);
    // Capture descriptors before disabling controls; no autosave or adoption happens here.
    const name = byId("typed-name").value, initials = byId("typed-initials").value;
    setBusy(true); status.textContent = "Saving and verifying both marks…";
    try {
        let signatureBlob, initialsBlob;
        if (method === "Typed") {
            signatureBlob = await png(typed(name, 200)); initialsBlob = await png(typed(initials, 20));
            body.append("TypedName", name); body.append("TypedInitials", initials);
        } else if (method === "Drawn") {
            if (pads.some(({ pad }) => pad.isEmpty())) throw new Error("Draw both your signature and initials, or choose Type.");
            signatureBlob = await png(pads[0].canvas); initialsBlob = await png(pads[1].canvas);
        } else {
            signatureBlob = await uploaded(byId("signature-upload")); initialsBlob = await uploaded(byId("initials-upload"));
        }
        body.append("Signature", signatureBlob, "signature.png"); body.append("Initials", initialsBlob, "initials.png");
        const response = await fetch(form.action, { method: "POST", body, headers: { Accept: "application/json" }, cache: "no-store", referrerPolicy: "no-referrer" });
        if (response.status === 429) throw new Error("Too many requests. Wait before preparing another preview.");
        let data; try { data = await response.json(); } catch { throw new Error("The preview could not be confirmed. Reload the request or try later."); }
        if (!response.ok) throw new Error(data.message || "The preview could not be prepared.");
        if (current !== generation) return;
        const signatureImage = byId("signature-image"), initialsImage = byId("initials-image");
        signatureImage.src = `data:image/png;base64,${data.signature}`; initialsImage.src = `data:image/png;base64,${data.initials}`;
        await Promise.all([signatureImage.decode(), initialsImage.decode()]);
        const remaining = new Date(data.expiresAt).getTime() - Date.now();
        if (remaining <= 0 || current !== generation) throw new Error("This preview expired. Prepare it again.");
        receipt.value = data.receipt; byId("statement-version").value = data.statementVersion;
        byId("adoption-statement").textContent = data.statement;
        byId("preview-expiry").textContent = `Preview expires ${new Date(data.expiresAt).toLocaleTimeString()}. Preparing it again is an explicit new request.`;
        panel.hidden = false; status.textContent = "Saved preview ready. Review both marks and the adoption statement.";
        byId("preview-heading").focus();
        expiryTimer = setTimeout(() => { invalidate(); status.textContent = "The saved preview expired. Prepare and review it again."; }, remaining);
    } catch (problem) { invalidate(); error.textContent = problem.message || "The preview could not be prepared."; error.hidden = false; status.textContent = "No new adoption was recorded. Correct the issue and prepare a new preview."; }
    finally { setBusy(false); resizePads(); }
});
adoptForm.addEventListener("submit", event => {
    if (busy || !receipt.value || !ack.checked || !nameConfirmed.checked) { event.preventDefault(); return; }
    busy = true; adopt.disabled = true; status.textContent = "Confirming adoption…";
});
prepare.disabled = false;
renderTypedSamples();
window.addEventListener("pageshow", event => { if (event.persisted) { invalidate(); setBusy(false); resizePads(); } });
