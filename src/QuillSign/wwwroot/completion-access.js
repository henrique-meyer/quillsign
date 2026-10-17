(() => {
    "use strict";
    // An already-open entry tab may receive a new fragment without a document load.
    window.addEventListener("hashchange", () => window.location.reload());
    let fragment = window.location.hash;
    if (!fragment) return;
    // Remove private transport from history before rendering or making any request.
    try { window.history.replaceState(null, "", "/complete/access"); }
    catch { return; }
    document.getElementById("completion-pending")?.setAttribute("hidden", "");
    let code = /^#token=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1] ?? null;
    fragment = "";
    const form = document.getElementById("completion-code-form");
    const input = document.getElementById("completion-code");
    const button = document.getElementById("completion-begin");
    const status = document.getElementById("completion-link-status");
    if (!form || !input || !button || !status) return;
    status.hidden = false;
    if (!code) { status.textContent = "This link is incomplete. Enter the access code or contact the sender for another copy."; return; }
    input.disabled = true;
    button.textContent = "Continue with completion link";
    status.textContent = "Your completion link is ready. Continue to prepare it, then select Open records.";
    form.addEventListener("submit", async event => {
        event.preventDefault();
        if (!code || button.disabled) return;
        button.disabled = true;
        const body = new FormData(form);
        body.set("code", code);
        code = null;
        try {
            const response = await fetch(form.action, {method: "POST", body, credentials: "same-origin", headers: {Accept: "application/json"}});
            body.delete("code");
            if (response.ok) { window.location.replace("/complete/access"); return; }
        } catch { body.delete("code"); }
        status.textContent = "The link could not be prepared. Return to access entry and open your link again, or enter its access code.";
    });
    window.addEventListener("pageshow", event => { if (event.persisted) window.location.replace("/complete/access"); });
})();
