(() => {
    "use strict";
    window.addEventListener("hashchange", () => window.location.reload());
    let fragment = window.location.hash;
    if (!fragment) return;
    try { window.history.replaceState(null, "", "/find/access"); }
    catch { return; }
    document.getElementById("lookup-pending")?.setAttribute("hidden", "");
    let code = /^#token=([A-Za-z0-9_-]{43,3800})$/.exec(fragment)?.[1] ?? null;
    fragment = "";
    const form = document.getElementById("lookup-code-form");
    const input = document.getElementById("lookup-code");
    const button = document.getElementById("lookup-begin");
    const status = document.getElementById("lookup-link-status");
    if (!form || !input || !button || !status) return;
    status.hidden = false;
    if (!code) { status.textContent = "This link is incomplete. Enter the full access code or use a fresh lookup link."; return; }
    input.disabled = true;
    button.textContent = "Continue with lookup link";
    status.textContent = "Your lookup link is ready. Continue, then choose Open my documents.";
    button.focus();
    form.addEventListener("submit", async event => {
        event.preventDefault();
        if (!code || button.disabled) return;
        button.disabled = true;
        const body = new FormData(form);
        body.set("code", code);
        code = null;
        try {
            const response = await fetch(form.action, { method: "POST", body, credentials: "same-origin", headers: { Accept: "application/json" } });
            body.delete("code");
            if (response.ok) { window.location.replace("/find/access"); return; }
        } catch { body.delete("code"); }
        status.textContent = "The link could not be prepared. Return to access entry and open your link again, or enter its access code.";
    });
    window.addEventListener("pageshow", event => { if (event.persisted) window.location.replace("/find/access"); });
})();
