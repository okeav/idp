// Dev-mode stand-in for "send an email." The idp-core hooks that would
// normally trigger a real mailer instead write here, and the corresponding
// test page reads the latest entry for the email you just submitted and
// prints the raw token/code on screen — so you can copy it into the next
// step of the flow without ever leaving the browser.
const store = new Map(); // email -> array of entries, most recent last

export function recordDevToken(email, kind, data) {
    const key = email.toLowerCase();
    const list = store.get(key) || [];
    list.push({ kind, data, at: new Date().toISOString() });
    store.set(key, list);
}

export function latestDevToken(email, kind) {
    const list = store.get(email.toLowerCase()) || [];
    return [...list].reverse().find((e) => e.kind === kind) || null;
}
