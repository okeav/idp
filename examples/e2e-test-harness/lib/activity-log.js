// Simple in-memory ring buffer the whole harness shares — every idp-core
// hook and every received webhook delivery pushes an entry here, and the
// shared layout polls GET /api/activity to render a live "recent activity"
// panel on every page. Deliberately not persisted anywhere — restart the
// harness and it's empty again, which is exactly what you want for a
// throwaway manual-test run.
const MAX_ENTRIES = 300;
let entries = [];
let nextId = 1;

export function pushActivity(kind, label, detail) {
    entries.push({ id: nextId++, kind, label, detail, at: new Date().toISOString() });
    if (entries.length > MAX_ENTRIES) entries = entries.slice(-MAX_ENTRIES);
}

export function getActivitySince(sinceId = 0) {
    return entries.filter((e) => e.id > sinceId);
}

export function getAllActivity() {
    return entries;
}
