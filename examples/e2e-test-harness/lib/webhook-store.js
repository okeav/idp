// Captured deliveries received by this harness's own /webhooks/receiver
// endpoint — kept separately from the general activity log so the Webhooks
// test page can show full delivery detail (headers, signature verdict, raw
// body) without needing to re-parse activity-log entries.
const deliveries = [];
const MAX = 100;

export function recordWebhookDelivery(entry) {
    deliveries.push(entry);
    if (deliveries.length > MAX) deliveries.shift();
}

export function getWebhookDeliveries() {
    return deliveries;
}
