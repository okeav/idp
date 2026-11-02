import { KEY_STATUS } from '../config/constants.js';

export const DEFAULT_ROTATION_GRACE_SECONDS = 60 * 60;

/**
 * Whether a stored service key may verify tokens (and be published in the services JWKS).
 *
 * ACTIVE keys may. A ROTATING key — one its service replaced with a newer key — may only for
 * `serviceMesh.rotationGraceSeconds` after it was replaced: long enough for in-flight tokens and for
 * instances still running the old key during a rolling deploy, but not indefinitely. A service
 * rotates precisely when a key is suspected compromised, and an unbounded "rotating" state would keep
 * honouring the compromised key until some later rotation happened to retire it.
 *
 * `statusChangedAt` is written on every status change since 0.4.0; an older row falls back to its
 * `updatedAt`, which the status change also bumped.
 */
export function isKeyPublishable(doc, graceSeconds = DEFAULT_ROTATION_GRACE_SECONDS, now = Date.now()) {
    if (doc?.status === KEY_STATUS.ACTIVE) return true;
    if (doc?.status !== KEY_STATUS.ROTATING) return false;
    const since = doc.statusChangedAt ?? doc.updatedAt ?? doc.lastSeenAt;
    return Boolean(since) && new Date(since).getTime() + graceSeconds * 1000 > now;
}
