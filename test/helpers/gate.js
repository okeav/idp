/**
 * Pauses the next call of `obj[method]` (matching `pred`) until `release()` — after it ran (default) or
 * before it runs — so a test can force a precise interleaving of two requests. `reached` resolves when
 * the paused call gets there.
 */
export function gate(obj, method, { pred = () => true, when = 'after' } = {}) {
    const original = obj[method];
    let release;
    const released = new Promise((r) => { release = r; });
    let markReached;
    const reached = new Promise((r) => { markReached = r; });
    let armed = true;
    obj[method] = async function gated(...args) {
        if (!armed || !pred(...args)) return original.apply(this, args);
        armed = false;
        if (when === 'before') {
            markReached();
            await released;
            return original.apply(this, args);
        }
        const result = await original.apply(this, args);
        markReached();
        await released;
        return result;
    };
    return { reached, release: () => release(), restore: () => { obj[method] = original; } };
}
