/** In-process key lookup — used when the verifier is the IDP itself, which has direct storage access. */
export function localKeyLookup(serviceKeyRepository) {
    return async (kid) => {
        const keys = await serviceKeyRepository.listPublishable();
        const match = keys.find((k) => k.kid === kid);
        if (!match) return null;
        return { publicKeyPem: Buffer.from(match.publicKey, 'base64').toString('utf8'), service: match.name };
    };
}
