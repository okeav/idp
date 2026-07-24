// Hand-rolled base64url <-> ArrayBuffer glue — this is exactly what
// @simplewebauthn/browser does under the hood. Written by hand here instead
// of adding that package as a dependency, since the harness only needs these
// two conversions plus the two navigator.credentials calls.

function b64urlToBuffer(b64url) {
  const pad = b64url + '='.repeat((4 - (b64url.length % 4)) % 4);
  const b64 = pad.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function optionsToCreateOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    user: { ...options.user, id: b64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
  };
}

function optionsToGetOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
  };
}

function credentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      attestationObject: bufferToB64url(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  };
}

function assertionToJSON(cred) {
  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      authenticatorData: bufferToB64url(cred.response.authenticatorData),
      signature: bufferToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : undefined,
    },
  };
}

async function webauthnRegister(authPrefix) {
  const optRes = await callApi(authPrefix + '/webauthn/registration/options', { method: 'POST', body: {} });
  if (!optRes.ok) return optRes;
  const cred = await navigator.credentials.create({ publicKey: optionsToCreateOptions(optRes.body) });
  const response = credentialToJSON(cred);
  return callApi(authPrefix + '/webauthn/registration/verify', { method: 'POST', body: { response, name: 'Harness browser passkey' } });
}

async function webauthnLogin(authPrefix, email) {
  const optRes = await callApi(authPrefix + '/webauthn/authentication/options', { method: 'POST', body: email ? { email } : {} });
  if (!optRes.ok) return optRes;
  const cred = await navigator.credentials.get({ publicKey: optionsToGetOptions(optRes.body) });
  const response = assertionToJSON(cred);
  return callApi(authPrefix + '/webauthn/authentication/verify', { method: 'POST', body: { response } });
}

async function webauthnMfa(authPrefix, mfaChallengeToken) {
  const optRes = await callApi(authPrefix + '/webauthn/mfa/options', { method: 'POST', body: { mfaChallengeToken } });
  if (!optRes.ok) return optRes;
  const cred = await navigator.credentials.get({ publicKey: optionsToGetOptions(optRes.body) });
  const response = assertionToJSON(cred);
  return callApi(authPrefix + '/webauthn/mfa/verify', { method: 'POST', body: { mfaChallengeToken, response } });
}
