# Changelog

All notable changes to `@okeav/idp-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: a `MINOR` bump may include
backwards-incompatible changes, per the [semver spec's rules for 0.y.z](https://semver.org/#spec-item-4)).

## [0.2.0] - 2026-08-02

### Fixed

- **`POST /oauth2/authorize/deny` no longer accepts an unregistered `redirect_uri`.** The handler
  previously redirected to any well-formed `redirect_uri` in the request body without validating
  it against the named client's registered `redirectUris` — an open-redirect gap that the
  accept/confirm path never had. It now runs the same client-lookup and `redirect_uri` validation
  as `authorizeHandler`/`confirmConsentHandler`. **Behavior change:** a request with an unknown
  `client_id` or an unregistered `redirect_uri` now fails with `OAUTH_CLIENT_NOT_FOUND` /
  `INVALID_REDIRECT_URI` (400) instead of redirecting.
- **`refresh_token` grant no longer widens scope beyond the original consent.** The grant
  previously recomputed the issued scope from the client's *current* `allowedScopes` on every
  refresh, so a refresh exchange could silently grant broader access than the resource owner ever
  consented to (e.g. after an admin later expanded the client's `allowedScopes`). It now narrows
  the scopes captured at the original authorization against the client's current `allowedScopes`,
  so a refresh can only hold steady or shrink, never widen. **Behavior change:** the `scope` in a
  refresh response may now be narrower than before for clients whose `allowedScopes` exceeds what
  was actually consented to.
- **A `REVOKED` signing key's tokens are now actually rejected.** Token verification
  (`verifyWithAnyKey` → `getPublicKeyByKid`) previously resolved a key purely by matching `kid`
  against the registry, ignoring `status` entirely — a token signed by a key marked `REVOKED` (or
  even just removed from active use) still verified successfully as long as its `kid` was still
  configured. `getPublicKeyByKid` now refuses to resolve a `REVOKED` key, so previously-issued
  tokens signed by it now correctly fail with `INVALID_TOKEN` (401). `ACTIVE`/`ROTATING`/`RETIRED`
  keys are unaffected — a `RETIRED` key still verifies tokens issued during its rotation grace
  period, matching what `/keys/:kid` already allowed. **Behavior change:** if you were relying on
  `REVOKED` keys continuing to verify (unlikely, since that defeats the purpose of marking a key
  revoked), tokens signed by them will now be rejected.

### Docs

- Moved hand-written API reference and examples into this repo (`docs/`) as the source of truth
  for `@okeav/idp-core` documentation, previously maintained only on the consuming platform repo.
- Verified all 31 moved doc files against current source and corrected every discrepancy found —
  see the full file list in this release's commits for specifics (stale claims about scope
  recomputation, error codes that don't match what's actually thrown, an unusable copy-pasteable
  example, missing config options, and a few others).

## [0.1.0] - 2026-07-24

Initial release.
