# Changelog

## 0.1.6 — 2026-08-06

- verify the annotated release tag, signature and exact commit through GitHub's
  API instead of relying on checkout's local lightweight tag representation;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.5 — 2026-08-06

- fetch the complete Git tag history before enforcing the verified annotated-tag
  publication gate;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.4 — 2026-08-06

- publish only from a verified annotated Git tag, using npm Trusted Publishing
  with GitHub Actions OIDC and automatic registry provenance;
- remove the manual workflow trigger that can produce an OIDC workflow-name
  mismatch at npm;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.3 — 2026-08-06

- publish through npm Trusted Publishing with GitHub Actions OIDC and
  registry provenance;
- disallow token-based publication through the package access policy;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.2 — 2026-08-06

- make `npm install @govp/verifier` the primary installation path now that the
  public `@govp` scope is active;
- retain the signed GitHub release tarball as the reproducible audit path;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.1 — 2026-08-05

- publish a working signed-release installation path while npm scope ownership
  is being configured;
- keep the verifier API, protocol behavior and conformance inputs unchanged.

## 0.1.0 — 2026-08-05

- publish the first installable JavaScript GOVP verifier;
- reproduce all 18 GOVP-1 text and JSON conformance vectors;
- support browser and Node.js WebCrypto with `@noble/ed25519` fallback;
- expose parsing, signing-input, GOVP-ID, signature, asset and canonical checks;
- implement GOVP-STATUS-1 key authorization and record revocation;
- bundle the exact public conformance vectors and TypeScript declarations;
- prepare npm Trusted Publishing with automatic provenance.
