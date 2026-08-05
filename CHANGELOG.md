# Changelog

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
