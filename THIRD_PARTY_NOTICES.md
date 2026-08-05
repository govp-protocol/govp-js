# Third-party notices

`@govp/verifier` depends on `@noble/ed25519` 3.1.0, Copyright Paul Miller,
licensed under the MIT License. Its package and license are available from
https://www.npmjs.com/package/@noble/ed25519 and
https://github.com/paulmillr/noble-ed25519.

The dependency is used as the portable Ed25519 fallback. Native WebCrypto
Ed25519 is preferred when the runtime supports it.
