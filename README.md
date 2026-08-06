# `@govp/verifier`

Environment-neutral JavaScript verification for the open GOVP protocol.
It independently implements GOVP-1 parsing, signing bytes, Ed25519 verification,
GOVP-ID derivation, asset binding, canonical URL checks and GOVP-STATUS-1.

The package works in modern browsers and Node.js 20 or newer. It does not send
records, assets or results to GOVP.

## Install

Install the public package from the npm registry:

```bash
npm install @govp/verifier
```

For reproducible audits, the matching release tarball and `SHA256SUMS` are also
published with the signed GitHub release:

```bash
npm install https://github.com/govp-protocol/govp-js/releases/download/v0.1.8/govp-verifier-0.1.8.tgz
```

## Verify a record

```js
import { verifyText } from '@govp/verifier';

const result = await verifyText(recordText, {
  assetBytes,
  fetchedUrl: 'https://issuer.example/.well-known/govp/record.govp',
});
if (!result.ok) throw new Error(JSON.stringify(result.checks));
```

Every applicable check must pass. A valid signature proves that the matching
private key signed the record; it does not certify the publisher or the truth
of a statement.

## Evaluate live status

```js
import { evaluateStatus, parseRecord, parseStatus } from '@govp/verifier';

const result = await evaluateStatus(
  parseRecord(recordText),
  parseStatus(statusText),
  {
    recordFetchedUrl: 'https://issuer.example/.well-known/govp.txt',
    fetchedUrl: 'https://issuer.example/.well-known/govp/revoked.json',
  },
);
if (result.currentlyTrusted !== true) throw new Error(result.reasons.join(', '));
```

Live trust additionally requires `generated_at` within the default 300-second
maximum age and 60-second future clock-skew allowance. Pass
`maxAgeSeconds`, `maxFutureSkewSeconds` and an optional `now` explicitly for a
stricter or reproducible policy. Offline evaluation can return
`snapshotValid: true`, but always returns `currentlyTrusted: null` because a
saved file cannot prove liveness. `snapshotTrusted` is a deprecated 0.1.x alias
for `snapshotValid`. Network retrieval remains the caller's responsibility so
applications can enforce their own TLS, redirect and resource policies.

## Conformance

The npm package contains the exact public vectors under exported paths:

```js
import vectors from '@govp/verifier/conformance/vectors.json' with { type: 'json' };
```

Run the implementation suite with `npm test`; the tests are included in the
published package, so this command also works after a registry install. The
suite tests every GOVP-1 vector and the separately versioned GOVP-STATUS-1
suite.

Specification and documentation: [govp.io](https://govp.io)  
Python reference implementation: [`govp`](https://pypi.org/project/govp/)  
License: Apache-2.0. The GOVP and Gemacode names remain subject to the
[trademark policy](TRADEMARKS.md).
