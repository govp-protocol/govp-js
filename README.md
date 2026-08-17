# `@govp/verifier`

Environment-neutral JavaScript verification for the open GOVP protocol.
It independently implements GOVP-1 parsing, signing bytes, Ed25519 verification,
GOVP-ID derivation, asset binding, canonical URL checks and GOVP-STATUS-1.
It also verifies GOVP-EXT-1 signed evidence envelopes with the same byte-exact
canonical input as the Python reference implementation. It also rebuilds and
verifies `org.govp.publication-batch/1` Merkle inclusion proofs locally.
It also implements the GOVP AI-1 receiving gate and reproduces the Python
admission codes from the same canonical-byte corpus.

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
npm install https://github.com/govp-protocol/govp-js/releases/download/v0.1.10/govp-verifier-0.1.10.tgz
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

## Verify an evidence envelope

```js
import { verifyEnvelope } from '@govp/verifier';

const result = await verifyEnvelope(envelope, { subjectBytes });
if (!result.ok) throw new Error(JSON.stringify(result.checks));
```

This operation is local. It verifies the signature, deterministic signing
input, subject digest, declared origin and registered reference shapes; it does
not fetch or independently validate external attestations.

## Receive GOVP AI-1 evidence

```js
import { receiveAi } from '@govp/verifier';

const reception = await receiveAi(canonicalEnvelopeBytes, { subjectBytes });
if (!reception.admitted) throw new Error(reception.code);
```

Admission validates structure and causal bindings only. It is not a trust,
regulatory-sufficiency or execution-authorization decision.

## Verify a static publication proof

```js
import { verifyEnvelope, verifyPublicationProof } from '@govp/verifier';

if (!(await verifyEnvelope(envelope)).ok) throw new Error('invalid envelope');
if (!verifyPublicationProof(envelope, proof, batch.payload.root)) {
  throw new Error('event is not included in the signed batch');
}
```

The verifier binds the signed event descriptor to its shard, reconstructs both
RFC 6962 paths and compares the exact batch root. It performs no network call.

## Conformance

The npm package contains the exact public vectors under exported paths:

```js
import vectors from '@govp/verifier/conformance/vectors.json' with { type: 'json' };
```

Run the implementation suite with `npm test`; the tests are included in the
published package, so this command also works after a registry install. The
suite tests every GOVP-1 vector, GOVP-STATUS-1, GOVP AI-1, the shared GOVP-EXT-1 corpus and
the exact Python publication roots and proofs for 7 and 10,000 events.

Specification and documentation: [govp.io](https://govp.io)  
Python reference implementation: [`govp`](https://pypi.org/project/govp/)  
License: Apache-2.0. The GOVP and Gemacode names remain subject to the
[trademark policy](TRADEMARKS.md).
