import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import {
  deriveKeyId,
  evaluateStatus,
  loadJsonRecord,
  parseRecord,
  parseStatus,
  signingInput,
  verifyFields,
  verifyText,
} from '../src/index.js';

const textVectors = JSON.parse(await readFile(new URL(
  '../conformance/vectors.json', import.meta.url,
), 'utf8'));
const jsonVectors = JSON.parse(await readFile(new URL(
  '../conformance/json-vectors.json', import.meta.url,
), 'utf8'));
const statusVectors = JSON.parse(await readFile(new URL(
  '../conformance/status-vectors.json', import.meta.url,
), 'utf8'));
const STATUS_NOW = Date.parse('2026-08-05T22:09:00Z');

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

test('all GOVP-1 text vectors reproduce the normative results', async () => {
  assert.equal(textVectors.domain, 'GOVP::record.v1\\0');
  for (const vector of textVectors.vectors) {
    const fields = parseRecord(vector.record);
    const result = await verifyFields(fields);
    assert.equal(fields['govp-id'], vector.expected.govp_id, `${vector.name}: id`);
    assert.equal(result.checks.format, vector.expected.format_ok, `${vector.name}: format`);
    assert.equal(result.checks.signature, vector.expected.signature_ok, `${vector.name}: signature`);
    assert.equal(result.checks['govp-id'], vector.expected.govpid_ok, `${vector.name}: govp-id`);
    assert.equal(result.ok, vector.expected.core_valid, `${vector.name}: core`);
    assert.equal(
      await sha256Hex(signingInput(fields)),
      vector.expected.signing_input_sha256,
      `${vector.name}: signing input`,
    );
  }
});

test('all GOVP-1 JSON vectors load or reject identically', async () => {
  for (const vector of jsonVectors.vectors) {
    if (vector.expected.load_ok) {
      const loaded = loadJsonRecord(vector.payload);
      const result = await verifyFields(loaded.fields, { bundle: loaded.bundle });
      assert.equal(result.ok, vector.expected.core_valid, vector.name);
    } else {
      assert.throws(
        () => loadJsonRecord(vector.payload),
        new RegExp(vector.expected.error),
        vector.name,
      );
    }
  }
});

test('GOVP-STATUS-1 vectors reproduce format and revocation decisions', async () => {
  const recordText = await readFile(new URL('./fixtures/govp.io.govp.txt', import.meta.url), 'utf8');
  const fields = parseRecord(recordText);
  for (const vector of statusVectors.vectors) {
    const result = await evaluateStatus(fields, vector.status);
    assert.equal(
      result.checks['status-format'],
      vector.expected.schema_valid,
      vector.name,
    );
  }
  const revoked = await evaluateStatus(fields, statusVectors.vectors[1].status);
  assert.equal(revoked.checks['record-not-revoked'], false);
});

test('live status requires exact online bindings and an active key', async () => {
  const recordText = await readFile(new URL('./fixtures/govp.io.govp.txt', import.meta.url), 'utf8');
  const statusText = await readFile(new URL('./fixtures/govp.io-status.json', import.meta.url), 'utf8');
  const fields = parseRecord(recordText);
  const status = parseStatus(statusText);
  assert.equal(
    await deriveKeyId(fields['public-key']),
    status.keys[0].key_id,
  );

  const offline = await evaluateStatus(fields, status, { now: STATUS_NOW });
  assert.equal(offline.snapshotValid, true);
  assert.equal(offline.snapshotTrusted, true);
  assert.equal(offline.currentlyTrusted, null);

  const online = await evaluateStatus(fields, status, {
    recordFetchedUrl: fields.canonical,
    fetchedUrl: status.canonical,
    now: STATUS_NOW,
  });
  assert.equal(online.currentlyTrusted, true);
  assert.equal(Object.values(online.checks).every((value) => value === true), true);
});

test('live status rejects stale replay and future timestamps', async () => {
  const recordText = await readFile(new URL('./fixtures/govp.io.govp.txt', import.meta.url), 'utf8');
  const statusText = await readFile(new URL('./fixtures/govp.io-status.json', import.meta.url), 'utf8');
  const fields = parseRecord(recordText);
  const base = parseStatus(statusText);
  const options = {
    recordFetchedUrl: fields.canonical,
    fetchedUrl: base.canonical,
    now: STATUS_NOW,
  };

  const stale = await evaluateStatus(fields, {
    ...base,
    generated_at: '2026-08-05T22:03:59Z',
  }, options);
  assert.equal(stale.snapshotValid, true);
  assert.equal(stale.checks['status-fresh'], false);
  assert.equal(stale.currentlyTrusted, false);

  const future = await evaluateStatus(fields, {
    ...base,
    generated_at: '2026-08-05T22:10:01Z',
  }, options);
  assert.equal(future.snapshotValid, true);
  assert.equal(future.checks['status-fresh'], false);
  assert.equal(future.currentlyTrusted, false);
});

test('status decisions use verified normalized fields and cannot miss revocation aliases', async () => {
  const recordText = await readFile(new URL('./fixtures/govp.io.govp.txt', import.meta.url), 'utf8');
  const statusText = await readFile(new URL('./fixtures/govp.io-status.json', import.meta.url), 'utf8');
  const fields = parseRecord(recordText);
  const status = parseStatus(statusText);
  status.revoked_records.push({
    govp_id: fields['govp-id'],
    revoked_at: '2026-08-05T22:08:00Z',
    reason: 'withdrawn',
  });
  const aliased = { ...fields, 'Govp-ID': fields['govp-id'] };
  delete aliased['govp-id'];

  const result = await evaluateStatus(aliased, status, {
    recordFetchedUrl: fields.canonical,
    fetchedUrl: status.canonical,
    now: STATUS_NOW,
  });
  assert.equal(result.checks.core, true);
  assert.equal(result.checks['record-not-revoked'], false);
  assert.equal(result.currentlyTrusted, false);
});

test('strict Ed25519 encodings and insecure browser contexts fail deterministically', async () => {
  const valid = textVectors.vectors.find((vector) => vector.expected.core_valid);
  const fields = parseRecord(valid.record);
  const identity = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
  const signature = Buffer.from(fields.signature, 'base64');
  const order = 2n ** 252n + 27742317777372353535851937790883648493n;
  const highS = Buffer.alloc(32);
  let scalar = order;
  for (let index = 0; index < 32; index += 1) {
    highS[index] = Number(scalar & 0xffn);
    scalar >>= 8n;
  }

  assert.equal((await verifyFields({
    ...fields,
    'public-key': identity.toString('base64'),
  })).checks.signature, false);
  assert.equal((await verifyFields({
    ...fields,
    signature: Buffer.concat([identity, signature.subarray(32)]).toString('base64'),
  })).checks.signature, false);
  assert.equal((await verifyFields({
    ...fields,
    signature: Buffer.concat([signature.subarray(0, 32), highS]).toString('base64'),
  })).checks.signature, false);

  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.equal((await verifyText(valid.record)).ok, true);
  } finally {
    if (cryptoDescriptor) Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
  }
});

test('tampering still fails independently of status', async () => {
  const valid = textVectors.vectors.find((vector) => vector.expected.core_valid);
  assert.ok(valid);
  const fields = parseRecord(valid.record);
  fields.publisher = 'Attacker';
  assert.equal((await verifyFields(fields)).ok, false);
  assert.equal((await verifyText(valid.record)).ok, true);
});
