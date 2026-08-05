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

  const offline = await evaluateStatus(fields, status);
  assert.equal(offline.snapshotTrusted, true);
  assert.equal(offline.currentlyTrusted, null);

  const online = await evaluateStatus(fields, status, {
    recordFetchedUrl: fields.canonical,
    fetchedUrl: status.canonical,
  });
  assert.equal(online.currentlyTrusted, true);
  assert.equal(Object.values(online.checks).every((value) => value === true), true);
});

test('tampering still fails independently of status', async () => {
  const valid = textVectors.vectors.find((vector) => vector.expected.core_valid);
  assert.ok(valid);
  const fields = parseRecord(valid.record);
  fields.publisher = 'Attacker';
  assert.equal((await verifyFields(fields)).ok, false);
  assert.equal((await verifyText(valid.record)).ok, true);
});
