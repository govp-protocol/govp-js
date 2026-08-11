import { Point, hashes, verify as nobleVerify } from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

hashes.sha512 = sha512;

const encoder = new TextEncoder();
export const ENVELOPE_DOMAIN = 'GOVP::extension-envelope.v1\0';
const MAX_SAFE_INTEGER = 2 ** 53 - 1;
const CORE_KEYS = new Set([
  'govp', 'extension', 'type', 'id', 'issuer', 'subject', 'created_at', 'hash',
  'payload', 'references', 'evidence', 'origin', 'signature',
]);
const ORIGINS = new Set(['system_observed', 'artifact_derived', 'human_asserted', 'upstream_attested']);
const FORMATS = new Set([
  'application/vnd.in-toto+json',
  'application/vnd.dev.sigstore.bundle+json;version=0.3',
  'application/vnd.rekor.entry+json',
  'application/timestamp-reply',
]);
const TYPE = /^[a-z0-9]+(?:\.[a-z0-9-]+)+\/[1-9][0-9]*$/;
const EXTENSION = /^[a-z0-9]+(?:\.[a-z0-9-]+)+$/;
const VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/;
const SHA256 = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function exactKeys(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
}

function scalar(value, maximum = 200) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && !/[\0\r\n]/.test(value) && !containsUnpairedSurrogate(value);
}

function containsUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function validateJson(value, depth = 0) {
  if (depth > 64) throw new TypeError('envelope JSON exceeds the maximum depth');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (containsUnpairedSurrogate(value)) throw new TypeError('envelope strings must contain Unicode scalar values');
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new TypeError('envelope numbers must be interoperable safe integers');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) validateJson(item, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      validateJson(key, depth + 1);
      validateJson(item, depth + 1);
    }
    return;
  }
  throw new TypeError(`unsupported envelope JSON value: ${typeof value}`);
}

export function canonicalJson(value) {
  validateJson(value);
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${canonicalJson(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function concatenate(...arrays) {
  const length = arrays.reduce((total, value) => total + value.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const value of arrays) { result.set(value, offset); offset += value.length; }
  return result;
}

export function envelopeSigningInput(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new TypeError('envelope must be an object');
  }
  const unsigned = Object.fromEntries(Object.entries(envelope).filter(([key]) => key !== 'signature'));
  return concatenate(encoder.encode(ENVELOPE_DOMAIN), encoder.encode(canonicalJson(unsigned)));
}

function hex(bytes) { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(''); }
function decodeBase64(value) {
  if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new TypeError('invalid base64');
  if (typeof globalThis.Buffer !== 'undefined') return new Uint8Array(globalThis.Buffer.from(value, 'base64'));
  const binary = globalThis.atob(value); return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function httpsUrl(value, canonical = false) {
  try {
    if (typeof value !== 'string' || value.length > 2048) return false;
    const url = new URL(value);
    return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password && !url.hash
      && (!canonical || (url.pathname === '/.well-known/govp.txt' && !url.search));
  } catch { return false; }
}
function reference(value) {
  if (value?.type === 'govp') {
    const keys = new Set(Object.keys(value));
    return ['type', 'id', 'digest'].every((key) => keys.has(key))
      && [...keys].every((key) => ['type', 'id', 'digest', 'locator'].includes(key))
      && scalar(value.id) && DIGEST.test(value.digest)
      && (!keys.has('locator') || httpsUrl(value.locator));
  }
  return value?.type === 'external_attestation'
    && exactKeys(value, new Set(['type', 'format', 'digest', 'locator']))
    && FORMATS.has(value.format) && DIGEST.test(value.digest) && httpsUrl(value.locator);
}
function evidence(value) {
  const keys = value && typeof value === 'object' && !Array.isArray(value) ? new Set(Object.keys(value)) : new Set();
  return ['type', 'id', 'digest'].every((key) => keys.has(key))
    && [...keys].every((key) => ['type', 'id', 'digest', 'locator'].includes(key))
    && TYPE.test(value.type) && scalar(value.id) && DIGEST.test(value.digest)
    && (!keys.has('locator') || httpsUrl(value.locator));
}
function origin(value) {
  if (!exactKeys(value, new Set(['origin', 'observed_by', 'observation']))
      || !ORIGINS.has(value.origin) || !scalar(value.observed_by)) return false;
  return value.origin === 'human_asserted'
    ? value.observation === null
    : value.observation !== null && typeof value.observation === 'object' && !Array.isArray(value.observation);
}
function signatureShape(value) {
  try {
    return exactKeys(value, new Set(['alg', 'key_id', 'public_key', 'signing_input_sha256', 'value']))
      && value.alg === 'Ed25519' && DIGEST.test(value.key_id) && SHA256.test(value.signing_input_sha256)
      && decodeBase64(value.public_key).length === 32 && decodeBase64(value.value).length === 64;
  } catch { return false; }
}
function shape(value) {
  try { validateJson(value); } catch { return false; }
  return exactKeys(value, CORE_KEYS) && value.govp === 'GOVP-EXT-1'
    && exactKeys(value.extension, new Set(['id', 'version'])) && EXTENSION.test(value.extension.id) && VERSION.test(value.extension.version)
    && TYPE.test(value.type) && scalar(value.id)
    && exactKeys(value.issuer, new Set(['canonical', 'name'])) && httpsUrl(value.issuer.canonical, true) && scalar(value.issuer.name)
    && exactKeys(value.subject, new Set(['type', 'id'])) && scalar(value.subject.type) && scalar(value.subject.id)
    && TIMESTAMP.test(value.created_at)
    && exactKeys(value.hash, new Set(['alg', 'value'])) && value.hash.alg === 'sha256' && SHA256.test(value.hash.value)
    && value.payload !== null && typeof value.payload === 'object' && !Array.isArray(value.payload)
    && Array.isArray(value.references) && value.references.length <= 256 && value.references.every(reference)
    && Array.isArray(value.evidence) && value.evidence.length <= 256 && value.evidence.every(evidence)
    && origin(value.origin) && signatureShape(value.signature);
}
function littleEndian(bytes) { let result = 0n; for (let index = bytes.length - 1; index >= 0; index -= 1) result = (result << 8n) | BigInt(bytes[index]); return result; }
function strictPoint(bytes) { try { const point = Point.fromBytes(bytes, false); return !point.isSmallOrder() && point.isTorsionFree(); } catch { return false; } }

export async function verifyEnvelope(envelope, { subjectBytes = null } = {}) {
  const format = shape(envelope);
  const checks = { format, references: format, origin: format, 'key-id': format ? false : null, 'signing-input': format ? false : null, signature: format ? false : null, subject: null };
  if (!format) return { ok: false, checks, signingInputSha256: null, warnings: [] };
  const input = envelopeSigningInput(envelope); const inputHash = hex(sha256(input));
  const publicKey = decodeBase64(envelope.signature.public_key); const signature = decodeBase64(envelope.signature.value);
  checks['key-id'] = envelope.signature.key_id === `sha256:${hex(sha256(publicKey))}`;
  checks['signing-input'] = envelope.signature.signing_input_sha256 === inputHash;
  checks.signature = strictPoint(publicKey) && strictPoint(signature.subarray(0, 32))
    && littleEndian(signature.subarray(32)) < Point.CURVE().n
    && await nobleVerify(signature, input, publicKey, { zip215: false });
  if (subjectBytes !== null) checks.subject = hex(sha256(new Uint8Array(subjectBytes))) === envelope.hash.value;
  const ok = ['format', 'references', 'origin', 'key-id', 'signing-input', 'signature'].every((key) => checks[key] === true)
    && checks.subject !== false;
  return { ok, checks, signingInputSha256: inputHash, warnings: envelope.references.length ? [] : ['no-references'] };
}
