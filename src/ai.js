import { canonicalJson, verifyEnvelope } from './envelope.js';

export const AI_EXTENSION = Object.freeze({ id: 'org.govp.ai', version: '1.0.0' });
export const AI_TYPES = Object.freeze([
  'org.govp.ai-request/1',
  'org.govp.ai-result/1',
  'org.govp.ai-verification/1',
]);
export const AI1_CODES = Object.freeze([
  'AI1_INVALID_ENVELOPE',
  'AI1_EXTENSION_UNSUPPORTED',
  'AI1_TYPE_UNSUPPORTED',
  'AI1_PAYLOAD_INVALID',
  'AI1_REFERENCE_INVALID',
  'AI1_STATE_CONFLICT',
  'AI1_COMPARISON_UNSUPPORTED',
  'AI1_SUBJECT_REQUIRED',
  'AI1_SUBJECT_DIGEST_MISMATCH',
]);

const MAX_BYTES = 4 * 1024 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,63}$/;
const NONCE = /^[A-Za-z0-9_-]{22,200}$/;
const DISCLOSURES = new Set(['digest_only', 'sealed', 'private', 'public']);
const STATES = new Set(['SUCCEEDED', 'FAILED', 'DENIED', 'CANCELLED', 'TIMED_OUT', 'INDETERMINATE']);

function exact(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && Object.keys(value).every((field) => fields.includes(field));
}
function digest(value) { return typeof value === 'string' && DIGEST.test(value); }
function identifier(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 200
    && !/[\0\r\n]/.test(value);
}
function link(value) {
  return exact(value, ['id', 'digest']) && identifier(value.id) && digest(value.digest);
}
function committedInput(value) {
  return exact(value, ['digest', 'disclosure']) && digest(value.digest)
    && DISCLOSURES.has(value.disclosure);
}
function artifact(value) {
  if (!exact(value, ['artifact_digest', 'identity_basis', 'publisher', 'publisher_manifest_digest'])) return false;
  const valid = digest(value.artifact_digest)
    && ['artifact_observed', 'publisher_attested', 'provider_declared'].includes(value.identity_basis)
    && (value.publisher === null || identifier(value.publisher))
    && (value.publisher_manifest_digest === null || digest(value.publisher_manifest_digest));
  return valid && (value.identity_basis !== 'publisher_attested'
    || (value.publisher !== null && value.publisher_manifest_digest !== null));
}
function runtime(value) {
  return exact(value, ['artifact_digest', 'backend', 'hardware_class', 'deterministic_profile'])
    && digest(value.artifact_digest) && identifier(value.backend)
    && (value.hardware_class === null || identifier(value.hardware_class))
    && (value.deterministic_profile === null || identifier(value.deterministic_profile));
}
function requestPayload(payload) {
  const fields = ['kind', 'model', 'runtime', 'input', 'inference_parameters', 'seed', 'nonce', 'reproducibility', 'commitment'];
  if (!exact(payload, fields) || payload.kind !== 'request') return [false, 'AI1_PAYLOAD_INVALID'];
  const seedOk = payload.seed === null || (Number.isSafeInteger(payload.seed) && Math.abs(payload.seed) <= Number.MAX_SAFE_INTEGER);
  const valid = artifact(payload.model) && runtime(payload.runtime)
    && committedInput(payload.input) && committedInput(payload.inference_parameters)
    && seedOk && typeof payload.nonce === 'string' && NONCE.test(payload.nonce)
    && exact(payload.reproducibility, ['claimed', 'scope_digest'])
    && typeof payload.reproducibility.claimed === 'boolean'
    && digest(payload.reproducibility.scope_digest)
    && exact(payload.commitment, ['timing', 'externalized'])
    && payload.commitment.timing === 'pre_inference'
    && typeof payload.commitment.externalized === 'boolean';
  return [valid, valid ? null : 'AI1_PAYLOAD_INVALID'];
}
function resultPayload(payload) {
  const fields = ['kind', 'request', 'attempt_id', 'status', 'output_digest', 'reason_code', 'effective_model_digest', 'effective_runtime_digest', 'execution_metadata_digest'];
  if (!exact(payload, fields) || payload.kind !== 'result') return [false, 'AI1_PAYLOAD_INVALID'];
  if (!(link(payload.request) && identifier(payload.attempt_id) && STATES.has(payload.status)
    && digest(payload.effective_model_digest) && digest(payload.effective_runtime_digest)
    && digest(payload.execution_metadata_digest))) return [false, 'AI1_PAYLOAD_INVALID'];
  const stateOk = payload.status === 'SUCCEEDED'
    ? digest(payload.output_digest) && payload.reason_code === null
    : payload.output_digest === null && typeof payload.reason_code === 'string' && REASON.test(payload.reason_code);
  return [stateOk, stateOk ? null : 'AI1_STATE_CONFLICT'];
}
function verificationPayload(payload) {
  const fields = ['kind', 'request', 'result', 'method', 'verifier_relationship', 'environment_digest', 'observed_output_digest', 'comparison_profile', 'canonicalization_profile', 'match'];
  if (!exact(payload, fields) || payload.kind !== 'verification') return [false, 'AI1_PAYLOAD_INVALID'];
  if (!['exact', 'canonicalized'].includes(payload.comparison_profile)) return [false, 'AI1_COMPARISON_UNSUPPORTED'];
  const comparisonOk = payload.comparison_profile === 'exact'
    ? payload.canonicalization_profile === null : identifier(payload.canonicalization_profile);
  const valid = link(payload.request) && link(payload.result)
    && !(payload.request.id === payload.result.id && payload.request.digest === payload.result.digest)
    && payload.method === 'recomputation'
    && ['self', 'organizationally_separate', 'third_party'].includes(payload.verifier_relationship)
    && digest(payload.environment_digest) && digest(payload.observed_output_digest)
    && comparisonOk && typeof payload.match === 'boolean';
  return [valid, valid ? null : 'AI1_PAYLOAD_INVALID'];
}

export function validateAiPayload(envelope) {
  const { payload, references } = envelope;
  if (!Array.isArray(references)) return [false, 'AI1_REFERENCE_INVALID'];
  if (envelope.type === 'org.govp.ai-request/1') {
    const result = requestPayload(payload);
    if (!result[0]) return result;
    if (payload.commitment.externalized
      && !references.some((item) => item?.type === 'external_attestation')) return [false, 'AI1_REFERENCE_INVALID'];
    return [true, null];
  }
  if (envelope.type === 'org.govp.ai-result/1') {
    const result = resultPayload(payload);
    if (!result[0]) return result;
    const links = references.filter((item) => item?.type === 'govp');
    if (links.length !== 1 || links[0].id !== payload.request.id
      || links[0].digest !== payload.request.digest) return [false, 'AI1_REFERENCE_INVALID'];
    return [true, null];
  }
  if (envelope.type === 'org.govp.ai-verification/1') {
    const result = verificationPayload(payload);
    if (!result[0]) return result;
    const links = references.filter((item) => item?.type === 'govp');
    const expected = new Set([
      `${payload.request.id}\0${payload.request.digest}`,
      `${payload.result.id}\0${payload.result.digest}`,
    ]);
    const actual = new Set(links.map((item) => `${item.id}\0${item.digest}`));
    if (links.length !== 2 || actual.size !== expected.size
      || [...actual].some((item) => !expected.has(item))) return [false, 'AI1_REFERENCE_INVALID'];
    return [true, null];
  }
  return [false, 'AI1_TYPE_UNSUPPORTED'];
}

function rejected(code, envelope, checks, warnings = []) {
  return { admitted: false, code, envelope, checks, warnings };
}

export async function receiveAi(data, { subjectBytes = null } = {}) {
  const checks = { transport: false, l0: null, subject: null, 'ai-payload': null, references: null };
  if (!(data instanceof Uint8Array) || data.byteLength > MAX_BYTES) {
    return rejected('AI1_INVALID_ENVELOPE', null, checks);
  }
  let envelope;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(data);
    envelope = JSON.parse(text);
    if (canonicalJson(envelope) !== text) return rejected('AI1_INVALID_ENVELOPE', null, checks);
  } catch {
    return rejected('AI1_INVALID_ENVELOPE', null, checks);
  }
  checks.transport = true;
  if (envelope.extension?.id !== AI_EXTENSION.id || envelope.extension?.version !== AI_EXTENSION.version) {
    return rejected('AI1_EXTENSION_UNSUPPORTED', envelope, checks);
  }
  if (!AI_TYPES.includes(envelope.type)) return rejected('AI1_TYPE_UNSUPPORTED', envelope, checks);
  if (subjectBytes === null) return rejected('AI1_SUBJECT_REQUIRED', envelope, checks);
  let l0;
  try { l0 = await verifyEnvelope(envelope, { subjectBytes }); } catch {
    return rejected('AI1_INVALID_ENVELOPE', envelope, checks);
  }
  checks.l0 = l0.ok; checks.subject = l0.checks.subject;
  if (l0.checks.subject === false) return rejected('AI1_SUBJECT_DIGEST_MISMATCH', envelope, checks, l0.warnings);
  if (!l0.ok) return rejected('AI1_INVALID_ENVELOPE', envelope, checks, l0.warnings);
  const [valid, code] = validateAiPayload(envelope);
  checks['ai-payload'] = valid;
  checks.references = valid || code !== 'AI1_REFERENCE_INVALID';
  return { admitted: valid, code, envelope, checks, warnings: l0.warnings };
}

