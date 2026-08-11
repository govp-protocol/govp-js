import { sha256 } from '@noble/hashes/sha2.js';

import { canonicalJson } from './envelope.js';

const encoder = new TextEncoder();
const SHA256 = /^[0-9a-f]{64}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const TYPE = /^[a-z0-9]+(?:\.[a-z0-9-]+)+\/[1-9][0-9]*$/;
const DESCRIPTOR_KEYS = new Set(['id', 'key_id', 'signing_input_sha256', 'type']);
const SHARDS = 256;

function concatenate(...arrays) {
  const size = arrays.reduce((total, value) => total + value.length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const value of arrays) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new TypeError('invalid SHA-256');
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

function exactDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)
      || Object.keys(descriptor).length !== DESCRIPTOR_KEYS.size
      || !Object.keys(descriptor).every((key) => DESCRIPTOR_KEYS.has(key))) {
    throw new TypeError('publication descriptor has missing or unknown members');
  }
  if (typeof descriptor.id !== 'string' || descriptor.id.length < 1 || descriptor.id.length > 256) {
    throw new TypeError('event id is invalid');
  }
  if (!KEY_ID.test(descriptor.key_id)) throw new TypeError('event key_id is invalid');
  if (!SHA256.test(descriptor.signing_input_sha256)) {
    throw new TypeError('event signing_input_sha256 is invalid');
  }
  if (!TYPE.test(descriptor.type)) throw new TypeError('event type is invalid');
  return {
    id: descriptor.id,
    key_id: descriptor.key_id,
    signing_input_sha256: descriptor.signing_input_sha256,
    type: descriptor.type,
  };
}

export const EMPTY_PUBLICATION_ROOT = hex(sha256(new Uint8Array()));

export function eventDescriptor(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new TypeError('event envelope is invalid');
  }
  return exactDescriptor({
    id: envelope.id,
    key_id: envelope.signature?.key_id,
    signing_input_sha256: envelope.signature?.signing_input_sha256,
    type: envelope.type,
  });
}

export function publicationEntryId(descriptor) {
  const valid = exactDescriptor(descriptor);
  return hex(sha256(concatenate(
    encoder.encode(valid.id),
    Uint8Array.of(0),
    encoder.encode(valid.signing_input_sha256),
  )));
}

export function publicationLeaf(descriptor) {
  const valid = exactDescriptor(descriptor);
  return sha256(concatenate(Uint8Array.of(0), encoder.encode(canonicalJson(valid))));
}

function largestPowerLessThan(value) {
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
}

function rangeRoot(leaves, start, end, cache) {
  const key = `${start}:${end}`;
  if (cache.has(key)) return cache.get(key);
  const length = end - start;
  let result;
  if (length === 0) result = fromHex(EMPTY_PUBLICATION_ROOT);
  else if (length === 1) result = leaves[start];
  else {
    const split = largestPowerLessThan(length);
    result = sha256(concatenate(
      Uint8Array.of(1),
      rangeRoot(leaves, start, start + split, cache),
      rangeRoot(leaves, start + split, end, cache),
    ));
  }
  cache.set(key, result);
  return result;
}

export function merkleRoot(leaves) {
  if (!Array.isArray(leaves) || !leaves.every((leaf) => leaf instanceof Uint8Array)) {
    throw new TypeError('Merkle leaves must be Uint8Array values');
  }
  return rangeRoot(leaves, 0, leaves.length, new Map());
}

function auditPath(leaves, index, cache = new Map()) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError('Merkle proof index is outside the tree');
  }
  function walk(start, end, relative) {
    const length = end - start;
    if (length <= 1) return [];
    const split = largestPowerLessThan(length);
    if (relative < split) {
      return [
        ...walk(start, start + split, relative),
        [hex(rangeRoot(leaves, start + split, end, cache)), true],
      ];
    }
    return [
      ...walk(start + split, end, relative - split),
      [hex(rangeRoot(leaves, start, start + split, cache)), false],
    ];
  }
  return walk(0, leaves.length, index);
}

function foldPath(leaf, path) {
  if (!Array.isArray(path) || path.length > 64) throw new TypeError('Merkle path is invalid');
  let value = leaf;
  for (const step of path) {
    if (!Array.isArray(step) || step.length !== 2 || !SHA256.test(step[0])
        || typeof step[1] !== 'boolean') throw new TypeError('Merkle path step is invalid');
    const sibling = fromHex(step[0]);
    value = step[1]
      ? sha256(concatenate(Uint8Array.of(1), value, sibling))
      : sha256(concatenate(Uint8Array.of(1), sibling, value));
  }
  return value;
}

export function buildPublicationTree(descriptors, batchId) {
  if (!Array.isArray(descriptors) || descriptors.length === 0) {
    throw new TypeError('publication batch must contain at least one event');
  }
  if (typeof batchId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(batchId)) {
    throw new TypeError('batch_id is invalid');
  }
  const entries = descriptors.map((item) => {
    const descriptor = exactDescriptor(item);
    return { descriptor, entryId: publicationEntryId(descriptor) };
  }).sort((left, right) => (left.entryId < right.entryId ? -1 : left.entryId > right.entryId ? 1 : 0));
  if (new Set(entries.map(({ descriptor }) => descriptor.id)).size !== entries.length
      || new Set(entries.map(({ entryId }) => entryId)).size !== entries.length) {
    throw new TypeError('publication batch contains a duplicate event');
  }
  const buckets = Array.from({ length: SHARDS }, () => []);
  for (const entry of entries) buckets[Number.parseInt(entry.entryId.slice(-2), 16)].push(entry);
  const shardLeaves = buckets.map((bucket) => bucket.map(({ descriptor }) => publicationLeaf(descriptor)));
  const shardRoots = shardLeaves.map((leaves) => merkleRoot(leaves));
  const root = hex(merkleRoot(shardRoots));
  const proofs = {};
  const topCache = new Map();
  buckets.forEach((bucket, shard) => {
    const intraCache = new Map();
    bucket.forEach(({ descriptor, entryId }, index) => {
      proofs[entryId] = {
        batch_id: batchId,
        descriptor,
        entry_id: entryId,
        intra_proof: auditPath(shardLeaves[shard], index, intraCache),
        root,
        shard,
        shard_root: hex(shardRoots[shard]),
        top_proof: auditPath(shardRoots, shard, topCache),
      };
    });
  });
  return { root, proofs };
}

export function verifyPublicationProof(envelope, proof, expectedRoot) {
  try {
    if (!SHA256.test(expectedRoot) || !proof || typeof proof !== 'object' || Array.isArray(proof)) return false;
    const descriptor = eventDescriptor(envelope);
    if (canonicalJson(proof.descriptor) !== canonicalJson(descriptor)) return false;
    const entryId = publicationEntryId(descriptor);
    const shard = Number.parseInt(entryId.slice(-2), 16);
    if (proof.entry_id !== entryId || proof.shard !== shard || proof.root !== expectedRoot) return false;
    const intra = foldPath(publicationLeaf(descriptor), proof.intra_proof);
    if (proof.shard_root !== hex(intra) || !Array.isArray(proof.top_proof)
        || proof.top_proof.length !== 8) return false;
    return hex(foldPath(intra, proof.top_proof)) === expectedRoot;
  } catch {
    return false;
  }
}
