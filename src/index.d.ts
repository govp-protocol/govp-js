export type GovpFields = Record<string, string>;

export interface VerificationChecks {
  format: boolean;
  signature: boolean | null;
  "govp-id": boolean;
  canonical: boolean | null;
  asset: boolean | null;
}

export interface VerificationResult {
  ok: boolean;
  fields: GovpFields;
  checks: VerificationChecks;
  derivedGovpId: string | null;
  assetSha256: string | null;
  warnings: string[];
  bundle: boolean | null;
  /** @deprecated Verification uses the deterministic backend named by backend. */
  native: false;
  backend: string;
}

export interface StatusResult {
  currentlyTrusted: boolean | null;
  snapshotValid: boolean;
  /** @deprecated Use snapshotValid; this is a 0.1.x compatibility alias. */
  snapshotTrusted: boolean;
  checks: Record<string, boolean | null>;
  reasons: string[];
}

export interface EnvelopeResult {
  ok: boolean;
  checks: Record<string, boolean | null>;
  signingInputSha256: string | null;
  warnings: string[];
}

export interface PublicationDescriptor {
  id: string;
  key_id: string;
  signing_input_sha256: string;
  type: string;
}

export type PublicationProofStep = [hash: string, siblingOnRight: boolean];

export interface PublicationProof {
  batch_id: string;
  descriptor: PublicationDescriptor;
  entry_id: string;
  intra_proof: PublicationProofStep[];
  root: string;
  shard: number;
  shard_root: string;
  top_proof: PublicationProofStep[];
}

export const EMPTY_PUBLICATION_ROOT: string;
export function eventDescriptor(envelope: Record<string, unknown>): PublicationDescriptor;
export function publicationEntryId(descriptor: PublicationDescriptor): string;
export function publicationLeaf(descriptor: PublicationDescriptor): Uint8Array;
export function merkleRoot(leaves: Uint8Array[]): Uint8Array;
export function buildPublicationTree(
  descriptors: PublicationDescriptor[],
  batchId: string,
): { root: string; proofs: Record<string, PublicationProof> };
export function verifyPublicationProof(
  envelope: Record<string, unknown>,
  proof: PublicationProof,
  expectedRoot: string,
): boolean;

export const ENVELOPE_DOMAIN: string;
export function canonicalJson(value: unknown): string;
export function envelopeSigningInput(envelope: Record<string, unknown>): Uint8Array;
export function verifyEnvelope(
  envelope: Record<string, unknown>,
  options?: { subjectBytes?: Uint8Array | ArrayBuffer | null },
): Promise<EnvelopeResult>;

export interface VerifyOptions {
  fetchedUrl?: string | null;
  assetBytes?: Uint8Array | ArrayBuffer | null;
  bundle?: object | null;
}

export interface StatusOptions {
  fetchedUrl?: string | null;
  recordFetchedUrl?: string | null;
  now?: Date | number;
  maxAgeSeconds?: number;
  maxFutureSkewSeconds?: number;
}

export function trimFieldValue(value: unknown): string;
export function normalizeFieldName(value: unknown): string;
export function normalizeCanonical(value: unknown): string;
export function parseRecord(text: string): GovpFields;
export function loadJsonRecord(payload: unknown): { fields: GovpFields; bundle: object | null };
export function signingInput(fields: GovpFields): Uint8Array;
export function deriveGovpId(assetType: string, assetId: string, assetSha256: string): Promise<string | null>;
export function deriveKeyId(publicKey: string): Promise<string>;
export function verifyRecordSignature(fields: GovpFields): Promise<boolean | null>;
export function verifyFields(fields: GovpFields, options?: VerifyOptions): Promise<VerificationResult>;
export function verifyText(text: string, options?: VerifyOptions): Promise<VerificationResult>;
export function parseStatus(text: string): Record<string, unknown>;
export function evaluateStatus(fields: GovpFields, status: Record<string, unknown>, options?: StatusOptions): Promise<StatusResult>;

declare const GOVP: {
  EMPTY_PUBLICATION_ROOT: typeof EMPTY_PUBLICATION_ROOT;
  ENVELOPE_DOMAIN: typeof ENVELOPE_DOMAIN;
  RECORD_DOMAIN: string;
  TYPECODE: Record<string, string>;
  deriveGovpId: typeof deriveGovpId;
  deriveKeyId: typeof deriveKeyId;
  canonicalJson: typeof canonicalJson;
  buildPublicationTree: typeof buildPublicationTree;
  envelopeSigningInput: typeof envelopeSigningInput;
  eventDescriptor: typeof eventDescriptor;
  evaluateStatus: typeof evaluateStatus;
  loadJsonRecord: typeof loadJsonRecord;
  normalizeCanonical: typeof normalizeCanonical;
  normalizeFieldName: typeof normalizeFieldName;
  parseRecord: typeof parseRecord;
  parseStatus: typeof parseStatus;
  merkleRoot: typeof merkleRoot;
  publicationEntryId: typeof publicationEntryId;
  publicationLeaf: typeof publicationLeaf;
  signingInput: typeof signingInput;
  trimFieldValue: typeof trimFieldValue;
  verifyFields: typeof verifyFields;
  verifyEnvelope: typeof verifyEnvelope;
  verifyPublicationProof: typeof verifyPublicationProof;
  verifyRecordSignature: typeof verifyRecordSignature;
  verifyText: typeof verifyText;
};

export default GOVP;
