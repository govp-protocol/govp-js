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
  RECORD_DOMAIN: string;
  TYPECODE: Record<string, string>;
  deriveGovpId: typeof deriveGovpId;
  deriveKeyId: typeof deriveKeyId;
  evaluateStatus: typeof evaluateStatus;
  loadJsonRecord: typeof loadJsonRecord;
  normalizeCanonical: typeof normalizeCanonical;
  normalizeFieldName: typeof normalizeFieldName;
  parseRecord: typeof parseRecord;
  parseStatus: typeof parseStatus;
  signingInput: typeof signingInput;
  trimFieldValue: typeof trimFieldValue;
  verifyFields: typeof verifyFields;
  verifyRecordSignature: typeof verifyRecordSignature;
  verifyText: typeof verifyText;
};

export default GOVP;
