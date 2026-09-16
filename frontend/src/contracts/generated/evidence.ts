/* Generated from canonical APEX schemas; run npm run contracts. */

export interface EvidenceRecord {
  id: string;
  case_id: string;
  display_name: string;
  format: "DIRECTORY" | "RAW" | "DD" | "IMG" | "E01" | "VHD" | "VHDX";
  status: "REGISTERED" | "HASHING" | "READY" | "FAILED";
  size_bytes: number;
  sector_size?: number | null;
  read_only: true;
  acquired_at?: string | null;
  registered_at: string;
  reader: {
    id: string;
    version: string;
  };
  capabilities: string[];
  hashes: {
    [k: string]: unknown;
  }[];
  metadata: {
    [k: string]: unknown;
  };
  fingerprint: {
    algorithm: "SHA256";
    value: string;
    size_bytes: number;
    reader_id: string;
    reader_version: string;
    created_at: string;
  } | null;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
