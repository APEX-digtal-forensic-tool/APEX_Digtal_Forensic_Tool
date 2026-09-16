/* Generated from canonical APEX schemas; run npm run contracts. */

export interface ReportRecord {
  report_id: string;
  case_id: string;
  title: string;
  description: string | null;
  report_type:
    | "INVESTIGATION"
    | "TRIAGE"
    | "INCIDENT_RESPONSE"
    | "EVIDENCE_SUMMARY"
    | "CHAIN_OF_CUSTODY"
    | "TECHNICAL_APPENDIX"
    | "OTHER";
  locale: string;
  /**
   * IANA Time Zone Database identifier. UTC is accepted as the canonical zero-offset identifier.
   */
  timezone: string;
  status:
    | "DRAFT"
    | "REVIEW_REQUIRED"
    | "APPROVED"
    | "REJECTED"
    | "EXPORT_PREPARING"
    | "EXPORT_READY"
    | "EXPORTED"
    | "EXPORT_FAILED"
    | "ARCHIVED";
  active_version_id: string | null;
  latest_version_number: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  report_fingerprint: string;
  report_schema_version: string;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
