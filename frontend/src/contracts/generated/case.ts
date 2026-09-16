/* Generated from canonical APEX schemas; run npm run contracts. */

export interface CaseRecord {
  id: string;
  name: string;
  description: string | null;
  status: "OPEN" | "CLOSED" | "ARCHIVED";
  locale: string;
  /**
   * IANA Time Zone Database identifier. UTC is accepted as the canonical zero-offset identifier.
   */
  timezone: string;
  created_at: string;
  created_by: string | null;
  closed_at: string | null;
  engine_version: string;
  metadata: {
    [k: string]: unknown;
  };
  timezone_decision_id: string | null;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
