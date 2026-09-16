/* Generated from canonical APEX schemas; run npm run contracts. */

export interface ViewProjection {
  projection_id: string;
  case_id: string;
  resource_type:
    | "EVIDENCE"
    | "FILE_SYSTEM_NODE"
    | "ARTIFACT"
    | "REGISTRY"
    | "EVENT_LOG"
    | "PREFETCH"
    | "BROWSER"
    | "MEDIA"
    | "TIMELINE_EVENT"
    | "SEARCH_RESULT"
    | "MACHINE_CANDIDATE"
    | "CUSTODY_EVENT"
    | "CONTEXT_SNAPSHOT"
    | "OTHER";
  resource_id: string;
  view_mode: "SIMPLE" | "DETAILED" | "RAW";
  title: string;
  subtitle: string | null;
  summary: string | null;
  severity: string | null;
  badges: string[];
  primary_fields: {
    [k: string]: unknown;
  };
  secondary_fields: {
    [k: string]: unknown;
  };
  technical_fields: {
    [k: string]: unknown;
  };
  raw_fields: {
    [k: string]: unknown;
  };
  timestamps: {
    [k: string]: unknown;
  };
  timezone: string | null;
  confidence: number | null;
  partial_state: {
    [k: string]: unknown;
  };
  stale_state: {
    [k: string]: unknown;
  };
  warnings: {
    [k: string]: unknown;
  }[];
  citations: {
    [k: string]: unknown;
  }[];
  raw_locator: {
    [k: string]: unknown;
  } | null;
  available_actions: string[];
  source_revision: string | number | null;
  analyzer_id: string | null;
  analyzer_version: string | null;
  projection_version: string;
  created_at: string;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
