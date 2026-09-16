/* Generated from canonical APEX schemas; run npm run contracts. */

export interface GuiContext {
  session_context_id: string;
  session_id: string;
  case_id: string;
  actor_id: string | null;
  locale: string;
  /**
   * IANA Time Zone Database identifier. UTC is accepted as the canonical zero-offset identifier.
   */
  timezone: string;
  current_route:
    | "CASE_OVERVIEW"
    | "EVIDENCE"
    | "FILE_SYSTEM"
    | "ARTIFACTS"
    | "REGISTRY"
    | "EVENT_LOG"
    | "PREFETCH"
    | "BROWSER"
    | "MEDIA"
    | "SEARCH"
    | "TIMELINE"
    | "CANDIDATES"
    | "CHAIN_OF_CUSTODY"
    | "REPORT"
    | "SETTINGS"
    | "UNKNOWN";
  current_panel: string | null;
  active_evidence_id: string | null;
  selected_file_node_ids: string[];
  selected_artifact_ids: string[];
  selected_timeline_event_ids: string[];
  selected_search_result_ids: string[];
  selected_media_artifact_ids: string[];
  selected_browser_artifact_ids: string[];
  selected_candidate_ids: string[];
  active_filters: {
    [k: string]: unknown;
  };
  active_sort: {
    [k: string]: unknown;
  };
  active_time_range: {
    [k: string]: unknown;
  };
  active_keyword_set_id: string | null;
  active_keyword_set_version: number | null;
  active_search_execution_id: string | null;
  active_timeline_revision: number | null;
  active_context_scope:
    | "case"
    | "evidence"
    | "filesystem"
    | "registry"
    | "eventlog"
    | "prefetch"
    | "browser"
    | "media"
    | "timeline"
    | "keyword_search"
    | "machine_candidate"
    | "chain_of_custody"
    | "report"
    | "selection";
  ui_preferences: {
    [k: string]: unknown;
  };
  context_revision: number;
  source_revision_fingerprint: string;
  is_partial: boolean;
  stale_reasons: string[];
  created_at: string;
  updated_at: string;
  expires_at: string | null;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
