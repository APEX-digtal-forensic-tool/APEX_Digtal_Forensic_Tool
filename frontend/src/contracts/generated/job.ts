/* Generated from canonical APEX schemas; run npm run contracts. */

export interface JobRecord {
  id: string;
  case_id: string;
  evidence_id: string | null;
  job_type:
    | "HASH"
    | "VERIFY"
    | "FS_INGEST"
    | "ARTIFACT"
    | "TIMELINE"
    | "INDEX"
    | "SEARCH"
    | "SEARCH_INDEX"
    | "AI_ENRICHMENT"
    | "REPORT_DRAFT"
    | "REPORT_EXPORT"
    | "MEDIA_EXTRACTION"
    | "TIMEZONE_DETECTION"
    | "CUSTODY_SNAPSHOT"
    | "KEYWORD_RECOMMENDATION";
  status: "QUEUED" | "RUNNING" | "PAUSING" | "PAUSED" | "RESUMING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "CANCELLED";
  progress: {
    current: number;
    total: number | null;
    unit: "BYTES" | "FILES" | "TASKS" | "UNKNOWN";
    /**
     * @deprecated
     * Legacy compatibility alias. New contracts use progress_percent.
     */
    percent?: number | null;
    processed_items: number;
    estimated_total_items: number | null;
    throughput_items_per_second: number | null;
    elapsed_seconds: number;
    estimated_remaining_seconds: number | null;
    estimate_confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
    current_analyzer: string | null;
    worker_count: number;
    cache_hits: number;
    cache_misses: number;
    partial_results_available: boolean;
    status: "QUEUED" | "RUNNING" | "PAUSING" | "PAUSED" | "RESUMING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "CANCELLED";
    /**
     * Estimated completion percentage; null when the total cannot be estimated.
     */
    progress_percent: number | null;
    discovered_items: number;
    skipped_items: number;
    warning_count: number;
    error_count: number;
    current_path: string | null;
  };
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested_at: string | null;
  warnings: {
    code: string;
    message_key: string;
    developer_message: string | null;
    source_id?: string | null;
    details: {
      [k: string]: unknown;
    };
  }[];
  errors: {
    code: string;
    message_key: string;
    developer_message: string | null;
    target?: string | null;
    retryable: boolean;
    details: {
      [k: string]: unknown;
    };
  }[];
  profile_id: string | null;
  priority: number;
  checkpoint_available: boolean;
  result_completeness: {
    is_partial: boolean;
    as_of: string;
    completed_scopes: (
      | "CASE"
      | "EVIDENCE"
      | "FILESYSTEM"
      | "REGISTRY"
      | "EVENTLOG"
      | "PREFETCH"
      | "BROWSER"
      | "MEDIA"
      | "TIMELINE"
      | "KEYWORD_SEARCH"
      | "REPORT"
      | "CHAIN_OF_CUSTODY"
    )[];
    pending_scopes: (
      | "CASE"
      | "EVIDENCE"
      | "FILESYSTEM"
      | "REGISTRY"
      | "EVENTLOG"
      | "PREFETCH"
      | "BROWSER"
      | "MEDIA"
      | "TIMELINE"
      | "KEYWORD_SEARCH"
      | "REPORT"
      | "CHAIN_OF_CUSTODY"
    )[];
    available_item_count: number;
    warning: string | null;
  };
  job_revision: number;
  /**
   * Filesystem index revision for INDEX jobs; null for non-index jobs.
   */
  index_revision: number | null;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
