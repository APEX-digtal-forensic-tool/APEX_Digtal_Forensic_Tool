/* Generated from canonical APEX schemas; run npm run contracts. */

export interface ReportVersion {
  report_version_id: string;
  report_id: string;
  case_id: string;
  version_number: number;
  previous_version_id: string | null;
  source_kind: "ANALYST_DRAFT" | "AI_DRAFT" | "IMPORTED_DRAFT" | "SYSTEM_ASSEMBLED_DATA" | "OTHER";
  source_reference_id: string | null;
  created_by: string;
  title: string;
  executive_summary: string;
  /**
   * @minItems 1
   * @maxItems 200
   */
  sections: [
    {
      section_id: string;
      section_type:
        | "CASE_OVERVIEW"
        | "ANALYSIS_PURPOSE"
        | "EVIDENCE"
        | "HASH_INTEGRITY"
        | "CHAIN_OF_CUSTODY"
        | "ANALYSIS_ENVIRONMENT"
        | "ANALYSIS_SCOPE"
        | "PARTIAL_STALE_WARNING"
        | "TIMEZONE"
        | "KEY_FINDINGS"
        | "FILE_SYSTEM"
        | "WINDOWS_ARTIFACT"
        | "BROWSER"
        | "MEDIA"
        | "TIMELINE"
        | "KEYWORD_SEARCH"
        | "AI_ASSISTANCE"
        | "MACHINE_CANDIDATE"
        | "LIMITATIONS"
        | "CONCLUSION"
        | "RECOMMENDATION"
        | "TECHNICAL_APPENDIX"
        | "OTHER";
      title: string;
      order: number;
      content_kind: "PLAIN_TEXT" | "MARKDOWN_SUBSET" | "STRUCTURED_DATA" | "REFERENCE_LIST" | "TABLE_DATA" | "OTHER";
      content: string;
      structured_data: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      };
      source_kind: "ANALYST_DRAFT" | "AI_DRAFT" | "IMPORTED_DRAFT" | "SYSTEM_ASSEMBLED_DATA" | "OTHER";
      /**
       * @maxItems 10000
       */
      source_resource_ids: string[];
      /**
       * @maxItems 1000
       */
      context_snapshot_ids: string[];
      /**
       * @maxItems 1000
       */
      citations: {
        id?: string | null;
        label?: string | null;
        case_id: string;
        evidence_id?: string | null;
        source_kind: string;
        source_id: string;
        file_id?: string | null;
        artifact_id?: string | null;
        timeline_event_id?: string | null;
        search_result_id?: string | null;
        source_path?: string | null;
        source_offset?: number | null;
        source_reference?: string | null;
        excerpt?: string | null;
        content_sha256?: string | null;
        created_at?: string | null;
        source_length?: number | null;
        encoding?: string | null;
        raw_locator?: {
          [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
        } | null;
      }[];
      is_partial: boolean;
      /**
       * @maxItems 1000
       */
      stale_reasons: string[];
      coverage: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      };
      /**
       * @maxItems 1000
       */
      warnings: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      }[];
      section_fingerprint: string;
    },
    ...{
      section_id: string;
      section_type:
        | "CASE_OVERVIEW"
        | "ANALYSIS_PURPOSE"
        | "EVIDENCE"
        | "HASH_INTEGRITY"
        | "CHAIN_OF_CUSTODY"
        | "ANALYSIS_ENVIRONMENT"
        | "ANALYSIS_SCOPE"
        | "PARTIAL_STALE_WARNING"
        | "TIMEZONE"
        | "KEY_FINDINGS"
        | "FILE_SYSTEM"
        | "WINDOWS_ARTIFACT"
        | "BROWSER"
        | "MEDIA"
        | "TIMELINE"
        | "KEYWORD_SEARCH"
        | "AI_ASSISTANCE"
        | "MACHINE_CANDIDATE"
        | "LIMITATIONS"
        | "CONCLUSION"
        | "RECOMMENDATION"
        | "TECHNICAL_APPENDIX"
        | "OTHER";
      title: string;
      order: number;
      content_kind: "PLAIN_TEXT" | "MARKDOWN_SUBSET" | "STRUCTURED_DATA" | "REFERENCE_LIST" | "TABLE_DATA" | "OTHER";
      content: string;
      structured_data: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      };
      source_kind: "ANALYST_DRAFT" | "AI_DRAFT" | "IMPORTED_DRAFT" | "SYSTEM_ASSEMBLED_DATA" | "OTHER";
      /**
       * @maxItems 10000
       */
      source_resource_ids: string[];
      /**
       * @maxItems 1000
       */
      context_snapshot_ids: string[];
      /**
       * @maxItems 1000
       */
      citations: {
        id?: string | null;
        label?: string | null;
        case_id: string;
        evidence_id?: string | null;
        source_kind: string;
        source_id: string;
        file_id?: string | null;
        artifact_id?: string | null;
        timeline_event_id?: string | null;
        search_result_id?: string | null;
        source_path?: string | null;
        source_offset?: number | null;
        source_reference?: string | null;
        excerpt?: string | null;
        content_sha256?: string | null;
        created_at?: string | null;
        source_length?: number | null;
        encoding?: string | null;
        raw_locator?: {
          [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
        } | null;
      }[];
      is_partial: boolean;
      /**
       * @maxItems 1000
       */
      stale_reasons: string[];
      coverage: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      };
      /**
       * @maxItems 1000
       */
      warnings: {
        [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
      }[];
      section_fingerprint: string;
    }[]
  ];
  /**
   * @maxItems 10000
   */
  context_snapshot_ids: string[];
  /**
   * @maxItems 10000
   */
  evidence_ids: string[];
  /**
   * @maxItems 10000
   */
  search_execution_ids: string[];
  /**
   * @maxItems 10000
   */
  timeline_revisions: number[];
  /**
   * @maxItems 10000
   */
  ai_assistance_request_ids: string[];
  /**
   * @maxItems 10000
   */
  ai_result_ids: string[];
  /**
   * @maxItems 10000
   */
  citation_ids: string[];
  partial_state: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  stale_state: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  coverage_summary: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  /**
   * @minItems 1
   * @maxItems 100
   */
  limitations: [string, ...string[]];
  analyzer_versions: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  /**
   * @maxItems 1000
   */
  source_revisions: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  }[];
  content_fingerprint: string;
  previous_content_fingerprint: string | null;
  review_state: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  approval_state: {
    [k: string]: string | number | boolean | null | JsonValue[] | {[key: string]: JsonValue};
  };
  created_at: string;
  report_schema_version: string;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
