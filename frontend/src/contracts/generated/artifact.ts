/* Generated from canonical APEX schemas; run npm run contracts. */

export interface ArtifactRecord {
  id: string;
  artifact_id: string;
  case_id: string;
  evidence_id: string;
  source_file_node_id: string;
  source_object_id: string | null;
  artifact_type:
    | "REGISTRY_KEY"
    | "REGISTRY_VALUE"
    | "REGISTRY_AUTORUN"
    | "REGISTRY_USB_DEVICE"
    | "REGISTRY_TIMEZONE"
    | "REGISTRY_USERASSIST"
    | "EVENT_LOG_RECORD"
    | "PREFETCH_EXECUTION"
    | "MEDIA_IMAGE"
    | "MEDIA_VIDEO"
    | "MEDIA_AUDIO"
    | "BROWSER_PROFILE"
    | "BROWSER_VISIT"
    | "BROWSER_SEARCH"
    | "BROWSER_DOWNLOAD"
    | "BROWSER_COOKIE"
    | "BROWSER_CREDENTIAL"
    | "BROWSER_CACHE_ENTRY"
    | "BROWSER_DELETED_SQLITE_ROW"
    | "BROWSER_PRIVATE_MODE_CANDIDATE"
    | "COMMUNICATION_PROFILE"
    | "COMMUNICATION_ACCOUNT"
    | "COMMUNICATION_CONVERSATION"
    | "COMMUNICATION_MESSAGE"
    | "COMMUNICATION_ATTACHMENT"
    | "COMMUNICATION_UNSUPPORTED_STORE"
    | "UNKNOWN_WINDOWS_ARTIFACT";
  artifact_subtype: string;
  schema_version: string;
  display_name_key: string;
  description_key: string;
  analyzer_id: string;
  analyzer_version: string;
  parser_backend: string;
  parser_backend_version: string;
  source_path: string;
  source_kind:
    | "REGISTRY_HIVE"
    | "REGISTRY_EXPORT"
    | "EVENT_LOG_EVTX"
    | "EVENT_LOG_XML"
    | "PREFETCH_FILE"
    | "IMAGE_FILE"
    | "VIDEO_FILE"
    | "AUDIO_FILE"
    | "BROWSER_SQLITE_DB"
    | "BROWSER_CACHE_FILE"
    | "EMAIL_MBOX"
    | "COMMUNICATION_SQLITE_DB"
    | "UNKNOWN_WINDOWS_ARTIFACT";
  observed_at_raw: string | null;
  observed_at_utc: string | null;
  timezone_source: string | null;
  timezone_confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  title: string;
  summary: string;
  fields: {
    [k: string]: unknown;
  };
  payload: {
    [k: string]: unknown;
  };
  raw_locator: {
    evidence_id: string;
    source_kind: "EVIDENCE" | "FILE" | "ARTIFACT" | "MACHINE_EXTRACTION";
    source_id: string;
    source_path: string | null;
    source_reference: string | null;
    offset: number | null;
    length: number | null;
    locator_type:
      | "BYTE_RANGE"
      | "LOGICAL_PATH"
      | "LOGICAL_REGISTRY"
      | "LOGICAL_EVENT_RECORD"
      | "PREFETCH_FIELD"
      | "MEDIA_METADATA"
      | "SQLITE_ROW";
    encoding: string | null;
    /**
     * @minItems 1
     */
    view_types: ["HEX" | "TEXT", ...("HEX" | "TEXT")[]];
    content_sha256: string | null;
    limitations: string[];
    details: {
      [k: string]: unknown;
    };
  };
  citations: {
    id: string;
    label: string;
    case_id: string;
    evidence_id: string | null;
    source_kind:
      | "EVIDENCE"
      | "FILE"
      | "ARTIFACT"
      | "TIMELINE_EVENT"
      | "SEARCH_RESULT"
      | "ANALYST_ANNOTATION"
      | "AI_ENRICHMENT"
      | "MACHINE_EXTRACTION"
      | "CUSTODY_EVENT"
      | "KEYWORD_RECOMMENDATION";
    source_id: string;
    file_id: string | null;
    artifact_id: string | null;
    timeline_event_id: string | null;
    search_result_id: string | null;
    source_path: string | null;
    source_offset: number | null;
    source_reference: string | null;
    excerpt: string | null;
    content_sha256: string | null;
    created_at: string;
    source_length: number | null;
    encoding: string | null;
    raw_locator: {
      evidence_id: string;
      source_kind: "EVIDENCE" | "FILE" | "ARTIFACT" | "MACHINE_EXTRACTION";
      source_id: string;
      source_path: string | null;
      source_reference: string | null;
      offset: number | null;
      length: number | null;
      locator_type:
        | "BYTE_RANGE"
        | "LOGICAL_PATH"
        | "LOGICAL_REGISTRY"
        | "LOGICAL_EVENT_RECORD"
        | "PREFETCH_FIELD"
        | "MEDIA_METADATA"
        | "SQLITE_ROW";
      encoding: string | null;
      /**
       * @minItems 1
       */
      view_types: ["HEX" | "TEXT", ...("HEX" | "TEXT")[]];
      content_sha256: string | null;
      limitations: string[];
      details: {
        [k: string]: unknown;
      };
    } | null;
  }[];
  warnings: {
    severity?: "WARNING" | "ERROR";
    code: string;
    message_key: string;
    developer_message: string;
    details?: {
      [k: string]: unknown;
    };
    [k: string]: unknown;
  }[];
  parse_status: "SUCCESS" | "PARTIAL" | "UNSUPPORTED" | "CORRUPT" | "FAILED";
  confidence: number;
  is_partial: boolean;
  index_revision: number;
  created_at: string;
  updated_at: string;
  dedup_key: string;
  timestamp_interpretations: {
    raw_timestamp: string;
    raw_timezone: string | null;
    normalized_utc: string | null;
    display_timestamp: string | null;
    /**
     * IANA Time Zone Database identifier. UTC is accepted as the canonical zero-offset identifier.
     */
    display_timezone: string;
    timezone_source:
      | "CASE_SETTING"
      | "EVIDENCE_OS"
      | "WINDOWS_REGISTRY"
      | "LINUX_LOCALTIME"
      | "BROWSER_PROFILE"
      | "APPLICATION_SETTING"
      | "ARTIFACT_OFFSET"
      | "ANALYST_OVERRIDE"
      | "UNKNOWN";
    timezone_confidence: "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
    dst_status: "STANDARD" | "DAYLIGHT" | "TRANSITION" | "NOT_APPLICABLE" | "UNKNOWN";
    ambiguity: "NONE" | "AMBIGUOUS_LOCAL_TIME" | "NONEXISTENT_LOCAL_TIME" | "INVALID_RAW_TIME";
  }[];
  provenance: {
    evidence_id: string;
    source_object_id: string | null;
    source_path: string | null;
    source_offset: number | null;
    source_length: number | null;
    analyzer_run_id: string;
    analyzer_id: string;
    analyzer_version: string;
    raw_locator: {
      evidence_id: string;
      source_kind: "EVIDENCE" | "FILE" | "ARTIFACT" | "MACHINE_EXTRACTION";
      source_id: string;
      source_path: string | null;
      source_reference: string | null;
      offset: number | null;
      length: number | null;
      locator_type:
        | "BYTE_RANGE"
        | "LOGICAL_PATH"
        | "LOGICAL_REGISTRY"
        | "LOGICAL_EVENT_RECORD"
        | "PREFETCH_FIELD"
        | "MEDIA_METADATA"
        | "SQLITE_ROW";
      encoding: string | null;
      /**
       * @minItems 1
       */
      view_types: ["HEX" | "TEXT", ...("HEX" | "TEXT")[]];
      content_sha256: string | null;
      limitations: string[];
      details: {
        [k: string]: unknown;
      };
    };
  };
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
