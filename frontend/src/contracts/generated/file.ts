/* Generated from canonical APEX schemas; run npm run contracts. */

export type FileNode =
  | {
      id: string;
      object_id: string;
      evidence_id: string;
      parent_file_id: string | null;
      name: string;
      name_encoding: string | null;
      name_lossy: boolean;
      full_path: string;
      file_type: "REGULAR" | "DIRECTORY" | "SYMLINK" | "STREAM" | "SPECIAL";
      mime_type: string | null;
      size_bytes: number;
      allocated: boolean;
      deleted: boolean;
      hidden: boolean;
      times: {
        created: string | null;
        modified: string | null;
        accessed: string | null;
        changed: string | null;
        raw: {
          [k: string]: unknown;
        };
      };
      hash_sha256: string | null;
      metadata: {
        [k: string]: unknown;
      };
      time_interpretations: {
        created: {
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
        } | null;
        modified: {
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
        } | null;
        accessed: {
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
        } | null;
        changed: {
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
        } | null;
      };
    }
  | {
      id: string;
      case_id: string;
      evidence_id: string;
      parent_node_id: string | null;
      original_name: string;
      original_relative_path: string;
      display_path: string;
      comparison_path: string;
      node_type: "ROOT" | "DIRECTORY" | "FILE" | "SYMLINK" | "REPARSE_POINT" | "OTHER";
      file_size: number | null;
      extension: string | null;
      mime_candidate: string | null;
      mime_confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
      fs_metadata: {
        [k: string]: unknown;
      };
      platform: string;
      timestamp_meanings: {
        [k: string]: string;
      };
      raw_timestamps: {
        [k: string]: unknown;
      };
      utc_timestamps: {
        [k: string]: string | null;
      };
      timestamp_sources: {
        [k: string]: string;
      };
      is_deleted: boolean;
      is_readable: boolean;
      is_link: boolean;
      is_traversed: boolean;
      raw_locator: {
        [k: string]: unknown;
      };
      provider_metadata: {
        [k: string]: unknown;
      };
      is_partial: boolean;
      index_revision: number;
      created_at: string;
      updated_at: string;
      filesystem_provider: {
        id: string;
        version: string;
      };
    }
  | {
      items: {
        id: string;
        case_id: string;
        evidence_id: string;
        parent_node_id: string | null;
        original_name: string;
        original_relative_path: string;
        display_path: string;
        comparison_path: string;
        node_type: "ROOT" | "DIRECTORY" | "FILE" | "SYMLINK" | "REPARSE_POINT" | "OTHER";
        file_size: number | null;
        extension: string | null;
        mime_candidate: string | null;
        mime_confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
        fs_metadata: {
          [k: string]: unknown;
        };
        platform: string;
        timestamp_meanings: {
          [k: string]: string;
        };
        raw_timestamps: {
          [k: string]: unknown;
        };
        utc_timestamps: {
          [k: string]: string | null;
        };
        timestamp_sources: {
          [k: string]: string;
        };
        is_deleted: boolean;
        is_readable: boolean;
        is_link: boolean;
        is_traversed: boolean;
        raw_locator: {
          [k: string]: unknown;
        };
        provider_metadata: {
          [k: string]: unknown;
        };
        is_partial: boolean;
        index_revision: number;
        created_at: string;
        updated_at: string;
        filesystem_provider: {
          id: string;
          version: string;
        };
      }[];
      page: {
        next_cursor: string | null;
        has_more: boolean;
        returned: number;
      };
      coverage: {
        case_id: string;
        evidence_id: string;
        profile_type: "QUICK_TRIAGE" | "SELECTED_SCOPE" | "FULL_ANALYSIS" | "CUSTOM";
        option_fingerprint: string;
        status: "NOT_STARTED" | "PARTIAL" | "COMPLETE" | "FAILED" | "CANCELLED";
        discovered_items: number;
        processed_items: number;
        skipped_items: number;
        warning_count: number;
        error_count: number;
        current_path: string | null;
        elapsed_seconds: number;
        throughput_items_per_second: number | null;
        estimated_remaining_seconds: number | null;
        eta_confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
        index_revision: number;
        job_id: string | null;
        created_at: string | null;
        updated_at: string | null;
        filesystem_provider: {
          id: string;
          version: string;
        };
      } | null;
    };

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
