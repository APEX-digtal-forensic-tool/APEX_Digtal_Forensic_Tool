/* Generated from canonical APEX schemas; run npm run contracts. */

export type CandidateRecord = {
  [k: string]: unknown;
} & {
  candidate_id: string;
  case_id: string;
  evidence_id: string;
  source_node_id: string;
  source_type: "IMAGE" | "IMAGE_FILE" | "VIDEO_FRAME" | "AUDIO" | "AUDIO_FILE" | "DOCUMENT" | "OTHER";
  extraction_type: "OCR" | "STT" | "SUBTITLE" | "SCREEN_TEXT" | "OTHER";
  text: string;
  language: string | null;
  confidence: number;
  provider_id: string;
  provider_version: string;
  model_id: string | null;
  region: {
    [k: string]: unknown;
  } | null;
  frame_number: number | null;
  media_timestamp_ms: number | null;
  audio_start_ms: number | null;
  audio_end_ms: number | null;
  raw_locator:
    | {
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
      }
    | {
        source_path?: string;
        source_node_id: string;
        candidate_index?: number;
        locator_type: "OCR" | "STT" | "SUBTITLE" | "SCREEN_TEXT" | "OTHER" | "SYNTHETIC";
        source_sha256?: string;
        [k: string]: unknown;
      };
  citations: (
    | {
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
      }
    | {
        evidence_id: string;
        source_id: string;
        [k: string]: unknown;
      }
  )[];
  review_status: "UNREVIEWED" | "ACCEPTED" | "REJECTED" | "CORRECTED";
  reviewed_by: string | null;
  reviewed_at: string | null;
  correction_text: string | null;
  source_revision: number;
  is_partial: boolean;
  created_at: string | null;
  candidate_semantics: "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT";
};

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
