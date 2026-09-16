/* Generated from canonical APEX schemas; run npm run contracts. */

export interface CapabilityReport {
  schema_version: "1.0.0";
  engine_version: string;
  status: "AVAILABLE" | "AVAILABLE_WITH_LIMITATIONS";
  host: {
    os: string;
    platform: string;
    python_version: string;
    python_implementation: string;
    cpu_count: number | null;
  };
  summary: {
    capability_count: number;
    unavailable_count: number;
    host_verification_required_count: number;
    secret_values_emitted: false;
    environment_values_emitted: false;
    environment_names_emitted: false;
  };
  /**
   * @minItems 1
   */
  capabilities: [
    {
      id: string;
      status:
        | "AVAILABLE"
        | "AVAILABLE_WITH_LIMITATIONS"
        | "CAPABILITY_UNAVAILABLE"
        | "EXTERNAL_CONFIGURATION_REQUIRED"
        | "UNSUPPORTED_PLATFORM"
        | "BLOCKED_EXTERNAL_FIXTURE"
        | "HOST_VERIFICATION_REQUIRED";
      version: string | null;
      reason: string | null;
      probe: string;
      details: {
        [k: string]: unknown;
      };
    },
    ...{
      id: string;
      status:
        | "AVAILABLE"
        | "AVAILABLE_WITH_LIMITATIONS"
        | "CAPABILITY_UNAVAILABLE"
        | "EXTERNAL_CONFIGURATION_REQUIRED"
        | "UNSUPPORTED_PLATFORM"
        | "BLOCKED_EXTERNAL_FIXTURE"
        | "HOST_VERIFICATION_REQUIRED";
      version: string | null;
      reason: string | null;
      probe: string;
      details: {
        [k: string]: unknown;
      };
    }[]
  ];
}

export type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};
