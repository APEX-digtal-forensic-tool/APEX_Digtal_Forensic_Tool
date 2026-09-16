import { errorMessages, resourceMessages } from "./locales/ko-KR";
import * as validators from "./contracts/validators.js";
export type Row = Record<string, any>; // Heterogeneous Core projection/plugin fields.
export interface ApiError {
  code: string;
  message_key?: string;
  retryable?: boolean;
  target?: string;
}
export type Reply<T> = { ok: true; data: T } | { ok: false; error: ApiError };
export interface DesktopBridge {
  invoke(operation: string, payload: Row): Promise<Reply<any>>;
  pick(
    kind: "file" | "directory",
  ): Promise<Reply<{ reference: string; name: string } | null>>;
  openExports(): Promise<Reply<null>>;
  account(): Promise<Reply<{ connected: boolean; origin: string | null }>>;
  login(input: Row): Promise<Reply<{ connected: boolean; origin: string }>>;
  logout(): Promise<Reply<null>>;
}
declare global {
  interface Window {
    apex?: DesktopBridge;
  }
}
export class GatewayError extends Error {
  constructor(
    public code: string,
    public messageKey?: string,
  ) {
    super(code);
  }
}
export function validateContract(name: string, data: unknown) {
  const valid = (validators as Record<string, (data: unknown) => boolean>)[
    "validate_" + name.replaceAll("-", "_")
  ];
  if (!valid || !valid(data)) throw new GatewayError("CONTRACT_MISMATCH");
}
export function unwrap<T>(reply: Reply<T>): T {
  if (!reply.ok)
    throw new GatewayError(reply.error.code, reply.error.message_key);
  return reply.data;
}
export interface ApexGateway {
  call<T = Row>(operation: string, payload?: Row): Promise<T>;
}
export class DesktopGateway implements ApexGateway {
  async call<T = Row>(operation: string, payload: Row = {}): Promise<T> {
    if (!window.apex) throw new GatewayError("DESKTOP_REQUIRED");
    const data = unwrap(await window.apex.invoke(operation, payload));
    const lists: Record<string, string> = {
      "cases.list": "case",
      "evidence.list": "evidence",
      "files.roots": "file",
    };
    const pages: Record<string, string> = {
      "files.list": "file",
      "artifacts.list": "artifact",
      "candidates.list": "machine-extracted-candidate",
      "reports.list": "report-record",
    };
    if (lists[operation])
      data.forEach((item: unknown) => validateContract(lists[operation], item));
    if (pages[operation])
      data.items.forEach((item: unknown) =>
        validateContract(pages[operation], item),
      );
    if (operation.startsWith("context."))
      validateContract("gui-session-context", data);
    if (operation === "view") validateContract("view-projection", data);
    if (operation === "runtime")
      validateContract("runtime-capability-report", data.capabilities);
    return data as T;
  }
}
export const gateway = new DesktopGateway();
export const errorText = (error: unknown) => {
  const code =
    error instanceof GatewayError ? error.code : "DESKTOP_OPERATION_FAILED";
  return (
    (error instanceof GatewayError && error.messageKey
      ? resourceMessages[error.messageKey]
      : undefined) ??
    errorMessages[code] ??
    `작업을 완료하지 못했습니다. 오류 코드: ${code}`
  );
};
