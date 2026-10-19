import { useEffect, useRef, useState } from "react";
import { gateway, type Row } from "./gateway";
import { Badge, ErrorState, Fields, Loading, Section } from "./ui";

export function AiAssistant({
  caseId,
  selected,
}: {
  caseId: string;
  selected: { type: string; id: string } | null;
}) {
  const [result, setResult] = useState<Row | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const revision = useRef(0);
  useEffect(() => {
    revision.current++;
    setResult(null);
    setError(null);
    setBusy(false);
    return () => {
      revision.current++;
    };
  }, [caseId, selected?.type, selected?.id]);
  const supported =
    selected &&
    [
      "FILE_SYSTEM_NODE",
      "ARTIFACT",
      "TIMELINE_EVENT",
      "SEARCH_RESULT",
      "MACHINE_CANDIDATE",
    ].includes(selected.type);
  async function analyze() {
    if (!selected || busy) return;
    const current = ++revision.current;
    setBusy(true);
    setError(null);
    try {
      const response = await gateway.call("ai.analyze", {
        case_id: caseId,
        resource_type: selected.type,
        resource_id: selected.id,
      });
      if (current === revision.current) setResult(response);
    } catch (err) {
      if (current === revision.current) setError(err);
    } finally {
      if (current === revision.current) setBusy(false);
    }
  }
  const summary = result?.execution?.result;
  return (
    <>
      <p className="muted">
        현재 선택을 고정한 뒤 사건 정책을 검사합니다. AI에는 허용된 구조 정보만
        전달하며 원본 파일 내용은 전송하지 않습니다.
      </p>
      <button
        disabled={!caseId || !supported || busy}
        onClick={() => void analyze()}
      >
        현재 선택 분석 요청
      </button>
      {busy && <Loading />}
      {error != null && <ErrorState error={error} retry={analyze} />}
      {result?.status === "CONFIGURATION_REQUIRED" && (
        <p>분석 요청을 저장했습니다. AI 제공자 연결 설정이 필요합니다.</p>
      )}
      {result?.status === "POLICY_DENIED" && (
        <p>
          사건의 AI 데이터 정책이 전송을 허용하지 않았습니다. 설정에서 평가
          사유를 확인하세요.
        </p>
      )}
      {result?.audit && (
        <Section title="데이터 정책 평가">
          <Fields value={result.audit.result} />
        </Section>
      )}
      {summary && (
        <Section title={summary.title ?? "AI 분석 결과"}>
          <Badge value="AI_INFERENCE" />
          <p>{summary.summary_text}</p>
          <ul>
            {summary.key_points?.map((point: string, index: number) => (
              <li key={index}>{point}</li>
            ))}
          </ul>
          <p className="muted small">
            구조 정보에 대한 AI 요약입니다. 원본 내용에 대한 분석이나 검증된
            관찰 사실을 의미하지 않습니다.
          </p>
          <Section title="선택 자료 출처">
            <Fields value={summary.citations} />
          </Section>
        </Section>
      )}
      {result?.request && (
        <Section title="저장된 요청">
          <Fields
            value={{
              assistance_request_id: result.request.assistance_request_id,
              context_snapshot_id: result.request.context_snapshot_id,
            }}
          />
        </Section>
      )}
    </>
  );
}
