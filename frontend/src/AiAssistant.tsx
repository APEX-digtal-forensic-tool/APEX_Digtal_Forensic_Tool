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
  const [mode, setMode] = useState("STRUCTURE");
  const [reviewed, setReviewed] = useState(false);
  const revision = useRef(0);
  useEffect(() => {
    revision.current++;
    setResult(null);
    setError(null);
    setBusy(false);
    setReviewed(false);
    return () => {
      revision.current++;
    };
  }, [caseId, selected?.type, selected?.id, mode]);
  const supported =
    selected &&
    [
      "FILE_SYSTEM_NODE",
      "ARTIFACT",
      "TIMELINE_EVENT",
      "SEARCH_RESULT",
      "MACHINE_CANDIDATE",
    ].includes(selected.type);
  async function analyze(prepare = false) {
    if (!selected || busy) return;
    const current = ++revision.current;
    setBusy(true);
    setError(null);
    try {
      const response = await gateway.call(
        prepare ? "ai.prepare" : "ai.analyze",
        {
          case_id: caseId,
          resource_type: selected.type,
          resource_id: selected.id,
          mode,
          ...(mode === "CONTENT" && reviewed && result?.preview?.fingerprint
            ? { reviewed_fingerprint: result.preview.fingerprint }
            : {}),
        },
      );
      if (current === revision.current) {
        setResult(response);
        if (response.status === "REVIEW_REQUIRED") setReviewed(false);
      }
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
        선택한 자료와 사건 정책을 확인한 후 분석합니다. 본문 분석은 전송할
        발췌문을 먼저 확인해야 합니다.
      </p>
      <label>
        분석 방식
        <select
          value={mode}
          disabled={busy}
          onChange={(e) => setMode(e.target.value)}
        >
          <option value="STRUCTURE">구조 정보 요약</option>
          <option value="CONTENT">증거 본문 발췌 분석</option>
        </select>
      </label>
      {mode === "CONTENT" && (
        <button
          disabled={!supported || busy}
          onClick={() => void analyze(true)}
        >
          전송할 발췌문 준비
        </button>
      )}
      {mode === "CONTENT" && result?.preview && (
        <Section title="전송할 발췌문">
          <p>{result.preview.notice}</p>
          <pre className="text-view">{result.preview.payload.text}</pre>
          {result.preview.payload.truncated && (
            <p>일부 내용만 포함된 발췌문입니다.</p>
          )}
          <label className="check">
            <input
              type="checkbox"
              checked={reviewed}
              onChange={(e) => setReviewed(e.target.checked)}
            />
            발췌문을 확인했고 이 내용의 분석 요청에 동의합니다.
          </label>
        </Section>
      )}
      <button
        disabled={
          !caseId || !supported || busy || (mode === "CONTENT" && !reviewed)
        }
        onClick={() => void analyze()}
      >
        현재 선택 분석 요청
      </button>
      {busy && <Loading />}
      {error != null && (
        <ErrorState error={error} retry={() => void analyze()} />
      )}
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
            {mode === "CONTENT"
              ? "검토한 발췌문에 대한 AI 해석입니다. 원본 전체를 분석한 결과가 아니며 근거를 확인해야 합니다."
              : "구조 정보에 대한 AI 요약입니다. 원본 내용에 대한 분석이나 검증된 관찰 사실을 의미하지 않습니다."}
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
