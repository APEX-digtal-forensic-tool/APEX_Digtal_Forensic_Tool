import { useEffect, useRef, useState } from "react";
import { gateway, type Row } from "./gateway";
import { ErrorState, Fields, Loading, Section } from "./ui";

export function ForensicTools({
  caseId,
  evidenceId,
  selected,
  onTask,
}: {
  caseId: string;
  evidenceId: string;
  selected: Row | null;
  onTask: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<Row | null>(null);
  const [streams, setStreams] = useState<Row[]>([]);
  const [streamId, setStreamId] = useState("");
  const [offset, setOffset] = useState("0");
  const [language, setLanguage] = useState("eng");
  const [scope, setScope] = useState("UNALLOCATED");
  const [budget, setBudget] = useState("256");
  const [carveOffset, setCarveOffset] = useState("0");
  const revision = useRef(0);
  const dialog = useRef<HTMLDialogElement>(null);
  const file = selected?.node_type === "FILE";
  const imageFile = selected?.provider_id === "apex.pytsk_filesystem_provider";
  useEffect(() => {
    setCarveOffset("0");
  }, [caseId, evidenceId]);
  useEffect(() => {
    revision.current++;
    setResult(null);
    setError(null);
    setStreams([]);
    setStreamId("");
    setOffset("0");
    setBusy(false);
    setOpen(false);
    return () => {
      revision.current++;
    };
  }, [caseId, evidenceId, selected?.id]);
  useEffect(() => {
    if (open) dialog.current?.showModal();
    else dialog.current?.close();
  }, [open]);
  async function call(operation: string, payload: Row, task = false) {
    const current = ++revision.current;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await gateway.call(operation, {
        case_id: caseId,
        ...payload,
      });
      if (current !== revision.current) return;
      if (operation === "files.streams") {
        setStreams(data.streams);
        setStreamId(String(data.streams[0]?.id ?? ""));
      } else setResult(data);
      if (task) onTask();
    } catch (err) {
      if (current === revision.current) setError(err);
    } finally {
      if (current === revision.current) setBusy(false);
    }
  }
  const node = { node_id: selected?.id };
  return (
    <>
      <button disabled={!caseId || !evidenceId} onClick={() => setOpen(true)}>
        복구·카빙·OCR·ADS
      </button>
      <dialog
        ref={dialog}
        className="modal forensic-tools"
        onCancel={() => setOpen(false)}
      >
        <h2>추가 포렌식 분석</h2>
        <p>
          {selected?.original_name ?? "선택한 증거"} · 원본은 읽기 전용으로
          유지됩니다.
        </p>
        <button onClick={() => setOpen(false)} aria-label="추가 분석 닫기">
          닫기
        </button>
        <Section title="삭제 파일 복구">
          <p>
            기록된 데이터 위치로 파생 파일을 만듭니다. 덮어쓴 데이터와 누락
            구간은 복구를 보장하지 않습니다.
          </p>
          <button
            disabled={busy || !file || !selected?.is_deleted}
            onClick={() => void call("files.recover", node, true)}
          >
            선택한 삭제 파일 복구
          </button>
        </Section>
        <Section title="NTFS 데이터 스트림 (ADS)">
          <button
            disabled={busy || !file || !imageFile || !!selected?.is_deleted}
            onClick={() => void call("files.streams", node)}
          >
            데이터 스트림 조회
          </button>
          {streams.length > 0 && (
            <>
              <label>
                스트림
                <select
                  aria-label="데이터 스트림"
                  disabled={busy}
                  value={streamId}
                  onChange={(e) => {
                    setStreamId(e.target.value);
                    setOffset("0");
                    setResult(null);
                  }}
                >
                  {streams.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name || "기본 스트림"} · {s.size} bytes
                    </option>
                  ))}
                </select>
              </label>
              <label>
                스트림 오프셋
                <input
                  disabled={busy}
                  value={offset}
                  onChange={(e) => {
                    setOffset(e.target.value);
                    setResult(null);
                  }}
                />
              </label>
              <button
                disabled={
                  busy ||
                  !streamId ||
                  !offset.trim() ||
                  !Number.isSafeInteger(Number(offset)) ||
                  Number(offset) < 0
                }
                onClick={() =>
                  void call("streams.read", {
                    ...node,
                    stream_id: Number(streamId),
                    offset: Number(offset),
                  })
                }
              >
                스트림 읽기
              </button>
              <button
                disabled={busy || !streamId}
                onClick={() =>
                  void call(
                    "streams.export",
                    { ...node, stream_id: Number(streamId) },
                    true,
                  )
                }
              >
                스트림 내보내기
              </button>
            </>
          )}
        </Section>
        <Section title="OCR·음성 인식">
          <p>
            설정에서 로컬 분석기와 모델을 선택하세요. 결과는 자동 추출 후보
            화면에서 검토합니다.
          </p>
          <label>
            언어
            <select
              disabled={busy}
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
            >
              <option value="eng">영어 OCR</option>
              <option value="kor+eng">한국어·영어 OCR</option>
              <option value="ko">한국어 음성</option>
              <option value="en">영어 음성</option>
              <option value="auto">음성 언어 자동</option>
            </select>
          </label>
          {(["OCR", "STT"] as const).map((kind) => (
            <button
              key={kind}
              disabled={busy || !file || !!selected?.is_deleted}
              onClick={() =>
                void call(
                  "machine.run",
                  {
                    ...node,
                    kind,
                    language:
                      kind === "STT"
                        ? ({ eng: "en", "kor+eng": "ko" }[language] ?? language)
                        : ({ ko: "kor", en: "eng", auto: "eng" }[language] ??
                          language),
                  },
                  true,
                )
              }
            >
              {kind === "OCR" ? "선택 파일 문자 추출" : "선택 파일 음성 인식"}
            </button>
          ))}
        </Section>
        <Section title="파일 시그니처 카빙">
          <p>
            PNG·JPEG·PDF·ZIP·GIF의 연속 바이트를 찾습니다. 결과는 원본 이름을 알
            수 없는 검토 후보입니다.
          </p>
          <label>
            탐색 범위
            <select
              disabled={busy}
              value={scope}
              onChange={(e) => setScope(e.target.value)}
            >
              <option value="UNALLOCATED">미할당 영역</option>
              <option value="IMAGE">이미지 전체</option>
            </select>
          </label>
          <label>
            한 작업의 탐색량 (MiB)
            <input
              type="number"
              disabled={busy}
              min="1"
              max="1048576"
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
            />
          </label>
          <label>
            탐색 시작 오프셋
            <input
              disabled={busy}
              value={carveOffset}
              onChange={(e) => setCarveOffset(e.target.value)}
            />
          </label>
          <button
            disabled={
              busy ||
              !budget.trim() ||
              !Number.isSafeInteger(Number(budget)) ||
              Number(budget) < 1 ||
              Number(budget) > 1048576 ||
              !carveOffset.trim() ||
              !Number.isSafeInteger(Number(carveOffset)) ||
              Number(carveOffset) < 0
            }
            onClick={() =>
              void call(
                "evidence.carve",
                {
                  evidence_id: evidenceId,
                  scope,
                  max_scan_bytes: Number(budget) * 1048576,
                  start_offset: Number(carveOffset),
                },
                true,
              )
            }
          >
            카빙 시작
          </button>
          <p>
            제한에 도달하면 작업 결과의 next_offset부터 이어서 탐색할 수
            있습니다.
          </p>
        </Section>
        {busy && <Loading />}
        {error != null && <ErrorState error={error} />}
        {result && (
          <Section
            title={result.task_id ? "작업이 등록되었습니다" : "분석 결과"}
          >
            {result.text_preview && (
              <pre className="text-view">{result.text_preview}</pre>
            )}
            <Fields value={result} />
          </Section>
        )}
        <button onClick={() => window.apex?.openExports()}>
          복구·추출 결과 폴더 열기
        </button>
      </dialog>
    </>
  );
}
