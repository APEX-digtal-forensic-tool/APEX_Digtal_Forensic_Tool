import { useEffect, useRef, useState } from "react";
import { gateway, type Row } from "./gateway";
import { ErrorState, Fields, Loading } from "./ui";

export function VideoInspector({
  caseId,
  resourceType,
  resourceId,
}: {
  caseId: string;
  resourceType: string;
  resourceId: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const revision = useRef(0);
  const [seconds, setSeconds] = useState(0);
  const [result, setResult] = useState<Row | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    revision.current++;
    setResult(null);
    setError(null);
    setBusy(false);
    setSeconds(0);
    return () => {
      revision.current++;
    };
  }, [caseId, resourceType, resourceId]);
  async function inspect() {
    const id = ++revision.current;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await gateway.call("media.video", {
        case_id: caseId,
        resource_type: resourceType,
        resource_id: resourceId,
        timestamp_seconds: seconds,
        max_dimension: 1536,
      });
      if (id === revision.current) setResult(data);
    } catch (e) {
      if (id === revision.current) setError(e);
    } finally {
      if (id === revision.current) setBusy(false);
    }
  }
  return (
    <>
      <button onClick={() => dialog.current?.showModal()}>
        영상 프레임 보기
      </button>
      <dialog
        className="image-dialog"
        ref={dialog}
        aria-labelledby="video-inspector-title"
      >
        <header>
          <h2 id="video-inspector-title">영상 프레임 보기</h2>
          <button onClick={() => dialog.current?.close()}>닫기</button>
        </header>
        <p>
          영상의 로컬 사본에서 한 프레임을 읽습니다. 원본은 변경하지 않으며
          외부로 전송하지 않습니다.
        </p>
        <p className="muted small">
          최대 512 MiB · 15초 디코딩 제한 · 최대 1536 px 미리보기. 지정 시각
          이후 디코딩되는 프레임이며 원본 프레임 번호를 보장하지 않습니다.
        </p>
        <label>
          요청 시각 (초)
          <input
            type="number"
            min={0}
            max={604800}
            step={0.1}
            value={seconds}
            onChange={(e) => setSeconds(Number(e.target.value))}
          />
        </label>
        <button
          disabled={
            busy || !Number.isFinite(seconds) || seconds < 0 || seconds > 604800
          }
          onClick={() => void inspect()}
        >
          프레임 읽기
        </button>
        {busy && <Loading />}
        {error != null && <ErrorState error={error} />}
        {result && (
          <>
            <p>요청 시각: {result.timestamp_seconds_requested}초 · 파생 분석</p>
            <div className="image-viewport">
              <img alt="선택 시각의 영상 프레임" src={result.image_url} />
            </div>
            <details>
              <summary>영상 정보 · 출처 · 해시</summary>
              <Fields
                value={Object.fromEntries(
                  Object.entries(result).filter(([key]) => key !== "image_url"),
                )}
              />
            </details>
          </>
        )}
      </dialog>
    </>
  );
}
