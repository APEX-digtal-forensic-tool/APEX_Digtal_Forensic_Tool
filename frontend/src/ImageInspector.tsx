import { useEffect, useRef, useState } from "react";
import { gateway, unwrap, type Row } from "./gateway";
import { Badge, ErrorState, Fields, Loading } from "./ui";

export function ImageInspector({
  caseId,
  resourceType,
  resourceId,
}: {
  caseId: string;
  resourceType: string;
  resourceId: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const request = useRef(0);
  const [preview, setPreview] = useState<Row | null>(null);
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [channel, setChannel] = useState("RGB");
  const [viewBit, setViewBit] = useState(-1);
  const [dimension, setDimension] = useState(1536);
  const [zoom, setZoom] = useState(100);
  const [channels, setChannels] = useState("RGB");
  const [bit, setBit] = useState(0);
  const [order, setOrder] = useState("MSB_FIRST");
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(512);
  useEffect(
    () => () => {
      request.current++;
    },
    [],
  );

  async function run(action: "PREVIEW" | "EXTRACT") {
    const revision = ++request.current;
    setBusy(true);
    setError(null);
    if (action === "PREVIEW") setPreview(null);
    else setResult(null);
    try {
      const value = await gateway.call("media.inspect", {
        case_id: caseId,
        resource_type: resourceType,
        resource_id: resourceId,
        action,
        channel,
        bit: action === "PREVIEW" ? (viewBit < 0 ? null : viewBit) : bit,
        channels,
        bit_order: order,
        pixel_offset: offset,
        byte_limit: limit,
        max_dimension: dimension,
      });
      if (revision !== request.current) return;
      if (action === "PREVIEW") setPreview(value);
      else setResult(value);
    } catch (err) {
      if (revision === request.current) setError(err);
    } finally {
      if (revision === request.current) setBusy(false);
    }
  }
  const valid =
    /^[RGBA]{1,4}$/.test(channels) &&
    new Set(channels).size === channels.length &&
    Number.isSafeInteger(offset) &&
    offset >= 0 &&
    offset < 25000000 &&
    Number.isSafeInteger(limit) &&
    limit >= 1 &&
    limit <= 65536;
  return (
    <>
      <button
        onClick={() => {
          dialog.current?.showModal();
          if (!preview) void run("PREVIEW");
        }}
      >
        이미지 보기 · 비트 분석
      </button>
      <dialog
        className="image-dialog"
        ref={dialog}
        aria-labelledby="image-inspector-title"
      >
        <header>
          <h2 id="image-inspector-title">이미지 보기 · 비트 분석</h2>
          <button onClick={() => dialog.current?.close()}>닫기</button>
        </header>
        <p className="muted small">
          읽기 전용 파생 분석 · 첫 프레임의 저장된 픽셀을 사용합니다. EXIF
          회전은 적용하지 않습니다.
        </p>
        <fieldset disabled={busy} className="image-controls">
          <legend>이미지 표시</legend>
          <label>
            표시 채널
            <select
              value={channel}
              onChange={(e) => {
                setChannel(e.target.value);
                setPreview(null);
              }}
            >
              {["RGB", "R", "G", "B", "A"].map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
          <label>
            비트 평면
            <select
              value={viewBit}
              onChange={(e) => {
                setViewBit(Number(e.target.value));
                setPreview(null);
              }}
            >
              <option value={-1}>전체 값</option>
              {Array.from({ length: 8 }, (_, i) => (
                <option key={i} value={i}>
                  bit {i}
                  {i === 0 ? " · LSB" : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            최대 표시 크기
            <select
              value={dimension}
              onChange={(e) => {
                setDimension(Number(e.target.value));
                setPreview(null);
              }}
            >
              {[256, 1536, 4096].map((n) => (
                <option key={n} value={n}>
                  {n} px
                </option>
              ))}
            </select>
          </label>
          <button onClick={() => void run("PREVIEW")}>이미지 표시</button>
          <label>
            확대율
            <select
              value={zoom}
              onChange={(e) => setZoom(Number(e.target.value))}
            >
              {[25, 50, 100, 200, 400, 800].map((n) => (
                <option key={n} value={n}>
                  {n}%
                </option>
              ))}
            </select>
          </label>
        </fieldset>
        {busy && <Loading />}
        {error != null && <ErrorState error={error} />}
        {preview && (
          <>
            <p className="small">
              {preview.format} · {preview.width} × {preview.height} ·{" "}
              {preview.color_mode}
              {preview.is_resized
                ? ` · 축소 미리보기 ${preview.preview_width} × ${preview.preview_height}`
                : " · 원본 해상도"}
            </p>
            <div className="image-viewport">
              <img
                alt={`증거 이미지 · ${preview.channel}${preview.bit == null ? "" : ` bit ${preview.bit}`}`}
                src={preview.image_url}
                style={{ width: (preview.preview_width * zoom) / 100 }}
              />
            </div>
            <p className="small image-hash">
              원본 SHA-256: {preview.source_sha256}
            </p>
          </>
        )}
        <fieldset disabled={busy} className="image-controls">
          <legend>픽셀 비트 추출</legend>
          <label>
            채널 순서
            <input
              value={channels}
              maxLength={4}
              onChange={(e) => setChannels(e.target.value.toUpperCase())}
            />
          </label>
          <label>
            추출 비트
            <select
              value={bit}
              onChange={(e) => setBit(Number(e.target.value))}
            >
              {Array.from({ length: 8 }, (_, i) => (
                <option key={i} value={i}>
                  bit {i}
                  {i === 0 ? " · LSB" : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            바이트 조합
            <select value={order} onChange={(e) => setOrder(e.target.value)}>
              <option value="MSB_FIRST">상위 비트부터 (MSB)</option>
              <option value="LSB_FIRST">하위 비트부터 (LSB)</option>
            </select>
          </label>
          <label>
            시작 픽셀
            <input
              type="number"
              min={0}
              max={24999999}
              value={offset}
              onChange={(e) => setOffset(Number(e.target.value))}
            />
          </label>
          <label>
            최대 추출 바이트
            <input
              type="number"
              min={1}
              max={65536}
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            />
          </label>
          <button disabled={!valid} onClick={() => void run("EXTRACT")}>
            비트 추출
          </button>
        </fieldset>
        <p className="muted small">
          채널은 R·G·B·A를 중복 없이 지정합니다. 왼쪽 위부터 행 순서로 8비트
          RGBA 변환 픽셀을 읽습니다. 추출에는 축소 미리보기를 사용하지 않습니다.
        </p>
        {result && (
          <section className="image-extraction" aria-label="비트 추출 결과">
            <h3>
              추출 결과 <Badge value="DERIVED_ANALYSIS" />
            </h3>
            <p>
              {result.channels} · bit {result.bit} ·{" "}
              {result.bit_order === "MSB_FIRST" ? "MSB 우선" : "LSB 우선"} ·
              시작 픽셀 {result.pixel_offset}
              {` · ${result.returned_bytes} / ${result.available_bytes}바이트`}
              {result.has_more ? " · 추가 데이터 있음" : " · 끝"}
            </p>
            <label>
              추출 텍스트 (UTF-8)
              <textarea
                readOnly
                rows={6}
                value={String(result.text).replace(
                  /[\x00-\x08\x0b-\x1f\x7f]/g,
                  "·",
                )}
              />
            </label>
            <p className="muted small">
              제어 문자는 ·, 유효하지 않은 UTF-8은 �로 표시합니다. 정확한
              바이트는 Hex와 저장된 JSON에서 확인하세요.
            </p>
            <details>
              <summary>추출 Hex</summary>
              <pre>{result.hex}</pre>
            </details>
            <details>
              <summary>분석 조건 · 출처 · 해시</summary>
              <Fields
                value={Object.fromEntries(
                  Object.entries(result).filter(
                    ([key]) => !["text", "hex"].includes(key),
                  ),
                )}
              />
            </details>
            <p className="small">
              분석 조건·원본 해시·결과가 JSON으로 저장됐습니다:{" "}
              {result.export_relative_path}
            </p>
            <button
              onClick={async () => {
                try {
                  if (window.apex) unwrap(await window.apex.openExports());
                } catch (err) {
                  setError(err);
                }
              }}
            >
              결과 폴더 열기
            </button>
          </section>
        )}
      </dialog>
    </>
  );
}
