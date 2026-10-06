import { useEffect, useMemo, useState } from "react";
import { gateway, type Row } from "../gateway";
import {
  ErrorState,
  Fields,
  FileIcon,
  Loading,
  ResultState,
  Section,
} from "../ui";
import { ImageInspector } from "../ImageInspector";
import { Splitter } from "./Splitter";

type Format = "preview" | "text" | "hex" | "metadata";
export function FileViewer({
  caseId,
  selected,
  height,
  onHeight,
  onCollect,
  onSelect,
}: {
  caseId: string;
  selected: Row | null;
  height: number;
  onHeight: (height: number) => void;
  onCollect: (citations: Row[]) => void;
  onSelect: (row: Row) => void;
}) {
  const [format, setFormat] = useState<Format>("preview");
  const [offset, setOffset] = useState("0");
  const [range, setRange] = useState({ offset: 0, length: 4096 });
  const [projection, setProjection] = useState<Row | null>(null);
  const [raw, setRaw] = useState<Row | null>(null);
  const [preview, setPreview] = useState<Row | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [retry, setRetry] = useState(0);
  const directory =
    selected && ["ROOT", "DIRECTORY"].includes(selected.node_type);
  const resourceType = selected?._resource_type ?? "FILE_SYSTEM_NODE";
  const resourceId = selected?._resource_id ?? selected?.id;
  const isImage =
    !directory &&
    /\.(png|jpe?g|gif|tiff?|bmp|webp)$/i.test(selected?.original_name ?? "");
  const kind =
    format === "metadata" || directory
      ? "metadata"
      : format === "preview" && isImage
        ? "image"
        : "raw";
  useEffect(() => {
    let live = true;
    setProjection(null);
    setRaw(null);
    setPreview(null);
    setError(null);
    if (!selected) {
      setBusy(false);
      return;
    }
    setBusy(true);
    const input = {
      case_id: caseId,
      resource_type: resourceType,
      resource_id: resourceId,
    };
    async function load() {
      try {
        const view = await gateway.call("view", {
          ...input,
          view_mode: kind === "raw" ? "RAW" : "DETAILED",
        });
        if (!live) return;
        setProjection(view);
        if (kind === "image") {
          const image = await gateway.call("media.inspect", {
            ...input,
            action: "PREVIEW",
            channel: "RGB",
            bit: null,
            channels: "RGB",
            bit_order: "MSB_FIRST",
            pixel_offset: 0,
            byte_limit: 512,
            max_dimension: 1536,
          });
          if (live) setPreview(image);
        } else if (
          kind === "raw" &&
          view.available_actions?.includes("view.raw-read")
        ) {
          const bytes = await gateway.call("raw.read", { ...input, ...range });
          if (live) setRaw(bytes);
        }
      } catch (error) {
        if (live) setError(error);
      } finally {
        if (live) setBusy(false);
      }
    }
    void load();
    return () => {
      live = false;
    };
  }, [caseId, resourceType, resourceId, kind, range, retry]);

  const hexLines = useMemo(() => {
    const compact = String(raw?.hex_preview ?? "").replace(/\s/g, "");
    if (!compact || !/^(?:[0-9a-f]{2})+$/i.test(compact)) return [];
    const bytes = compact.match(/.{2}/g) ?? [];
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const part = bytes.slice(i, i + 16);
      lines.push({
        offset: ((raw?.returned_offset ?? range.offset) + i)
          .toString(16)
          .padStart(8, "0")
          .toUpperCase(),
        hex: part
          .map((byte, index) => byte.toUpperCase() + (index === 7 ? " " : ""))
          .join(" ")
          .padEnd(48, " "),
        ascii: part
          .map((byte) => {
            const n = parseInt(byte, 16);
            return n >= 32 && n <= 126 ? String.fromCharCode(n) : ".";
          })
          .join(""),
      });
    }
    return lines;
  }, [raw, range.offset]);
  const maxHeight = Math.max(180, Math.floor(window.innerHeight * 0.65));
  const total = raw?.total_length ?? raw?.total_size_bytes;
  return (
    <section
      className="file-viewer"
      aria-label="파일 내용 뷰어"
      style={{ height }}
    >
      <Splitter
        axis="horizontal"
        label="내용 뷰어 높이 조절"
        value={height}
        min={180}
        max={maxHeight}
        onChange={onHeight}
      />
      <header className="pane-title">
        <span>내용 뷰어</span>
        <span className="viewer-file">
          {selected && <FileIcon row={selected} />}
          {selected?.original_name ?? selected?.title ?? "선택한 파일 없음"}
        </span>
        <span className="pane-caption">읽기 전용</span>
      </header>
      <div className="viewer-toolbar">
        <div className="tabs compact" aria-label="파일 표시 방식">
          {(
            [
              ["preview", "Preview"],
              ["text", "Text"],
              ["hex", "Hex"],
              ["metadata", "메타데이터"],
            ] as [Format, string][]
          ).map(([value, label]) => (
            <button
              key={value}
              aria-pressed={format === value}
              className={format === value ? "active" : ""}
              disabled={
                !selected || (!!directory && ["text", "hex"].includes(value))
              }
              onClick={() => setFormat(value)}
            >
              {label}
            </button>
          ))}
        </div>
        {selected && isImage && (
          <ImageInspector
            caseId={caseId}
            resourceType={resourceType}
            resourceId={resourceId}
          />
        )}
      </div>
      {selected && kind === "raw" && (
        <form
          className="byte-range"
          onSubmit={(event) => {
            event.preventDefault();
            const value = Number(offset);
            if (Number.isSafeInteger(value) && value >= 0)
              setRange({ offset: value, length: 4096 });
          }}
        >
          <label htmlFor="viewer-offset">Offset</label>
          <input
            id="viewer-offset"
            aria-label="원본 바이트 오프셋"
            value={offset}
            onChange={(event) => setOffset(event.target.value)}
            placeholder="0 또는 0x100"
          />
          <button
            disabled={
              busy ||
              !offset.trim() ||
              !Number.isSafeInteger(Number(offset)) ||
              Number(offset) < 0
            }
          >
            이동
          </button>
          <span>최대 4 KiB / 요청</span>
          <span className="spacer" />
          <button
            type="button"
            disabled={busy || range.offset === 0}
            onClick={() => {
              const next = Math.max(0, range.offset - 4096);
              setOffset(String(next));
              setRange({ offset: next, length: 4096 });
            }}
          >
            이전 범위
          </button>
          <button
            type="button"
            disabled={
              busy ||
              !raw ||
              (typeof total === "number"
                ? range.offset + (raw.returned_length ?? 0) >= total
                : !raw.truncated)
            }
            onClick={() => {
              const next = range.offset + (raw?.returned_length || 4096);
              setOffset(String(next));
              setRange({ offset: next, length: 4096 });
            }}
          >
            다음 범위
          </button>
        </form>
      )}
      <div className={`viewer-body ${format === "hex" ? "hex-body" : ""}`}>
        {!selected ? (
          <div className="viewer-empty">
            <FileIcon row={{ original_name: "file" }} />
            <p>파일을 선택해 내용을 확인하세요</p>
            <small>Preview · Text · Hex · 메타데이터</small>
          </div>
        ) : busy ? (
          <Loading />
        ) : error != null ? (
          <ErrorState error={error} retry={() => setRetry((v) => v + 1)} />
        ) : (
          <>
            <ResultState data={projection} />
            {kind === "metadata" ? (
              <>
                <Fields value={projection?.primary_fields} />
                <Fields value={projection?.secondary_fields} />
                <Fields value={projection?.technical_fields} />
                <Fields value={projection?.timestamps} />
                <Section title="원본 위치 및 인용 근거">
                  <Fields value={projection?.raw_locator} />
                  <Fields value={projection?.citations} />
                  {projection?.citations?.map(
                    (citation: Row, index: number) => {
                      const types: Record<string, string> = {
                        FILE: "FILE_SYSTEM_NODE",
                        FILE_SYSTEM_NODE: "FILE_SYSTEM_NODE",
                        ARTIFACT: "ARTIFACT",
                        TIMELINE_EVENT: "TIMELINE_EVENT",
                      };
                      const type =
                        types[citation.source_kind ?? citation.source_type];
                      return type && citation.source_id ? (
                        <button
                          key={index}
                          onClick={() =>
                            onSelect({
                              id: citation.source_id,
                              _resource_id: citation.source_id,
                              _resource_type: type,
                              title: "인용 원본",
                            })
                          }
                        >
                          인용 {index + 1} 원본 보기
                        </button>
                      ) : null;
                    },
                  )}
                  {!!projection?.citations?.length && (
                    <button onClick={() => onCollect(projection.citations)}>
                      보고서 근거로 추가
                    </button>
                  )}
                </Section>
              </>
            ) : kind === "image" && preview ? (
              <div className="inline-image">
                <img
                  src={preview.image_url}
                  alt={`${selected.original_name} 증거 미리보기`}
                />
                <p>
                  {preview.width} × {preview.height} · {preview.color_mode}
                  {preview.is_resized ? " · 축소 미리보기" : ""} · 첫 프레임,
                  EXIF 회전 미적용
                </p>
              </div>
            ) : raw ? (
              <>
                <ResultState data={raw} />
                {format === "hex" ||
                (format === "preview" && !raw.text_preview) ? (
                  <div className="hex-view" aria-label="원본 Hex">
                    <div className="hex-heading">
                      <span>Offset (h)</span>
                      <span>
                        {"00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F"}
                      </span>
                      <span>ASCII</span>
                    </div>
                    {hexLines.length ? (
                      hexLines.map((line) => (
                        <div className="hex-line" key={line.offset}>
                          <span>{line.offset}</span>
                          <span>{line.hex}</span>
                          <span>{line.ascii}</span>
                        </div>
                      ))
                    ) : (
                      <p className="pane-empty">
                        이 범위의 Hex 데이터가 제공되지 않았습니다.
                      </p>
                    )}
                  </div>
                ) : (
                  <pre className="text-view" aria-label="원본 텍스트">
                    {raw.text_preview ??
                      "텍스트로 해석할 수 없습니다. Hex 보기에서 바이트를 확인하세요."}
                  </pre>
                )}
                <Section title="원본 범위 및 출처">
                  <Fields
                    value={{
                      ...raw,
                      hex_preview: undefined,
                      text_preview: undefined,
                    }}
                  />
                </Section>
              </>
            ) : (
              <p className="pane-empty">
                이 항목의 원본 바이트 읽기가 제공되지 않습니다. 메타데이터에서
                출처와 지원 상태를 확인하세요.
              </p>
            )}
          </>
        )}
      </div>
      {raw && (
        <footer className="viewer-status">
          Offset {raw.returned_offset ?? range.offset} ·{" "}
          {raw.returned_length ?? 0} bytes 반환
          {typeof total === "number" ? ` / 전체 ${total} bytes` : ""}
          {raw.truncated ? " · 요청/미리보기 범위 제한" : ""}
          {raw.synthetic ? " · 합성 데모 데이터" : ""}
        </footer>
      )}
    </section>
  );
}
