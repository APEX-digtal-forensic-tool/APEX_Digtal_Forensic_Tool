import { useEffect, useState } from "react";
import { gateway, unwrap, type Row } from "./gateway";
import { ErrorState, Fields, Loading } from "./ui";

export function MachineSettings() {
  const [data, setData] = useState<Row | null>(null);
  const [settings, setSettings] = useState<Row>({});
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    gateway
      .call("machine.capabilities")
      .then((r) => {
        if (live) {
          setData(r);
          setSettings(r.settings);
        }
      })
      .catch((e) => {
        if (live) setError(e);
      });
    return () => {
      live = false;
    };
  }, []);
  async function pick(key: string, kind: "file" | "directory") {
    if (!window.apex) return;
    try {
      const picked = unwrap(await window.apex.pick(kind));
      if (picked)
        setSettings((s) => ({
          ...s,
          [key + "_reference"]: picked.reference,
          [key + "_label"]: picked.name,
        }));
    } catch (e) {
      setError(e);
    }
  }
  async function save() {
    setBusy(true);
    setError(null);
    try {
      const result = await gateway.call("machine.configure", {
        ocr_provider: settings.ocr_provider,
        stt_provider: settings.stt_provider,
        model_reference: settings.model_reference,
        tessdata_reference: settings.tessdata_reference,
      });
      setData(result);
      setSettings(result.settings);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="card">
      <h3>로컬 OCR·음성 인식 설정</h3>
      <p>
        원본을 외부로 보내지 않습니다. 설치된 분석기와 로컬 모델을 사용합니다.
      </p>
      {error != null && <ErrorState error={error} />}
      {!data ? (
        !error && <Loading />
      ) : (
        <>
          <label>
            문자 인식
            <select
              value={settings.ocr_provider}
              onChange={(e) =>
                setSettings((s) => ({ ...s, ocr_provider: e.target.value }))
              }
            >
              <option value="auto">사용 가능한 분석기 자동 선택</option>
              <option value="tesseract">Tesseract</option>
              <option value="rapidocr">RapidOCR</option>
            </select>
          </label>
          <button
            disabled={busy}
            onClick={() => void pick("tessdata", "directory")}
          >
            OCR 언어 모델 폴더 선택
          </button>
          <p>
            {settings.tessdata_label ??
              settings.tessdata_path ??
              "기본 언어 모델 경로"}
          </p>
          <label>
            음성 인식
            <select
              value={settings.stt_provider}
              onChange={(e) =>
                setSettings((s) => ({ ...s, stt_provider: e.target.value }))
              }
            >
              <option value="faster-whisper">Faster Whisper</option>
              <option value="whisper.cpp">whisper.cpp</option>
            </select>
          </label>
          <button
            disabled={busy}
            onClick={() =>
              void pick(
                "model",
                settings.stt_provider === "whisper.cpp" ? "file" : "directory",
              )
            }
          >
            음성 모델 선택
          </button>
          <p>
            {settings.model_label ?? settings.stt_model_path ?? "모델 미설정"}
          </p>
          <button disabled={busy} onClick={() => void save()}>
            분석기 설정 저장
          </button>
          <details>
            <summary>실행 가능 여부</summary>
            <Fields value={{ ocr: data.ocr, stt: data.stt }} />
          </details>
        </>
      )}
    </div>
  );
}
