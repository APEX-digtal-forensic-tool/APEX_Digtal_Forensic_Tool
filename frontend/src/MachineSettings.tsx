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
      <p>
        STT는 녹음의 음성을 글자로 바꾸는 기능입니다. API 키가 아닌 음성 인식용
        모델 파일을 PC에 한 번 준비한 뒤 선택하면 오프라인으로 실행할 수
        있습니다.
      </p>
      {error != null && <ErrorState error={error} />}
      {!data ? (
        !error && <Loading />
      ) : (
        <>
          {data.managed && (
            <p>환경변수로 관리되는 설정입니다. 실행 환경에서 변경해주세요.</p>
          )}
          <fieldset disabled={busy || data.managed}>
            <legend>분석기와 모델</legend>
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
                  setSettings((s) => ({
                    ...s,
                    stt_provider: e.target.value,
                    model_reference: null,
                    model_label: undefined,
                    stt_model_path: null,
                  }))
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
                  settings.stt_provider === "whisper.cpp"
                    ? "file"
                    : "directory",
                )
              }
            >
              음성 모델 선택
            </button>
            <p>
              {settings.model_label ?? settings.stt_model_path ?? "모델 미설정"}
            </p>
            {settings.stt_provider === "faster-whisper" ? (
              <p>
                Faster Whisper/CTranslate2 모델의 전체 폴더를 선택하세요.
                model.bin, config.json, tokenizer.json, vocabulary 파일이
                필요합니다. 한국어는 다국어 모델을 사용하세요. 이름이 .en으로
                끝나는 모델은 영어 전용입니다.
              </p>
            ) : (
              <p>
                whisper.cpp 모델 파일과 PATH에 설치된 whisper-cli 실행 파일이
                필요합니다. 기본 Faster Whisper는 별도 실행 파일을 설치하지
                않아도 됩니다.
              </p>
            )}
            <button
              onClick={() =>
                setSettings((s) => ({
                  ...s,
                  model_reference: null,
                  model_label: undefined,
                  stt_model_path: null,
                }))
              }
            >
              음성 모델 설정 해제
            </button>
            <button disabled={busy} onClick={() => void save()}>
              분석기 설정 저장
            </button>
          </fieldset>
          <p role="status">
            {data.stt?.is_available
              ? "저장된 STT 설정: 분석기와 모델 파일 준비됨"
              : "저장된 STT 설정: 모델 또는 분석기 준비 필요"}
          </p>
          <details>
            <summary>실행 가능 여부</summary>
            <Fields value={{ ocr: data.ocr, stt: data.stt }} />
          </details>
        </>
      )}
    </div>
  );
}
