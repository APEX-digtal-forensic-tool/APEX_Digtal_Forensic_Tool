import { useEffect, useState } from "react";
import { gateway, unwrap, type Row } from "./gateway";
import { ErrorState, Fields, Loading } from "./ui";

const settingsErrorReasons: Record<string, string> = {
  JSON_SYNTAX: "JSON 문법 오류",
  EMPTY: "설정 파일이 비어 있음 (잘린 파일)",
  ENCODING: "UTF-8이 아닌 인코딩",
  NOT_OBJECT: "설정 형식이 객체가 아님",
  INVALID_FIELDS: "허용되지 않는 필드 또는 값",
  UNREADABLE: "파일을 읽을 수 없음",
};

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
  async function reset() {
    setBusy(true);
    setError(null);
    try {
      const result = await gateway.call("machine.reset");
      setData(result);
      setSettings(result.settings);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
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
        로컬 모델을 사용합니다. 설치 파일의 기본 다국어 모델로 한국어·영어를
        오프라인에서 분석할 수 있습니다. 별도의 계정이나 다운로드는 필요하지
        않습니다.
      </p>
      {error != null && <ErrorState error={error} />}
      {!data ? (
        !error && <Loading />
      ) : (
        <>
          <h4>로컬 기능 준비 상태</h4>
          <ul>
            <li>
              기본 STT 모델:{" "}
              {data.bundled_stt?.available
                ? data.bundled_stt.name
                : "내장 모델 없음 · 소스 실행 시 자산 준비 또는 모델 선택 필요"}
            </li>
            <li>
              영상 프레임 FFmpeg:{" "}
              {data.media?.ffmpeg?.is_available ? "준비됨" : "준비 필요"}
            </li>
            <li>
              영상·음성 정보 ffprobe:{" "}
              {data.media?.ffprobe?.is_available ? "준비됨" : "준비 필요"}
            </li>
            <li>
              DPAPI 복호화 엔진:{" "}
              {data.dpapi?.runtime_status === "IMPLEMENTED_RUNTIME"
                ? "준비됨 · 대상의 키·자격정보는 별도 필요"
                : "라이브러리 준비 필요"}
            </li>
          </ul>
          {data.managed && (
            <p>환경변수로 관리되는 설정입니다. 실행 환경에서 변경해주세요.</p>
          )}
          {data.settings_error && (
            <div role="alert" className="settings-error">
              <p>
                저장된 분석기 설정을 읽지 못했습니다:{" "}
                {settingsErrorReasons[data.settings_error.reason] ??
                  data.settings_error.reason}
                {data.settings_error.fields?.length
                  ? ` (${data.settings_error.fields.join(", ")})`
                  : ""}
                . 설정을 복구하기 전까지 OCR·STT 실행은 거부됩니다.
              </p>
              {data.settings_error.resettable ? (
                <button disabled={busy} onClick={() => void reset()}>
                  손상된 설정 보존 후 기본값으로 복구
                </button>
              ) : (
                <p>
                  실행 환경의 APEX_DESKTOP_MACHINE_CONFIG 값을 수정해주세요.
                </p>
              )}
            </div>
          )}
          {data.preserved_settings_file && (
            <p role="status">
              이전 설정 파일을 {data.preserved_settings_file} 이름으로
              보존했습니다. 사건·증거 데이터는 변경되지 않았습니다.
            </p>
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
              {settings.model_label ??
                settings.stt_model_path ??
                (settings.stt_provider === "faster-whisper" &&
                data.bundled_stt?.available
                  ? "내장 다국어 모델 사용"
                  : "모델 미설정")}
            </p>
            {settings.stt_provider === "faster-whisper" ? (
              <p>
                더 큰 모델을 사용하려면 Faster Whisper/CTranslate2 모델의 전체
                폴더를 선택하세요. model.bin, config.json, tokenizer.json,
                vocabulary 파일이 필요합니다. 한국어는 다국어 모델을 사용하세요.
                이름이 .en으로 끝나는 모델은 영어 전용입니다.
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
              {settings.stt_provider === "faster-whisper"
                ? "기본 내장 모델로 복원"
                : "음성 모델 설정 해제"}
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
            <Fields
              value={{
                ocr: data.ocr,
                stt: data.stt,
                media: data.media,
                dpapi: data.dpapi,
              }}
            />
          </details>
        </>
      )}
    </div>
  );
}
