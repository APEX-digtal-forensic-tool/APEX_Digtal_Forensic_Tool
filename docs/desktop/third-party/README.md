# Bundled local analysis components

The Windows desktop distribution contains unmodified FFmpeg/ffprobe LGPL shared builds
from BtbN (linked by the FFmpeg download page). DLLs remain separate and replaceable.
The complete upstream distribution, including its licenses and documentation, is preserved
under `runtime/assets/media`. Build scripts and exact source references are recorded in
`runtime/assets/asset-manifest.json`; this manifest pins the archive SHA-256 and size.

- FFmpeg: https://ffmpeg.org/ ; upstream license and build flags are included in the archive.
- Build scripts: https://github.com/BtbN/FFmpeg-Builds/tree/autobuild-2026-10-18-13-01
- FFmpeg source: https://github.com/FFmpeg/FFmpeg/commit/46d899d7a0
- Source/dependency retrieval recipes: the pinned BtbN build scripts.

The bundled multilingual Whisper base model is the MIT-licensed OpenAI Whisper model
converted to CTranslate2 by Systran. Its pinned model card is included alongside the
weights, and the OpenAI license is included here as `WHISPER-LICENSE.txt`.

- https://github.com/openai/whisper
- https://huggingface.co/Systran/faster-whisper-base/tree/ebe41f70d5b6dfa9166e2c581c45c9c0cfc57b66

RapidOCR models and ONNX Runtime, CTranslate2, Faster Whisper, PyAV, Impacket and their
dependencies retain their upstream licenses in the native runtime collected by PyInstaller.
Model downloads occur only during development/build preparation. Evidence is never part
of asset downloads. Inference uses local files and requires no account or AI API key.
