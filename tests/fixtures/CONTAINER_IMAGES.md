# Synthetic container fixtures

`container-images.json` holds gzip/base64 bytes, original sizes and SHA-256 values. No personal evidence is included.

- compressed.E01: compressed EWF acquired from a FAT12 test image with ewfacquire.
- disk.vhd / disk.vhdx: qemu-img conversions of the same test image.
- All three contain `문서.txt` with UTF-8 text `E01 가상 디스크의 실제 내용`.
- streams.img: 32 MiB NTFS, created with mkntfs. `/document.txt` has default content `normal file body`, resident ADS `hidden` containing `ADS secret forensic stream`, and nonresident ADS `large` containing `bytes(range(256)) * 256`.
- ocr.png: generated test text `HELLO 123`, using the existing OCR fixture helper.

Regenerate in a development environment with ewfacquire, qemu-img, mkntfs and ntfscp on PATH:

```sh
uv run --no-sync python tools/generate_container_fixtures.py
```

Generation uses a private temporary directory and never mounts a filesystem. Container timestamps/identifiers can differ between runs; tests verify the recorded hashes and expected logical contents. Normal test runs need Python dependencies only, not these external CLI generators.
