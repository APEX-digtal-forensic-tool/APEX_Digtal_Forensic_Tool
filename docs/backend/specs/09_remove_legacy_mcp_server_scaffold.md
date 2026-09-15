# Phase 9 — 레거시 `mcp_server/` 스캐폴드 제거

상태: 완료 (2026-09-15)
선행조건: 없음
분류: chore

## 배경

`mcp_server/`는 실제 MCP 구현(`src/apex_mcp`)이 만들어지기 전에 학습/시작용으로
만든 완전히 별개의 스캐폴드다. 지금은 아무도 안 쓰고, git에 커밋된 적도 없는
untracked 상태로 리포 루트에 그냥 남아있다. `.venv`까지 통째로 들어있어서
용량도 크고, 저장소를 새로 clone하는 사람이 헷갈릴 수 있다.

## 할 일

1. `mcp_server/` 디렉터리 전체를 삭제한다 (`git status`로 untracked인 것
   재확인 후 `rm -rf mcp_server` — 커밋된 적 없으니 `git rm` 필요 없음).
2. `.gitignore`에 이미 `mcp_server/`나 `.venv` 관련 항목이 있는지 확인하고,
   없으면 재발 방지용으로 추가할지는 판단해서 결정 (필수는 아님, 애초에
   커밋된 적이 없어서 원인 재발 가능성은 낮음).
3. 삭제 후 `ruff check .` (레포 루트 전체, 이번엔 `mcp_server/` 제외 없이)를
   돌려서 전체가 클린한지 확인.
4. 혹시 `docs/` 안에 `mcp_server/`를 참조하는 옛날 문서가 있는지 검색해서
   있으면 같이 정리 (이 저장소 안에서만 검색 — Claude 프로젝트 쪽 문서는
   해당 없음).

## 완료 조건

- [ ] `mcp_server/` 디렉터리 삭제됨, `git status`에서 더 이상 안 보임
- [ ] `ruff check .` 레포 전체 기준 클린
- [ ] PR 생성

## PR 규칙 (기존 6절과 동일)

- 브랜치: `chore/backend-phase-9-remove-legacy-mcp-server`
- PR 제목: `chore(backend): Phase 9 — 레거시 mcp_server 스캐폴드 제거`
- base: `main`, 머지는 사람이 함
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 금지
