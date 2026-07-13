# 제안 디렉터리 구조

이 문서는 구현 단계에서 생성할 구조를 정의한다. 현재 설계 단계에서는 문서와 Schema만
생성하며 아래 Python 파일은 아직 구현하지 않는다.

```text
APEX/
├── README.md
├── pyproject.toml
├── src/
│   └── apex/
│       ├── domain/
│       │   ├── cases/
│       │   ├── evidence/
│       │   ├── filesystem/
│       │   ├── artifacts/
│       │   ├── timeline/
│       │   ├── search/
│       │   └── jobs/
│       ├── application/
│       │   ├── commands/
│       │   ├── queries/
│       │   └── services/
│       ├── ports/
│       │   ├── evidence_reader.py
│       │   ├── repositories.py
│       │   ├── index.py
│       │   ├── cache.py
│       │   ├── clock.py
│       │   └── event_sink.py
│       ├── adapters/
│       │   ├── evidence/
│       │   │   ├── directory/
│       │   │   ├── raw/
│       │   │   ├── e01/
│       │   │   └── vhd/
│       │   ├── persistence/
│       │   │   └── sqlite/
│       │   ├── index/
│       │   │   └── sqlite_fts/
│       │   └── cache/
│       │       └── filesystem/
│       ├── analyzers/
│       │   ├── base/
│       │   ├── filesystem/
│       │   └── artifacts/
│       │       ├── registry/
│       │       ├── eventlog/
│       │       ├── prefetch/
│       │       ├── browser/
│       │       └── multimedia/
│       ├── timeline/
│       ├── search/
│       ├── jobs/
│       ├── api/
│       │   ├── http/
│       │   ├── dto/
│       │   └── serialization/
│       ├── ai_layer/
│       │   ├── ports/
│       │   ├── dto/
│       │   └── README.md
│       ├── observability/
│       └── bootstrap/
├── schemas/
│   └── v1/
│       ├── common.schema.json
│       ├── api-response.schema.json
│       ├── case.schema.json
│       ├── evidence.schema.json
│       ├── file.schema.json
│       ├── artifact.schema.json
│       ├── timeline-event.schema.json
│       ├── search.schema.json
│       ├── job.schema.json
│       └── ai-enrichment.schema.json
├── migrations/
│   └── sqlite/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── fixtures/
│   └── performance/
├── docs/
└── tools/
```

## 구조 원칙

| 원칙 | 적용 방식 |
| --- | --- |
| Domain 독립성 | `domain`은 DB, HTTP, 파일 형식 Library를 Import하지 않음 |
| Use Case 분리 | 상태 변경은 `commands`, 조회는 `queries`에 배치 |
| Port 우선 | Evidence/DB/Index/Cache 연동은 `ports`의 계약을 먼저 정의 |
| Adapter 격리 | E01, VHD, SQLite 등 외부 기술을 `adapters`에 제한 |
| Analyzer 독립성 | Artifact 종류별 패키지와 Manifest, Fixture, Test 보유 |
| DTO 경계 | API DTO는 Domain Entity를 그대로 노출하지 않음 |
| AI 격리 | Provider-neutral 계약만 `ai_layer`에 두고 구현체는 Core 외부에 둠 |
| Schema 동기화 | DTO Contract Test로 `schemas/v1`과 실제 직렬화 결과를 검증 |

## 금지되는 의존성

```text
domain       -> api/adapters/analyzers/ai_layer
analyzers    -> api/http
application  -> concrete sqlite/e01/vhd adapter
core modules -> MCP SDK / LLM provider SDK / prompt package
ai_layer     -> artifact 원본 행 수정
```

MCP Adapter는 이 트리 안에 만들지 않는다. 필요 시 별도 저장소 또는 별도 배포 패키지에서
`api`의 공개 계약을 소비한다.
