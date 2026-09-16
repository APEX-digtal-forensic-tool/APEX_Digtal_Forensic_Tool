# APEX Frontend 연동 변경사항 안내

## 1. 목적

Forensic Engine에 AI Data Governance 기능이 추가되면서, 향후 Frontend에서도 일부 UI 및 연동 변경이 필요할 수 있습니다.

다만 이번 Engine 변경으로 인해 기존 Frontend 구조나 기존 AI Assistance / Context 계약이 즉시 깨지는 것은 아닙니다.

Frontend의 역할은 AI 정책을 직접 판단하는 것이 아니라, 사용자가 정책을 설정할 수 있도록 하고 Engine이 반환한 Governance 결과를 표시하는 것입니다.

---

## 2. Frontend에서 예상되는 주요 변경

### Case AI Policy 설정 UI

Case 단위로 AI 사용 정책을 설정할 수 있는 화면이 추가될 수 있습니다.

예상 항목:

- AI 사용 허용 여부
- External AI Provider 사용 허용 여부
- Local-only 정책
- 허용 가능한 Data Classification
- Secret 데이터 처리 정책
- Raw Data 허용 여부
- Redaction 필수 여부
- Safe Projection 필수 여부

예시 구조:

```text
Case Settings
 └─ AI Data Policy
     ├─ AI 사용 허용
     ├─ External AI 허용
     ├─ Local-only
     ├─ 허용 Classification
     ├─ Secret 처리 정책
     ├─ Raw Data 허용
     ├─ Redaction 필수
     └─ Projection 필수
```

---

## 3. AI 실행 시 Egress Decision 표시

Frontend에서 AI 기능을 실행할 때 Engine의 Egress Decision 결과를 사용자에게 표시할 수 있어야 합니다.

주요 상태:

```text
ALLOW
→ 정상 실행 가능

DENY
→ Case 정책상 AI 데이터 사용 또는 전송이 차단됨

ALLOW_WITH_REDACTION
→ 민감정보 제거 후 재평가 필요

ALLOW_PROJECTION_ONLY
→ Safe Projection 생성 후 재평가 필요
```

중요:

`ALLOW_WITH_REDACTION`과 `ALLOW_PROJECTION_ONLY`는 최종 허용 상태가 아닙니다.

Frontend는 이를 실제 실행 허가로 판단하지 않고, Engine 또는 Runtime에서 transformation 및 재평가가 완료된 뒤 최종 `ALLOW`를 받아야 합니다.

---

## 4. AI Governance Audit 표시

향후 Frontend에서 AI Governance Audit 정보를 조회하는 화면이 추가될 수 있습니다.

예상 표시 정보:

- Case
- Source
- Source Type
- Data Classification
- Destination Category
- Egress Decision
- Decision Reason
- Redaction 적용 여부
- Safe Projection 적용 여부
- Policy Revision
- Timestamp

예시:

```text
AI Data Access History

Case        : CASE-001
Source      : ARTIFACT-123
Destination : EXTERNAL
Class       : SECRET
Decision    : DENY
Reason      : SECRET_DENIED
Redaction   : false
Projection  : false
Time        : 2026-09-08T...
```

---

## 5. Frontend가 직접 정책을 판단하면 안 됨

Frontend에 Governance 로직을 직접 구현하지 않습니다.

잘못된 예:

```text
Frontend
→ if classification == SECRET:
      deny
```

이 방식은 Engine 정책과 Frontend 정책이 서로 달라질 수 있으므로 사용하지 않습니다.

올바른 흐름:

```text
Frontend
   ↓
Public Engine Interface
   ↓
AI Governance Service
   ↓
Decision
   ↓
Frontend에 결과 표시
```

Frontend는 정책 입력과 결과 표시를 담당하고 실제 allow / deny 판단은 Engine이 담당합니다.

---

## 6. Frontend와 Engine의 책임 분리

### Frontend 책임

- Case AI Policy 설정 UI
- Governance 상태 표시
- Egress Decision 표시
- Redaction / Projection 요구 안내
- Audit History 조회 및 표시
- 사용자 경고 및 확인 UI

### Engine 책임

- Case AI Policy 관리
- Data Classification Contract
- Egress Policy Evaluation
- Safe AI Projection 생성
- Source Fingerprint 검증
- Egress Audit 저장
- 최종 Governance Decision 생성

---

## 7. MCP / Runtime과의 관계

실제 AI Provider 실행은 Frontend가 직접 수행하지 않습니다.

예상 흐름:

```text
Frontend
   ↓
Engine / Public Interface
   ↓
AI Governance
   ↓
MCP / AI Runtime
   ↓
Local 또는 External Provider
```

Frontend는 사용자가 AI 기능을 요청하고 결과를 표시하는 UX 계층입니다.

실제 Provider 호출 전 Governance Enforcement는 MCP / AI Runtime 계층에서 수행해야 합니다.

---

## 8. 기존 Frontend에 대한 영향

현재 Engine 변경만으로 기존 Frontend를 즉시 수정해야 하는 것은 아닙니다.

기존 다음 계약은 유지됩니다.

- AI Assistance
- Context
- 기존 Engine Interface
- 기존 Forensic Artifact / Search / Timeline 흐름

따라서 현재 Frontend가 존재한다면 기존 기능은 유지할 수 있고, Governance 관련 UI는 추가 기능 형태로 연동하면 됩니다.

---

## 9. Frontend 담당자 체크리스트

```text
[ ] Frontend에서 직접 AI 정책 판단을 하지 않는가
[ ] Case AI Policy 설정 UI가 필요한지 검토했는가
[ ] Egress Decision 상태를 사용자에게 표시할 수 있는가
[ ] DENY 상태에서 AI 실행 UI를 중단하는가
[ ] ALLOW_WITH_REDACTION을 최종 허용으로 취급하지 않는가
[ ] ALLOW_PROJECTION_ONLY를 최종 허용으로 취급하지 않는가
[ ] Audit History 표시가 필요한지 검토했는가
[ ] Classification을 Frontend에서 임의로 변경하지 않는가
[ ] Engine / MCP가 제공한 Governance 결과를 그대로 사용하는가
[ ] Frontend가 SQLite 또는 Governance Repository에 직접 접근하지 않는가
```

---

## 10. 최종 구조

```text
User
 ↓
Frontend
 ├─ Policy Settings UI
 ├─ Decision Status UI
 ├─ Warning / Confirmation
 └─ Audit History
 ↓
Public Engine Interface
 ↓
AI Governance
 ├─ Case AI Policy
 ├─ Data Classification
 ├─ Egress Decision
 ├─ Safe Projection
 └─ Audit
 ↓
MCP / AI Runtime
 ↓
Local / External AI Provider
```

Frontend는 사용자 경험과 상태 표시를 담당하고, 보안 정책 판단과 데이터 통제는 Engine 및 Runtime 계층에서 담당합니다.
