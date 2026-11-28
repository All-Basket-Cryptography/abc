# ABC Agent 啟動方式

此套件是一份完整的待實作計畫，不含已完成的密碼學函式庫或已通過的證明。

## 使用方式

1. 把整個套件交給 Agent，或將內容放進目標 Repo 的 `docs/plan/abc/`。
2. 要求 Agent 先讀 `ABC-MASTER-PLAN.zh-Hant.md`、`TASKS.json` 與本套件 `AGENTS.md`。
3. 若目標 Repo 已有 `AGENTS.md`，保留既有內容並依上位規則合併，不直接覆蓋。
4. 貼上下面的啟動指令。只交付一份檔案時，主計畫也包含完整任務與關鍵驗收規格。

## 可直接貼給 Agent 的指令

```text
Implement All-Basket Cryptography (ABC) using the attached master plan,
TASKS.json, and AGENTS.md. Treat them as the implementation specification,
not as a request to write another proposal.

Inspect the current repository and instructions first. Preserve existing
work. Keep all first-party source, specifications, proofs, SDKs, automation,
documentation, and governance in one monorepo.

Begin with ABC-001 and complete M0 and M1 as a working, reproducible system.
Then continue into M2 and the remaining dependency-ready tasks. Keep the full
scope: the historical and contemporary catalog, original-language upstream
implementations, Lean-based evidence, fuzzing, and installable Rust, C, C++,
Go, Java, npm, and PyPI SDKs, with the listed extension ecosystems.

Use actual pinned toolchains and actual verification results. Do not invent
proofs, successful tests, compatible versions, maintainers, or audits. Do not
use empty SDKs, mock verifiers, hard-coded pass states, hidden axioms, weakened
theorems, or ignored failures to satisfy a milestone.

Implement dependency-aware incremental verification, including base/head
impact analysis, deleted and renamed files, trusted cache boundaries,
negative fixtures, and a final gate that checks every required result.

Keep source/specification, core implementation, binding, built target,
cryptographic security, constant-time claims, and production approval as
separate evidence scopes. A tested or installable package is not automatically
formally verified or production-approved.

For every completed task, update task status and record the actual commands,
artifacts, evidence, and remaining limitations in docs/status/. If a proof
tool or external dependency blocks a task, retain a minimal reproduction,
mark only the affected work blocked, and continue independent work.

Proceed autonomously with authorized reversible local work. For external
publication or other side effects, follow the current session authorization.
Finish local packages, consumer tests, dry runs, and reviewable manifests
before requesting any final approval that is actually necessary.

Deliver working code and reproducible evidence. Do not stop after scaffolding
or restating the plan.
```

## 第一批應拿到的成果

- 真實工具鏈實驗與版本鎖定。
- 資料契約、Registry、Validator 與負例。
- Typed Graph、Impact Planner、任務 Runner、證據與快取信任隔離。
- GitHub Actions 可重用工作與固定最終 Gate。
- 一個完整小型 Proof／Fuzz Probe；它不能冒充生產密碼學。
- 明確的 M2 SHA-256、SDK、完整形式化驗證進度與下一步。

如果 Agent 回傳只有目錄、TODO、假的 Verified 狀態或尚未執行的測試清單，不能視為完成。
