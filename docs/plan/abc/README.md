# ABC 開發 Agent 交付包

**版本 1.0 · 2026-11-28**

這是 All-Basket Cryptography 的完整工程計畫與可執行任務規格，尚未包含已完成的密碼學實作、已通過的 Lean 證明或已發布套件。

## 先做什麼

先讀 [START-HERE.md](START-HERE.md)，將其中指令與整包檔案交給 Agent。已有 Repo 時將文件放入 `docs/plan/abc/`，保留既有 `AGENTS.md` 與使用者工作。

## 檔案

| 檔案 | 用途 |
|---|---|
| [ABC-MASTER-PLAN.zh-Hant.md](ABC-MASTER-PLAN.zh-Hant.md) | 完整計畫：範圍、架構、分類、資料契約、驗證、SDK、CI、維護、40 項任務、啟動指令；可單獨交付 |
| [START-HERE.md](START-HERE.md) | 使用方式、可直接貼給 Agent 的啟動指令 |
| [AGENTS.md](AGENTS.md) | 接手 Agent 的工程與驗證誠信規則；應和既有規則合併 |
| [TASKS.json](TASKS.json) | 40 個任務的機器可讀 Backlog；包含依賴、交付物、驗收與初始狀態 |
| [TASKS.schema.json](TASKS.schema.json) | Backlog 檔案本身的 JSON Schema；不是未來 ABC Registry Schemas 的替代品 |
| [ACCEPTANCE.md](ACCEPTANCE.md) | 主計畫第 21 節的驗收清單副本，方便執行時查閱 |
| [HANDOFF-MANIFEST.json](HANDOFF-MANIFEST.json) | 交付檔案的 SHA-256／大小清單；供完整性檢查，不是密碼學實作安全證據 |

## 使用規則

主計畫是需求與驗收依據，`TASKS.json` 是排程拆分，`AGENTS.md` 是接手工作規則。若後續使用者變更需求，先同步修改受影響文件與任務，不讓兩種規格長期矛盾。

計畫中的 CLI 是待實作介面。所有任務目前都是 `not_started`。交付包的結構檢查不代表未來函式庫、Proof Pipeline 或 GitHub Actions 已完成。

第一批先完成 M0／M1，再持續推進真實 SHA-256 與所有指定 SDK。工具阻塞要如實保存；不以假的成功狀態、空套件或縮弱定理結案。
