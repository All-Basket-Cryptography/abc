# ABC 驗收清單

來源：主計畫第 21 節。這些是待執行的驗收要求，不是既有測試結果。


下表是計畫中的必要驗收設計，**目前尚未執行**。完整任務依賴與交付物見後附任務清單及 `TASKS.json`。

| ID | 操作／情境 | 必須觀察到的結果 |
|---|---|---|
| AC-01 | 重複 ID、無效 Reference、Path Traversal、未知 Schema | Validator 明確拒絕 |
| AC-02 | SHA-256 實作變更 | 真正的 SHA／HMAC／HKDF／Binding 消費者被選取 |
| AC-03 | 獨立 SHA-3 葉節點變更 | 不重跑 SHA-256 的無關重型工作 |
| AC-04 | 共用 Lean Foundation 變更 | 所有實際 Import 消費者重新檢查 |
| AC-05 | 刪除、改名、拆分模組、移除依賴 | Base／Head 聯集保留所有必要影響 |
| AC-06 | Base 缺失或未知檔案 | 保守全範圍必要工作或阻擋；不是空成功 |
| AC-07 | 知識圖循環與 Task Graph 循環 | 前者可表示；後者診斷並拒絕排程 |
| AC-08 | 純文件變更 | 文件／Metadata 驗收；無無關 Proof 重跑 |
| AC-09 | 工具鏈、Features、平台、Verifier／Policy 改變 | 對應 Cache／Evidence 失效 |
| AC-10 | 直接或轉遞 `sorryAx` | 正式 Proof Gate 失敗 |
| AC-11 | 未批准公理、Native Trust 不符 Profile | Gate 失敗並指出依賴 |
| AC-12 | 偷改定理／Spec／Generated Model | 可信命題比對或重新抽取攔下 |
| AC-13 | 程式變更但沿用舊證據 | Subject Digest 不符，拒絕 |
| AC-14 | 偽造 Pass JSON 或無產物 | Evidence Verifier 拒絕 |
| AC-15 | Fork PR 快取提升為 Release 證據 | Trust Domain 檢查拒絕 |
| AC-16 | Fuzz 忽略輸入／吞錯、Timeout／OOM | Harness Sanity 或結果分類暴露問題，不假綠 |
| AC-17 | 多 Wrapper 共用核心 | 不能被計成多個獨立 Differential Oracle |
| AC-18 | 刻意錯誤密碼學輸出 | KAT／Differential／適用 Proof Gate 確實失敗 |
| AC-19 | 七個核心 SDK 外部安裝 | 從打包成品安裝並執行同組向量 |
| AC-20 | C／C++／JVM／Python 邊界錯誤 | 有效記憶體前提下，契約與預期錯誤一致 |
| AC-21 | 舊版與新版／跨語言資料 | 允許的互通成功，不允許的組合明確拒絕 |
| AC-22 | RNG 不可用或測試 RNG 誤入 Production | 明確失敗，不做不安全退回 |
| AC-23 | 未批准 Provider／CPU 分支 | Dispatcher 拒絕或不選取，不靜默降級 |
| AC-24 | 歷史／Broken 模組意外進預設 Production 包 | Dependency／Policy Gate 阻擋 |
| AC-25 | Workflow 子任務失敗、取消、缺少證據 | 固定 Required Gate 不成功 |
| AC-26 | 上游停更與弱點修補演練 | 受影響版本可查，Patch／Backport／遷移可重現 |
| AC-27 | Package 缺少檔案、Native Library 或錯誤 Target | 外部 Consumer Test 阻擋發布 |
| AC-28 | 重建 Release 與發布 Bytes | 來源、Evidence、Digest、Provenance 對得上 |
| AC-29 | 撤回／Stale／缺失證據 | Explorer 不再顯示有效完成狀態 |
| AC-30 | 不支援工具、語言或平台 | 真實 `blocked/planned/unsupported`，不產生假的成功證據 |
