# All-Basket Cryptography（ABC）完整工程計畫

**文件版本：1.0 · 日期：2026-11-28（Asia/Taipei）**  
**用途：可交付給開發 Agent 的產品範圍、架構決策、執行順序與驗收契約。**  
**狀態：待實作規格。本文沒有宣稱任何演算法、SDK、證明或認證已經完成。**

## 0. 交給 Agent 前先讀這一節

ABC 的目標是：在**唯一一個第一方 Git Repository** 中，系統化收錄公開可辨識的歷史與現代密碼學，管理不同來源和語言的實作，建立 Lean 規格與逐實作證據，持續 Fuzz，並發行可直接整合到產品的多語言 SDK。

最終希望成為產業共同維護、長期可信賴的密碼學基礎設施。這是採用與治理目標，不是目前已獲承認的標準或「最安全」保證。

使用者已確定的要求：

1. 維護一個 Monorepo；不拆成多個需要獨立人工同步的第一方原始碼 Repository。
2. 保留完整歷史範圍，包括已淘汰、已破解、研究中與新發表的演算法。
3. 收錄既有開源實作，保留其原始語言、來源、版本與授權；不能改寫成 Rust 後宣稱原實作也已驗證。
4. 每個實作最終都以可追溯的 Lean 驗證和 Fuzz 為工作目標；未完成或工具不支援的部分必須公開標示。
5. 正式 SDK 範圍包含 **Rust crate、Go、Java、npm、PyPI、C、C++**；擴充範圍包含 Swift、Kotlin／Android、.NET 和 WASI。
6. 驗證、建置與測試按模組及真正依賴增量執行；修改無關模組不得重跑整套工作。
7. 同時交付文件、規格、文獻索引、歷史、安全狀態、相容性及遷移資訊。
8. 必須處理上游停更、漏洞、破壞性升級與 CI 長期失敗的維護問題。
9. ABC 的公開安全證據屬於開源專案能力；ISO 等商業顧問、認證、稽核服務不在此 Repository 的產品範圍。

### Agent 的第一個工作批次

讀完本文與 `AGENTS.md`，依 `TASKS.json` 開始 **M0 → M1**。完成工具鏈實驗、資料契約、依賴規劃器和小型端到端驗證後，持續進入 M2；不要只建立目錄或再交一份計畫。若缺少外部權限或工具實際不支援，記錄可重現阻塞並繼續不受阻的任務。

完整規劃與實際完成狀態必須分開。交付進度寫入 Repository 的 `docs/status/`；本套件中的所有任務初始皆為 `not_started`。

## 1. 用語與承諾

本文的「必須」是驗收要求；「應」是預設工程決策；「可以」是保留的擴充路線。後續使用者指示與所在環境的上位規則優先。

### 1.1 五個不能混淆的對象

| 對象 | 定義 | 證據邊界 |
|---|---|---|
| Algorithm／Construction／Protocol | 公開定義的計算或互動規則 | 功能、安全假設、版本與參數 |
| Specification | 對某個規格版本的形式化描述 | 規格忠實性與定理前提 |
| Implementation | 固定來源版本的一份實作，可含多語言 | 實際被驗證的來源、功能分支與外部呼叫 |
| Binding／SDK | 讓另一語言或框架使用實作的介面 | 轉碼、長度、錯誤、生命週期與平台相依 |
| Build Artifact | 一組來源、工具鏈、旗標與目標產生的成品 | 二進位、實際 dispatch、供應鏈與重現性 |

Rust 編成 WASM 後供 TypeScript 使用，通常是一個實作、不同建置與一個 Binding。純 TypeScript 重寫則是另一個實作。十個包裝相同核心的 SDK 不是十個獨立 Differential Testing Oracle。

### 1.2 永遠分開的四種狀態

- **收錄狀態**：是否有可追溯登錄與來源。
- **維護狀態**：誰負責、版本支援期、上游是否仍可用。
- **證據狀態**：對哪個版本、平台、命題完成何種驗證。
- **使用政策**：在指定用途與威脅模型下，是否允許進入正式產品。

歷史演算法可以實作正確、證明完整，仍禁止用於現代保密用途。形式化正確性、密碼學安全、常數時間、二進位正確性、產業審計及認證是不同主張。

## 2. 永久範圍與系統邊界

### 2.1 必須涵蓋

演算法與其變體、參數集、規格版本、形式化數學、構造與協定、公開密碼分析、原始碼實作、硬體最佳化實作、SDK、格式與金鑰抽象、測試向量、Fuzz Corpus、效能資料、漏洞公告、上游關係、文件與書目。

「所有」是持續擴張的收錄承諾方向，不能使用無法定義的全世界總數當作完成率分母。Coverage 的分母必須是某個公開來源集合和快照日期，例如指定競賽候選清單、標準目錄或實作集合。參數變體不可灌水成無限多項目。

### 2.2 生產發行與歷史收藏並存

所有內容在同一 Repo，但預設 Production 套件只包含獲准的實作與用途。歷史／研究內容有獨立模組與顯式依賴，Production Profile 在解析依賴與建置兩個階段阻擋未允許項目。

不建立一個預設把所有歷史演算法、FFI Backend、實驗協定編進去的巨大 SDK。不同語言各自建立最小 Package Dependency Closure。

### 2.3 不在本計畫內

商業 ISO 認證業務、SSO／IAM SaaS、託管 KMS／HSM、完整錢包產品、AI SaaS、一般雲端平台、付費安全評級。可以有 KMS／HSM Adapter 與測試；不因此建置託管服務。

## 3. 架構決策清單

| 決策 | 本版預設 |
|---|---|
| 專案名稱 | All-Basket Cryptography；簡稱 ABC；repo 建議 `all-basket-cryptography` |
| 原始碼管理 | 一個第一方 Monorepo；套件 Registry 與不可變成品儲存不算第二個原始碼 Repo |
| 共同證明環境 | Lean；數學基礎優先重用相容的 Mathlib |
| 第一條實作驗證路線 | Charon → Aeneas → Lean，先做相容性實驗再固定版本 [R1] |
| 官方首選可攜式核心 | Rust；限制在已確認可驗證的子集；不排除其他語言實作 |
| 初期建置 | Cargo、Lake、CMake、各語言原生工具，加一個薄的 `abc` 協調 CLI |
| 大型建置系統 | M0 不引入 Bazel／自製通用 Build System；出現量測瓶頸再用 ADR 決策 |
| Registry | YAML 1.2 的 JSON-compatible 子集；JSON Schema Draft 2020-12；禁止自訂 YAML Tag／重複 Key |
| 圖資料 | Registry、原生建置依賴、Lean imports、模組契約共同產生；執行 DAG 與知識圖分開 |
| UI | 靜態 Explorer；由 Metadata 與證據生成，不需要資料庫或常駐 Backend |
| CI | 優先 Public GitHub Actions Standard Runners；有預算、分片、重用與替代執行能力 |
| 公開文件 | 第一方 Repo 的程式、註解、API 文件與技術規格預設英文；本中文交付計畫供使用者閱讀 |
| 程式授權 | 新第一方程式預設提案 `MIT OR Apache-2.0`；保留既有 Repo 與上游授權，不擅自改授權 |
| 套件名稱 | 全部先視為候選；正式發布前檢查註冊權與現有名稱，不捏造已保留 namespace |

## 4. Monorepo 結構與唯一資料來源

以下目錄是完整邏輯邊界。Agent 應隨實際模組建立目錄；不要建立大量沒有內容或只有 TODO 的空殼。

| 路徑 | 內容與唯一責任 |
|---|---|
| `registry/` | Algorithms、Families、Parameters、Specs、Implementations、Bindings、Standards、Literature、Advisories 的 canonical records |
| `schemas/` | Registry、Evidence、Module、Task、Release-set JSON Schemas 與遷移 |
| `foundation/` | 可重用 Lean 數學、位元組、機率、安全遊戲、證明工具 |
| `algorithms/<function>/<family>/<variant>/` | 演算法說明、Lean 規格、各實作、所屬測試／證明／Fuzz |
| `constructions/` | 模式、AEAD、雜湊構造、樹、轉換與組合器 |
| `protocols/` | 狀態機、訊息格式、金鑰交換、PAKE、錢包與隱私協定 |
| `cryptanalysis/` | 來源明確的攻擊模型、限制、受控反例及防禦研究 |
| `runtime/` | 安全 API、Provider、Policy、Key、Format、Error 與 Dispatcher |
| `sdk/<ecosystem>/` | Rust、C、C++、Go、Java、JavaScript、Python、Swift、Kotlin、.NET、WASI |
| `assurance/` | 共用驗證 Runner、Axiom Audit、Evidence Checker、向量載入器、Differential 與側通道工具 |
| `compatibility/` | 跨版本／跨語言樣本、ABI、格式、遷移及外部使用者 Fixtures |
| `security/` | Threat Models、Disclosure、Support、Release 信任政策；不重複存一份 Advisory 正文 |
| `benchmarks/` | 測量方法、平台定義、重現腳本；大型結果放成品儲存 |
| `automation/` | 影響分析、任務調度、快取索引、上游監控、發布編排 |
| `tools/abc-cli/` | 統一指令入口，不能藏入密碼學產品 Runtime |
| `apps/explorer/` | 靜態搜尋、模組頁、證據與來源瀏覽 |
| `docs/` | 架構、ADR、Contributor Guide、使用教學、Milestone 狀態 |
| `governance/` | Charter、Maintainers、RFC、利益衝突與決策紀錄 |
| `fixtures/` | 隔離的負例、惡意 Metadata、失敗 Proof、跨版本與 Package Consumer 測試 |
| `.github/` | Workflow、Reusable Actions、CODEOWNERS、Issue／PR 模板 |

### 4.1 演算法模組範例

`algorithms/hash/sha2/sha256/` 包含：

- `README.md`：用途、來源、限制及 Registry ID。
- `module.toml`：檔案所有權、工作類型、顯式額外依賴、輸入與產出。
- `formal/`：獨立的規格、功能性質及待證命題。
- `implementations/abc-rust-portable/`：來源、Cargo manifest、Refinement、生成模型、實作專屬 Fuzz。
- `tests/`：官方／獨立向量、Streaming Properties、跨實作比較。

各語言 SDK 放在頂層 `sdk/`；不要為每個演算法複製一整套 npm／PyPI 專案。實作不只以 `rust` 命名，因為同一演算法可有多個 Rust 版本。

### 4.2 單一來源規則

Registry 擁有身份與描述；原生 Manifest 擁有實際建置依賴；`module.toml` 擁有任務、檔案與無法推導的額外關係；Evidence Runner 擁有結果。相同事實不得由兩個人工編輯位置同時決定。Generated Index 與網站一律重新生成並比對。

### 4.3 Repository 體積

所有第一方來源、規格、證明腳本、SDK 與治理都在同一 Repo。`.olean`、編譯目錄、巨型 Corpus、錄製 Trace、完整 Benchmark 結果與 Binary 不放普通 Git。它們使用 Releases／CI Artifacts／經授權的成品儲存，Repo 保存雜湊、大小、來源與重建方式。

上游可選「只索引」「固定版本依賴」「合法授權快照匯入」「ABC 維護分支快照」。不使用浮動 Git URL；不為達到單 Repo 而無條件複製所有上游。正式納入驗證的來源必須可以按固定版本取得和重現。

## 5. 密碼學分類法

分類是資料模型，不以一棵目錄樹代表全部知識。每個項目有主要功能、多個關係與標籤；PQC、歷史、用途與安全狀態均不是互斥的頂層功能類別。

| 主要領域 | 收錄範圍 |
|---|---|
| Classical | 替換、換位、多表、機械式歷史密碼及變體 |
| Symmetric | Block Cipher、Stream Cipher、Permutation、專用對稱原語 |
| Hash／XOF | 雜湊、可擴展輸出、Tree Hash、Domain Separation |
| MAC／PRF | MAC、PRF、Universal Hash、相關構造 |
| KDF／Password | Extract／Expand、Password Hashing、Memory-hard Function |
| Randomness | DRBG、Extractor、Sampler、熵來源模型；平台 CSPRNG Adapter |
| Key Agreement／KEM | DH／ECDH、KEM、Hybrid Combiners、後量子家族 |
| Public-key Encryption | PKE、Hybrid、Identity／Attribute／Functional Encryption |
| Signature | 一般、Aggregate、Blind、Ring、Group、Forward-secure、PQ 簽章 |
| Commitments／Authenticated Structures | Commitment、Polynomial Commitment、Accumulator、Merkle／Verkle 類結構 |
| VRF／VDF | 可驗證亂數、延遲函數、Time-lock 類構造 |
| Secret Sharing／Threshold | Sharing、DKG、Threshold Signing／Decryption |
| Zero Knowledge | Interactive Proof、Sigma、SNARK、STARK、IVC、Proof System |
| MPC／Privacy | OT、MPC、PSI、PIR、匿名憑證與相關原語 |
| Homomorphic | 部分、分層、全同態加密與 Bootstrapping |
| Constructions | Cipher Modes、AEAD、Sponge、Padding、Fiat–Shamir／FO 等轉換 |
| Protocols | PAKE、Secure Messaging、Key Establishment、Wallet Derivation、Token／OTP、PKI 等 |
| Cryptanalysis | 安全模型、攻擊前提、公開弱點、反例與歷史結果 |

規格不能混淆數學物件與演算法。例如 secp256k1 是曲線／參數，ECDSA／Schnorr 是簽章方案；SHA3-256 與 Keccak-256 也不能只當別名。AES-256-GCM 以明確邊連到 AES-256 與 GCM。

### 5.1 Metadata 維度

`kind`、`primary_function`、`family`、`parameters`、`construction`、`assumptions`、`standardization`、`publication_history`、`quantum_model`、`use_cases`、`known_findings`、`source_languages`、`platforms`、`maintenance`、`evidence_refs`。

安全性以帶範圍的 Finding 記錄，包含規格版本、參數、用途、攻擊者能力、資源／Query Bound、來源與日期。禁止只由 Key Bits 產生通用「安全分數」，或將所有演算法永久標為 Recommended。

## 6. 資料契約

### 6.1 通用要求

每個 Record 必須有 `schema_version`、穩定 `id`、來源、Owner／Maintainer 或明確無人負責狀態。ID 不嵌入容易變動的分類路徑、不重用；重新命名使用 Alias，刪除使用 Tombstone。

建議 ID 形態為 `abc:algorithm:sha-256`、`abc:implementation:sha256-abc-rust-portable`、`abc:spec:sha256-fips180-4-2015`。版本和 Artifact Hash 是獨立欄位，不能只靠檔名代表身份。

Validator 必須檢查 JSON Schema、跨 Record 引用、Unique ID、Path Traversal、Schema Upgrade、缺漏證據及語意限制。解析不可信 Metadata 時禁止執行任意程式、任意網路 `$ref`、YAML Object Constructor 或 Shell 字串。

### 6.2 核心契約欄位

| Contract | 必要資料 |
|---|---|
| Algorithm | ID、Kind、Function、Family、Variants、Parameter refs、Specification refs、Literature refs、用途與已知限制 |
| Specification | ID、規格版本、原始章節／Errata、Lean Module、公開命題、Domain、Input／Output Semantics、Preconditions、Reviewer |
| Implementation | ID、Algorithm／Spec refs、Source Origin、Revision／Digest、Path、Languages、Features、外部呼叫、Provider、Target Support、Maintainers、License |
| Module | ID、Owner Paths、原生 Manifest、觀察到的依賴來源、額外 Typed Edges、Tasks、Input／Output、Resource Budget |
| Binding | ID、Language／Runtime、包裝的實作／Provider、Encoding／Error／Ownership Contract、支援矩陣、Package Name |
| BuildTarget | Triple／OS／Arch／ABI、CPU Features、Compiler／Linker／Flags、Dependency Lock、Runtime、Dispatch Policy |
| EvidenceRequest | Subject、要證明／測試的 Claim、範圍、必要命題、工具鏈、Assumption Policy、輸出格式 |
| EvidenceResult | Subject Snapshot、Claim、State、Scope、Assumptions、TCB、命題／測試名稱、執行與產出 Digest、Verifier、時間與信任來源 |
| Policy | Profile ID／Version、用途、允許的 Suite／Parameters／Provider、Evidence Requirements、維護支援條件、例外與截止 |
| ReleaseSet | Source Commit、Packages／Versions、每個 Artifact Digest、核心／ABI 相容性、Evidence、SBOM、Provenance、Support Window |
| Literature／Standard | DOI／URL／版本／作者／出版資訊、章節、Errata、取得日期、授權、可重散布狀態、引用關係 |
| Advisory | 受影響實作／版本／Features／Targets、用途、風險、修補／緩解、證據、Disclosure 狀態、外部編號 |

四個先完成的 Schema 是 Algorithm、Implementation、Evidence、Dependency／Module。其餘在首次使用前完成，不要用未驗證的任意 JSON 擴充核心資料。

### 6.3 狀態值不能互相代替

Formal Claim 使用 `missing | in_progress | partial | proved | refuted | blocked | not_applicable`。Test Run 使用 `not_run | passed | failed | blocked`。Not Applicable 必須有理由與審查，不能用來避過 Gate。

`proved` 必須指向命題、範圍和版本；`passed` 必須指向真實測試結果。Evidence 的有效性由目前 Subject、Policy、TCB、工具鏈與支援範圍計算，可因來源變動或政策更新變成 Stale，不得手動填一個全域 `verified: true`。

正式 JSON Schemas 必須拒絕未知欄位，透過有版本的明確 Extension Namespace 擴充。所有 Example 必須經 Schema 與跨參照驗證；負例必須確認被拒絕。

## 7. 形式化驗證契約

### 7.1 分別追蹤的主張

`specification_fidelity`、`functional_correctness`、`implementation_refinement`、`memory_safety`、`panic_freedom`、`termination`、`cryptographic_security`、`constant_time`、`binary_correspondence`。

每個公開定理記錄全名、Quantifiers、Preconditions、Postconditions、排除行為、來源規格、實作 Snapshot、假設和 Trust Profile。若只能證明某個函式或某種輸入長度，展示其真實範圍。

對 SHA-256，符合位元組規格的功能正確性不是碰撞抗性的無條件證明。對歷史上已破解的演算法，可以證明正確實作、記錄反例，不能發明其不存在的安全定理。安全證明可以是明確假設與界限下的 Reduction；未知命題保持未知。

### 7.2 規格獨立性與忠實性

Spec 以固定版本標準或論文為依據，記錄對應章節、Errata、編碼、定義域與安全前提。需要獨立 Review 與可執行向量交叉檢查。把實作翻成 Lean 再命名為 Spec，不足以證明符合外部標準。

禁止為讓 Proof 通過而：縮小已承諾的定義域、加入不可成立的前提、把 theorem 改成無意義等式、從假設直接重述結論、移除必要的安全檢查。規格與 Claim 的實質改動必須有 ADR／Review 記錄。

### 7.3 Lean 信任政策

1. 以所固定 Lean 版本提供的機制，審查對外 Claim 的**傳遞性 Axiom Dependencies**；不能只有文字搜尋。
2. 正式證據拒絕直接或間接 `sorryAx`，拒絕未批准的自訂公理。
3. 預設明確允許 `propext`、`Classical.choice`、`Quot.sound` 等已列入政策的標準邏輯公理；允許清單有版本。
4. 密碼學假設優先成為 theorem hypotheses，附適用範圍，不藏入全域公理。
5. Native Evaluation 引入額外信任時，使用獨立 Profile，記錄具體公理、工具與版本；不能把 `native_decide` 的結果包裝成不依賴編譯器的 Kernel-only 證明。[R2]
6. 政策檢查結果、定理陳述摘要與來源 Digest 一起存證；最終發行 Gate 以可信工具重新檢查。
7. 未完成研究可以合併為明確隔離的 `research` 工作，但必須被 Production Gate 排除。失敗 Proof Fixtures 不得被正式產品 Import。
8. 對未審查 AI／外部貢獻，不能信任其自己輸出的成功訊息或 Axiom 清單；固定可信命題／定義，使用適用 Lean 版本的獨立重檢與 Comparator 路線驗證其確實證明預期命題。實作參考官方 Proof Validation 指南，並把 Checker 本身納入信任邊界。[R2]

### 7.4 Rust → Lean 路線

固定 Rust、Charon、Aeneas、Lean、Mathlib、額外 Library 的實際相容版本／Commit。M0 必須真實執行最小案例，不得使用假 Commit、`latest` 或臆測版本相容性。

記錄 Rust 來源、啟用 Features、目標、抽取選項、LLBC、生成 Lean、外部函式模型及其假設。生成模型必須可重新產生；任何人工後處理必須是版本化、可重現並受審查的 Transformation，不能直接手改生成模型來通過證明。

Aeneas 的支援範圍與限制以固定版本實驗及官方文件為準 [R1]。抽取模型中的證明不自動涵蓋 Rust Compiler、LLVM、FFI、整個 Runtime、任意 Unsafe 或最終機器碼。所有未證明連接保留在 TCB 與限制欄位。

### 7.5 非 Rust 實作

每個 C、C++、Go、Java、Assembly 等實作選擇適當語義、Translation／Refinement 或 Binary Verification 路線。現有 F*／Rocq／其他證據保留原 Proof System、版本和範圍；要達成 Lean 可檢查目標，另外建立可審查的連接或證明。

沒有合適工具時標示 `blocked`，建立最小重現與研究任務。不得把「重寫成容易驗證的 Rust」當作原 C／Assembly 實作已驗證。

### 7.6 常數時間與平台

指定公開／秘密輸入、控制流程及記憶體存取 Leakage Model、Compiler／Target、CPU Features、Dispatch 路徑。來源層沒有秘密分支，不代表所有平台沒有微架構洩漏。Timing Test 沒找到訊號也不是常數時間證明。

公開輸入用途的 Hash 與處理 Secret 的 HMAC／KDF 可以有不同要求，且繼承依賴必須重新評估。Production Profile 逐用途定義必要證據，不能以泛用 `not_applicable` 逃過審查。

## 8. 測試、Fuzz 與效能方法

### 8.1 所有可執行實作的最低測試資料

- 標準或獨立來源的 Known Answer Tests；來源版本、授權與 Digest 固定。[R3][R4]
- 邊界與錯誤行為：空輸入、最大允許長度、非法長度、Overflow、Encoding、狀態轉換。
- Streaming 與 One-shot 一致性、任意 Chunk 切分、Finalize 後行為、Reset／Clone（若支援）。
- 建立獨立來源 Differential 路線，揭露共同生成器或共用核心。尚無獨立 Oracle 時，以 `blocked` 加上 `reason: missing_oracle` 記錄原因與補足任務；不能複製同一實作充數。Catalog／Research 仍可收錄，正式發布依 Profile 的明確要求判定。
- 可持續執行的 Coverage-guided Fuzz Target 與最小化回歸 Corpus。
- 必要的 Sanitizer／Miri／Model Checking，以及平台／Compiler 相容性測試；各自只聲明真實涵蓋範圍。

Wycheproof 是已知攻擊與實作邊界的測試資源之一 [R4]，不是可取代所有演算法測試或形式化驗證的通用證明器。

### 8.2 Fuzz Target 契約

每個 Target 宣告實作、API Surface、Input Model、State Machine、Oracle、Seed／Corpus 版本、平台、Sanitizer、預算及停止條件。結果記錄實際執行時間、Executions、Coverage 指標種類、失敗／Timeout／OOM／Harness Error／未執行狀態。

預算耗盡只代表完成本次測試；不可推導「無漏洞」。Harness 必須有輸入敏感度／Mutation Sanity 檢查，避免忽略輸入、吞掉錯誤或永遠返回成功。

隨機化演算法可用受控測試亂數或語義性質比較；不得要求所有正確簽章／密文永遠 Bytes 相同。Mismatch 不能用多數決解決，應最小化反例並比對規格。

### 8.3 Binding 與 C ABI 測試

針對合法記憶體配置下的 Buffer 長度、重疊、Ownership、Double Finalize、整數轉換、Exception／Panic 邊界進行 Fuzz。C Caller Obligations 必須明寫，不能承諾在一般程序內安全驗證任意野指標。

### 8.4 效能與側通道環境

Benchmark 記錄硬體、OS、編譯器、Flags、CPU Governor／負載條件、輸入大小、分布、信賴區間與重現命令。共享 CI Runner 只用於粗略回歸；嚴謹排名與側通道量測使用已知且適合的環境。開啟 GPU、SIMD 或 Assembly 之前，需要有量測證明收益及維護成本的 ADR。

## 9. 模組依賴與增量驗證

### 9.1 三張圖

**Knowledge Graph** 可有循環，例如文獻引用、別名、歷史關係。**Evidence Graph** 記錄 Claim、Subject 與證據連接。**Task Graph** 是實際執行順序，必須為 DAG。

統一 Dependency 邊方向為 `consumer -> prerequisite`，變更沿反向邊找受影響消費者。`cites`／`alias_of` 不是自動觸發建置的邊。Typed Edges 至少包括 `imports`、`calls`、`implements`、`wraps`、`generated_from`、`tests`、`packages`、`constrained_by`。

### 9.2 依賴來源

Cargo Metadata／Lock、Lean Module Imports、建置 Script、Code Generator、`module.toml`、SDK 原生 Manifest、測試向量、Policy、Toolchain、Workflow、包裝設定與 Provider Dispatch 都必須被納入。

第一版以**模組／Import 級**增量，不承諾只重跑某一個 Lemma。Lean Attributes、Instances、Unfolding 與 Tactics 可能影響依賴；不能用定理名字文字搜尋代替真正的 Import 關係。

### 9.3 Planner 演算法契約

1. 解析明確 Base／Head；PR 預設使用正確 merge-base，Merge Queue 使用對應事件基準。
2. 同時取得 Base 和 Head 的 Ownership、Metadata 與依賴圖。
3. 以兩圖的聯集分析新增、刪除、改名、Feature／依賴邊變化。
4. 映射 Changed Paths 到節點，計算受影響閉包，依 Edge Type 決定必要任務。
5. 對每個必要 Task 展開工具鏈、平台、Features、信任政策與額外輸入。
6. 只有 Inputs 與 Trust Domain 完整匹配時才列為 Cache Candidate。
7. 產生可驗證的 `plan.json`、GitHub Matrix 及每個選取原因；不直接執行 Metadata 裡的 Shell 字串。
8. 聚合器核對預期 Task Set 與實際 Evidence，缺少必要任務即阻擋。

Base／Head 聯集只用來計算影響，不直接當作執行 DAG。實際執行圖由 Head 中仍存在的任務與依賴建立；刪除節點保留 Tombstone／原因，排程存續的消費者和刪除／相容性檢查。Base 與 Head 各自無循環、聯集有循環的合法重構，不應被誤判為執行循環。

Base 不存在、未知檔案、失效 Reference、無法可靠推導依賴時，保守擴大必要工作或明確失敗；**不得當作沒有變更**。任務 DAG 有循環時輸出 Cycle，不任意丟棄邊。

### 9.4 Planner 輸出

`planner_version`、`base_revision`、`head_revision`、`changed_paths`、`graph_digest`、`affected_nodes`、`selected_tasks`、`reason_paths`、`excluded_reason`、`cache_candidates`、`fallback_reason`、`required_gate`。

### 9.5 必須實測的行為

| 變更 | 預期 |
|---|---|
| SHA-256 Rust 實作 | SHA-256 及實際依賴的 HMAC／HKDF、Bindings／Consumers 被選取 |
| 無共用實作依賴的 SHA-3 葉節點 | 不重跑 SHA-256 的完整 Proof／Fuzz |
| 共用 Word／Bitvector Foundation | 依真實 Imports 重新選取兩邊相關 Proof |
| 文獻書目／純文字文件 | Metadata／文件工作；不觸發無關密碼學重驗 |
| C++ Wrapper | C++ API／Package Tests；若共用 ABI 未動，不重證無關核心 |
| 刪除／改名／移除依賴 | Base 與 Head 的受影響消費者都被處理 |
| Toolchain／Verifier／Policy | 對應證據與快取失效；不得沿用舊 Pass |
| 無法判定的檔案 | 明確擴大或阻擋，不能靜默跳過 |

## 10. 任務執行、快取與 CI 信任

### 10.1 內容定址

Task Fingerprint 包含：檔案 Path／Content、轉遞依賴、Spec／Theorem Snapshot、工具鏈 Binary／版本、Target、Flags、Features、Generator、Runner Image／Environment Definition、Verifier／Trust／Policy Config。

完整 Repo Commit 記錄於 Provenance，但不要單純以 Commit 作為唯一 Cache Key，否則每次無關變更都讓快取失效。反過來也不能只雜湊模組自己的檔案。

使用成熟的標準 Digest 實作來保護基礎設施，不以正在開發的 ABC Hash 核心作為唯一完整性根。Cache 是效能機制，Evidence 是可檢查的主張；兩者不同。

### 10.2 信任領域

外部 PR、受審查主分支、正式發行使用分離的 Trust Domain。未審查 PR 的 `.olean`、模型、Binary 或成功 JSON 不能直接提升為 Release Evidence。即使同一雜湊命中，也必須核對產生者與允許的信任鏈。

發行從固定且已審查來源、可信工具鏈重建本次發行依賴閉包，執行必要 Kernel／Evidence 檢查。無須每次發行都重跑 Atlas 中所有研究歷史項目，但不能漏掉打包進去的任何分支。

### 10.3 GitHub Actions 工作流

| Workflow | 工作範圍 |
|---|---|
| `pr-plan.yml` | 最低權限、驗證 Metadata、產生受影響工作與永遠執行的最終 Gate |
| `module-check.yml` | 可重用 Build／Proof／Test／Fuzz 工作；輸入經 Schema 驗證 |
| `main-assurance.yml` | 可信主分支較深測試與證據產生 |
| `scheduled-verify.yml` | 分批完整驗證已支援模組，偵測遺漏依賴與環境漂移 |
| `upstream-watch.yml` | 固定規則取得上游版本／公告；產生待審查更新 |
| `release-verify.yml` | 固定來源建置、必要完整驗證、Consumer Tests、SBOM、Provenance |
| `publish.yml` | 只發布核准的 Artifact Set，獨立權限；不重新編譯出另一批 Bytes |
| `docs.yml` | 由 canonical metadata 與有效證據產生版本化網站 |

以 Job-level 規劃取代跳過整個 Required Workflow 的粗略 `paths`。零重型任務時仍有真實 Metadata／Plan 驗收結果。子任務失敗、被取消、未執行或產物缺失，不得由總 Gate 假裝成功。

Planner、Verifier、Evidence Aggregator、Trust Policy 或 Required Task 規則被修改時，不能只信任候選 PR 自己產生的 Plan／Pass。保留受審查基準工具的檢查，另外執行候選工具的獨立正負 Fixture，並要求獨立 Review。正式 Gate 使用已核准版本，核對預期 Subject／Fingerprint／Task Set；候選工具不得自行放寬自己的驗收規則。

### 10.4 CI 安全與資源

- Actions 固定完整 Commit SHA，升級經 Review；第三方工具與容器固定版本／Digest。
- PR 程式、Lean Metaprogram、Build Script 都視為可執行的不可信程式；不能取得發布憑證。
- 不在具權限的 `pull_request_target` 流程 Checkout／Build 不可信 PR 程式碼。[R6]
- PR 標題、路徑、分支與 Registry 字串使用結構化參數；不插入 Shell 程式。
- 不使用含正式 Secrets 或可存取內網的長駐 Self-hosted Runner 執行未審查 PR。
- 配置工作預算、Timeout、Matrix 分片、並行上限、Artifact／Cache 保留與過時 Run 取消。
- 初期 PR Fuzz 可從受影響 Target 每個 60–180 秒開始，Nightly 從優先 Target 每個 10–30 分鐘開始；這是預算設定，不是安全保證。

公開 Repo 的 Standard GitHub-hosted Runner 有免費使用條件，也有執行、並行及其他限制；不視為無限或保證容量。[R5] OSS-Fuzz 需要符合資格與獲准，不能依賴第一天必定加入。[R7]

## 11. Runtime、API、Provider 與金鑰

### 11.1 API 層次

提供型別明確的 Primitive API 與用途導向的高階 API。Digest、MAC Key、AEAD Key、Signing Key、Verification Key、KEM Key 必須能區分。不要把所有能力壓成 `execute(algorithm_name, arbitrary_json)`。

預設依賴最小化，Raw／Research 能力顯式選取。可攜式核心優先同步、明確輸入輸出、可測試狀態機；IO、平台亂數、KMS 和 Async Adapter 在邊界外。

`no_std` 與 Embedded 是支援目標，不在未測試前聲稱全部演算法可用。Heap、Stack、最大輸入、Buffer 策略與錯誤行為需記錄。不可把「Rust」當成自動完成 Memory Safety／Side-channel 保證。

### 11.2 Provider 與 Dispatch

Provider 可對應 ABC Portable、上游原生庫、CPU 特化、WebCrypto、OS Crypto、KMS／HSM。每次能力選擇可查詢 `algorithm_id`、`suite_id`、`implementation_id`、`provider_id`、`build_digest`、`assurance_profile`。

功能選擇必須符合 Policy 與所支援參數；不得默默降級或退回沒有對應證據的 Backend。Dynamic Dispatch 各分支要有獨立測試／證據與可強制選取的測試模式。

為同一演算法換 Provider 可以維持 API，但金鑰、簽章、密文、Nonce 或錯誤語義仍可能不同，必須通過互通驗收。換演算法不是一般 Provider Patch；要有版本化 Suite 與遷移計畫。

### 11.3 Randomness 與 Nonce

每個部署環境使用適當的 OS／平台亂數入口，失敗就回報失敗。不得退回時間種子、普通 PRNG 或測試 Seed。瀏覽器 WASM、Node、WASI、行動裝置分別定義來源。

Deterministic Randomness 只用於隔離的測試，或標準明定的確定性演算法。測試控制不得意外啟用於 Production Profile。

AEAD API 必須明確分配 Nonce 生成／計數／持久化責任，定義每 Key 用量限制與故障恢復。核心加解密正確不會自動保證應用程式未重複 Nonce。

### 11.4 Keys、Secrets 與格式

Key Record 包含用途、Suite、來源、Provider Handle、可匯出性與生命週期。允許硬體／KMS 不匯出私鑰的操作，不為共用核心而強制匯出。

跨語言秘密資料要記錄複製、可變 Buffer、GC、清零及其不能保證的部分。避免把秘密當不可控的字串或記錄進 Logs。只有符合實際型別與 Runtime 的保證才能對外宣稱。

優先使用適用的既有格式。若確有 ABC Envelope 需求，先以 ADR／獨立規格定義 Version、Suite、AAD、Header Authentication、Length Limits、未知欄位和 Downgrade 規則，不能由 SDK 各自發明。

### 11.5 Policy 版本化

Policy ID／Version 獨立於 Package Version。`recommended` 必須解析到具體可追溯快照，不在使用者不知情下改變 Suite 或上傳網路設定。

區分「允許產生新的加密／簽章」與「為相容性讀取／驗證舊資料」。歷史資料遷移不是全域關閉所有舊格式，也不能無條件繼續建立新弱資料。正式 Profile 遇未知、無維護責任或必要證據缺失時拒絕使用。

## 12. SDK 與平台交付矩陣

以下核心 SDK 都是正式 Roadmap 交付，不能一直留在「未來可做」。每個 SDK 的能力和狀態以實際 Artifact 為準；前期可以只暴露已完成的 SHA-256，不得宣稱整套密碼學能力已可用。

| 生態 | 預設路線 | 真正交付物與最低驗收 |
|---|---|---|
| Rust | 原生 crate | `cargo package` 成品，在 Workspace 外 Consumer 編譯執行；MSRV／Features 有測試 |
| C | 版本化 C ABI | Header、Static／Shared Library、Link 範例、ABI 與所有權契約；實際 C Consumer |
| C++ | C ABI + RAII Wrapper | Header／Package Config、CMake Consumer、錯誤與生命週期；不得暴露 Rust 不穩定 Layout |
| npm | WASM + TypeScript；原生 Node Backend 經需求決策 | 真實 Tarball、瀏覽器與 Node Consumer、Types、載入／錯誤／Backend 身分測試 |
| PyPI | PyO3 與 Wheels／Source Distribution | 乾淨 Python 環境安裝、平台 Native Dependency 完整、Bytes／Errors／Lifetime 驗收 |
| Go | C ABI + cgo 首版，純 Go 若需要另建實作任務 | Go Module、外部 Consumer、建置／Link／平台說明；明確標示 cgo 需求 [R9] |
| Java | 先評估 JDK 基線；JNI 或適用 JDK 的 FFM | Maven／Gradle Artifact、外部 JVM Consumer、Native 載入、Lifecycle／Exceptions；Android 另列 |
| Swift | UniFFI 或平台 Binding | Swift Package／XCFramework、Simulator／Device 支援證據 |
| Kotlin／Android | UniFFI／JNI 等 | Android AAR／Gradle Consumer，真實 Android ABI 與 Runtime 驗收；不把 JVM 支援等同 Android |
| .NET | Native Interop | NuGet、Runtime Identifiers、Native Library Deployment、Consumer |
| WASI／Embedded | 目標專用 Adapter | 固定 Runtime／Target／Capability，驗證可用 API 與限制 |

工具選擇為候選實作路線，M0／相應 SDK Spike 後固定可用版本。[R10] C ABI 是一個出口，不強迫 PyO3、Node-API、WASM 都再繞同一層 C。

### 12.1 C ABI 必須先定義

Opaque Handles、Allocator／Deallocator、Buffer 長度與容量、Null／Alignment／Overlap 前提、整數範圍、錯誤碼、ABI Version、Thread Safety、Callback 與 Panic／Exception 邊界。Caller Obligations 與 Binding 自身的責任要分開。[R8]

### 12.2 共同行為契約

各語言遵循自身 API 命名慣例，但 Bytes、Endian、Encoding、Empty Input、長度上限、Streaming、Finalize／Reset、錯誤分類、金鑰用途及 Provider Discovery 有一致語意。

Fuzz／測試核心、Binding、平台成品各自執行。使用同一個 Rust 核心的 SDK 可以重用適用的核心證明，但不能宣稱整個 SDK／FFI／WASM Runtime 自動被 Lean 證明。

### 12.3 平台支援採逐項宣告

初始實作及 Proof 以 Linux x86-64 為主，另在 WASM Browser／Node 完成最小交付。正式 Native SDK 再逐項加入 Linux aarch64、macOS、Windows，記錄 `supported | experimental | planned | unsupported`。

Cross Compilation 成功不等於在 Target 執行過測試。模擬、真實硬體、純編譯三種證據分開。Native 包裝要考慮 libc／最低 OS、CPU Features 與 Runtime 版本，不能只列 OS 名稱。

## 13. 文件、文獻與 Explorer

### 13.1 每個項目必備內容

簡介、穩定 ID、分類、年代／版本、原始來源、數學定義、參數、假設、有效用途、已知攻擊、各實作、維護者、支援矩陣、精確證據範圍、最小使用範例、相容性與遷移、參考資料、Changelog。

API 文件與範例需可執行，引用實際 Package Artifact；不要出現不存在的功能。Explorer 顯示 `catalogued / implemented / proof-covered / maintained / production-approved` 等獨立數量及其計算口徑。

證據頁可以追到 theorem、Source Snapshot、工具鏈、TCB、完整執行命令及 Artifact Digest。不存在、Stale 或被撤回的證據不能繼續顯示有效綠色標章。

### 13.2 文獻權利與引用

先收錄書目、DOI／URL、章節、版本與自撰摘要。只有確認可再分發的全文、標準與圖表才能放進 Repo；公開可讀不代表可任意重散布。來源程式碼與 Test Vector 各自保留其 License／NOTICE／Revision。

Discovery 可涵蓋 NIST、IETF、IACR、競賽檔案、eBACS、既有開源專案及歷史文獻。Importer 需支援去重、Alias、Version／Errata、Rate Limit、重試、來源快照與人工審查。不允許 AI 自行補造不存在的文獻或安全結果。

### 13.3 文件建置

靜態站從 Registry、版本化 API Reference 和可信 Evidence Index 生成。GitHub Pages 或其他純靜態 Hosting 足以啟動；搜尋索引預先生成。網站不成為必需的 Runtime 網路依賴。

## 14. 版本、相容性與上游維護

### 14.1 三個第三方責任等級

| 等級 | ABC 的責任 |
|---|---|
| `catalog_only` | 來源索引與狀態；不承諾代修上游 |
| `integrated_upstream` | 固定版本整合、相容性／公告追蹤；清楚揭露上游支援限制 |
| `abc_maintained` | 有實際 Owner 與 Backup、修補、Backport、支援期限與替代方案 |

沒有 Maintainer 的項目不能仍標成具持續維護承諾。必要修補可在單 Repo 保存合法來源快照與 Patch Queue，定期回饋上游；對外送 PR／通報須依當時授權。

### 14.2 發行與相容性

模組／SDK 可有獨立 SemVer；不要求所有套件每次同時發版。每次建立 `release-set`，對齊 Source、Core／ABI、Package Version、Target、Features、Evidence 和支援範圍。

資料格式版本、Suite 版本、Policy 版本、ABI 版本與 SDK 版本分開。Security Patch 預設不任意改 Public API、ABI、MSRV／JDK／Python 基線或既有資料格式；必要變動附原因與可執行遷移流程。

建立外部 Consumer Fixtures 與舊版 Artifact：舊版產生新版讀取、跨語言互通、Provider 替換、支援版本建置、Backport 與移除不安全依賴皆需演練。

### 14.3 漏洞與 CI

Advisory 映射到實作、版本、Features、平台與 ReleaseSet。Scanner Finding 先確認可達性／用途與修補路徑；不能為了 CI 變綠而全域忽略。必要例外具有具體範圍、Owner、理由、補償措施、到期日與再審查。

上游停更演練至少涵蓋：受影響產品查詢、維持既有格式的修補、受支援分支 Backport、替代 Provider 互通、Migration Guide、Advisory 與 Regression Tests。

## 15. 發布與供應鏈

正式發行需有來源審查、固定工具鏈、乾淨建置、所選 Package Closure 的驗證、Consumer Tests、SBOM、來源／建置 Provenance、Artifact Digest、簽章／Attestation、Changelog、Support Window。

發布流程只能上傳已審查的同一批 Bytes；不能在 Publish Job 重新建置不可比對的結果。Registry 憑證僅授予獨立發布步驟，優先評估各生態當時可用的短期權限／Trusted Publishing。

可重現性區分：來源重建相同語義、Unsigned Artifact Bytes 可重現、簽章後成品差異。Timestamp／平台簽章等差異記錄正規化方式，不宣稱未達到的 Bit-for-bit 保證。

SLSA／OpenSSF 用於供應鏈與專案管理控制的對照。[R11] 它們、SBOM 或簽章都不代表演算法安全或軟體無漏洞。內部 Release Verification 不是正式 ISO／FIPS 認證。

### 15.1 Research 與 Production Gate

Research／Preview 可公開明確未完成的成果，但不能預設用於 Production。Production Profile 要同時滿足：用途允許、維護責任存在、必要規格與實作證據有效、適用側通道要求、Binding／Target 驗收、安全審查、供應鏈、相容性及支援公告。

由有能力的獨立 Reviewer 審查聲明範圍；Agent 不能替代自己核發「Industry Audited」。缺少人員、報告或權限時完成所有可完成準備，保持 Production Gate 關閉。

## 16. 治理與長期持續性

起初由 Super Solution 發起；Orbbit、SupWallet 是需求與測試使用者。逐步吸收不具關聯的工程師、企業與研究者，不宣稱三間相關公司等同獨立產業驗證。

建立真實 Maintainers／Backup、CODEOWNERS、技術 RFC、Security Disclosure、Release Role、利益衝突與撤銷權限流程。不要捏造 Reviewer、聯絡信箱、基金會法律實體或贊助者。

每個已發布系列公布確切支援範圍與 EOL 政策；未有實際資源前，不承諾五年 LTS、永久安全更新或 24/7 SLA。[R11] 安全修補與公開證據不以商業顧問合約為取得前提。

專案成功指標：可獨立安裝 SDK、維護中模組數、精確 Proof Coverage、真實 Fuzz Target、可重現成品、缺失修補與遷移時間、外部 Consumer 回歸、不同組織的實際維護貢獻。數量不能取代安全 Gate。

## 17. 分階段執行與完成門檻

本計畫不以「幾週完成幾百份證明」作承諾。工具鏈、證明開發、外部審查與實際維護人力未實測前，日期不是驗收依據。完整範圍保留，進度逐件記錄。

| 里程碑 | 核心成果 | 完成條件 |
|---|---|---|
| **M0：實際可用的基礎** | Repo 盤點、最小骨架、固定工具鏈實驗、信任與來源政策 | 真實 Rust → 模型 → Lean 小案例；具體版本與命令可重現；不能只安裝工具 |
| **M1：模組化驗證工程** | Schemas、Registry、依賴蒐集、Impact Planner、Runner、Cache／Evidence、CI、教學 Probe | 正向與負向驗收全通過；故意錯誤確實阻擋；無關模組確實不重跑 |
| **M2：第一個真實完整案例** | SHA-256 規格／Rust／指定完整功能 Refinement、Fuzz、Rust＋npm/WASM；HMAC／HKDF 與獨立 SHA-3 控制模組 | SHA-256 指定功能範圍的證明完成；外部 Consumer 可安裝；依賴變更實測；不宣稱碰撞抗性已證明 |
| **M3：指定 SDK 完整交付** | C、C++、Go、Java、npm、PyPI、Rust | 七個生態都有可安裝 Artifact、範例、支援矩陣及跨語言 Conformance；不是空殼 |
| **M4：可信發行與維護** | Release Gate、Supply Chain、相容性、上游停更演練、治理 | 所支援用途的完整發行閉包證據；有真實 Review／維護責任；缺少外部審查時不冒稱 Production |
| **M5：用途與實作擴充** | AEAD、KDF、簽章、錢包需求、非 Rust、Swift／Kotlin／.NET／WASI、PQC／Advanced、研究自動化 | 每新增項目走相同規格；每個子任務有自己的證據與完成狀態 |

### 17.1 M0 小案例與 M2 不得混淆

先用一個容易完整檢查的 Byte／Word Round-trip 或受限算術性質跑通工具鏈。這個 Probe 只驗證工程方法，必須放在明確隔離位置，不能計入 Production 密碼學演算法數。

SHA-256 Spec 以固定版本 FIPS 180-4 與其 Errata 為來源 [R3]，定義 Endian、Padding、有效長度、計數器溢位與 Streaming 語意。KAT／Fuzz 涵蓋空輸入，以及 55、56、63、64、65、119、120 Bytes 等填補邊界。

Refinement 涵蓋承諾 API 與有效輸入域；不能把測試向量或 Compression Function 的局部證明稱作完整 Hash API 已證明。以 Input Domain 和定理明確區分局部／完整成果。

HMAC-SHA256 與 HKDF-SHA256 作為真實依賴鏈；HKDF 的長度與 Extract／Expand 規則按固定 RFC 5869 及 Errata 驗收 [R12]。SHA-3 控制模組以實際獨立程式／測試建立無關變更案例，不偽造其 Proof 狀態。

### 17.2 允許平行，不降低門檻

SHA-256 證明暫時卡住時，可以先完成標明 Research 狀態的 SDK、Fuzz、Schema 或 Planner。M2 不因此被標成完成，Production Gate 保持關閉。每個 Milestone 的依賴門檻與每個任務可開工的條件分開。

M5 的演算法家族是持續工作；以每個 Module／Implementation 建立子任務，不使用一個「所有 PQC 完成」的大標籤掩蓋實際缺口。

Release Gate 的工程完成和某個正式發行獲准是兩件事。ABC-030 可以在 Gate 已真實實作、能攔下缺少獨立 Review 的候選版本並產生完整待審查成品時完成；實際 Production Approval 另記於 ReleaseSet，條件未滿仍阻擋。缺少外部 Reviewer 不應使後續維護與治理工程全部卡死。

## 18. CLI 與工作介面

以下是**待實作介面規格**，並非已存在的可用指令。Agent 先提供 `abc --help` 和最少必要 Subcommands，再逐步擴充；不可以只印出成功文字。

```bash
abc doctor --json
abc registry validate --strict
abc graph build --revision HEAD --output .abc/graph.json
abc plan --base BASE --head HEAD --output .abc/plan.json
abc run --plan .abc/plan.json
abc formal extract --implementation sha256-abc-rust-portable
abc formal check --implementation sha256-abc-rust-portable
abc formal audit --implementation sha256-abc-rust-portable
abc test --implementation sha256-abc-rust-portable
abc fuzz --implementation sha256-abc-rust-portable --budget 120s
abc evidence verify --release-set .abc/release-set.json
abc package --sdk rust --output dist/
abc consumer-test --sdk rust --artifact dist/ARTIFACT
abc docs build
abc release prepare --profile research --output dist/
abc release verify --manifest dist/release-set.json
```

所有命令：結構化 JSON 輸出選項、穩定 Exit Semantics、合理超時、對缺少工具／缺少證據回傳明確非成功狀態、不得記錄 Secrets。`plan`／`validate` 預設不產生外部副作用。

Root CLI 調用原生工具，密碼學 Library 不依賴 CLI。M0 可以從 Rust `xtask` 實作薄入口，之後包裝成 `abc`；不得因此寫第二套 Build System。Task Command 使用程式與參數陣列，不能接收任意未驗證 Shell。

## 19. Agent 工作流程與交接

### 19.1 開始前

讀取使用者指示、現有 `AGENTS.md`、Repo 狀態與 License。存在 Repo 就在原 Repo 做；沒有才在使用者指定工作區建立本地專案。不要覆蓋未知未提交工作，不把本套件當成已授權的遠端發行。

先將本計畫放在 `docs/plan/`，初始化狀態，完成 ABC-001；隨任務補必要目錄。若有現有架構差異，以 ADR 記錄具體映射，不能為配合計畫重建已工作的所有內容。

### 19.2 平行分工

主 Agent 負責資料契約、整合及最終 Gate。可平行分配 Registry／Docs、Lean／Proof、Rust／Runtime、Impact／CI、SDK／Packaging、安全 Review。共享 Schema／ABI／Policy 指定單一 Owner；其他 Agent 提出變更，避免互相改壞。

先固定跨組 Contract 和驗收，再平行實作。長任務保留 Checkpoint、來源 Digest、命令、失敗輸入與下一步，支援換 Agent 接續。

### 19.3 任務完成規則

每個任務包含：ID、Milestone、Dependencies、Deliverables、Acceptance、Status、Owner、Evidence、Blockers。狀態使用 `not_started | ready | in_progress | blocked | in_review | done`；取消需要有實際需求變更理由。

`done` 必須有真實輸出與驗收證據。工具未安裝、測試未執行、Stub Verifier、Hard-coded Pass、空 SDK、借用別的版本證明，都不能算完成。

Agent 每完成一個工作批次，更新 `docs/status/progress.md`、任務狀態、ADR、重現命令與阻塞。回報必須包含：完成／未完成、實際測試、失敗原因、證據路徑、下一個可執行任務。

### 19.4 決策與授權

已授權的本地讀取、編輯、建置、測試、文件、可逆重構持續執行。一般實作選擇不反覆詢問使用者。

公開 Repo／套件發布、遠端 Push、付款資源、對外聯繫與安全通報，依當時對話的實際授權及環境規則處理；若已有授權，不新增重複確認。本計畫本身不是這些外部操作的授權。缺少授權時先完成本地打包、Dry Run、Consumer Tests 與可審查成品。

工具或網路受阻時保存具體錯誤和最小重現，不繞過存取限制，不假裝已執行。繼續不受阻的任務。

## 20. 第一次工作批次的具體交付

Agent 必須先交付以下可執行成果：

1. 現況與需求盤點，確認單一 Repo 和完整 SDK 範圍。
2. 可重現的 Lean／Rust／Charon／Aeneas 版本組合與最小實驗，或具體工具阻塞。
3. 核心 JSON Schemas、正負 Fixture 與跨參照 Validator。
4. Typed Graph、Base／Head Impact Planner、Reason Trace 和負向案例。
5. 有信任區分的 Task Runner／Cache／Evidence，以及 CI 最終 Gate。
6. 一個完整小型 Probe，真實 Proof／Fuzz／錯誤注入都可重跑。
7. 自動產生的最小狀態文件，真實顯示完成與未完成。
8. M2 的 SHA-256 Spec／實作／證明工作計畫已拆成可執行任務，並立即接續不受阻部分。

第一批完成不代表 ABC 已經可以保護產品資產。真正密碼學與指定 SDK 的後續 Gate 必須保留；Agent 不得用教學案例取代永久目標。

## 21. 完整驗收清單

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

## 22. 未確定事項與處理方式

| 未確定事項 | Agent 必須如何處理 |
|---|---|
| Toolchain 相容版本 | M0 實驗、固定 Commit、保存成功命令或最小失敗 |
| SHA-256 完整 Refinement 工作量 | 逐 Lemma／模組記錄；不保證日曆工期；SDK 可平行 Research 交付 |
| 非 Rust 到 Lean 的工具成熟度 | 每個實作獨立技術評估，保留上游證據與缺口 |
| Registry／Package 名稱與發布權 | 本地可先打包；發布前查真實可用性與授權 |
| 實際平台／硬體資源 | 明列 Tested／Compile-only／Planned，不能用 Cross Compile 冒稱實測 |
| 外部審核與維護人員 | 完成本地 Evidence Bundle；沒有審查人就保持對應 Gate 未完成 |
| 多年維護經費 | 先公布有能力履行的支援政策，不預售不存在的保證 |
| 過大 Repo／CI 成本 | 量測 Artifact 體積、任務次數與耗時，調整分片／快取／資料留存；不降低驗證聲明要求 |

所有 Schema、CLI、工具鏈與邊界的變更都要有 Migration 或 ADR，不能為了某個測試通過任意修改全域契約。

## 23. 一次性成本與持續執行預算

初期目標是無常駐付費伺服器。GitHub 原始碼、合資格 CI、靜態文件及現有開發環境足以開始；不因此宣稱全部研究、AI、審核、硬體與 Artifact 儲存永久免費。

各 Task 記錄 Wall Time、CPU／Memory、Cache Hit、Artifact Size 和失敗原因。Proof Discovery 與已完成 Proof 的 Checking 分開計算。先量測第一個真實模組，再決定長期預算與排程。

依合理開源測試需求安排 CI，保留可在本地或合法替代 Runner 執行的同一 CLI。不要為擴大免費容量建立規避限制的帳號／Repo。

## 24. 來源與決策的區分

架構、名稱、Milestone、任務與時間預算是本計畫的工程決策。下列 Primary Sources 支撐工具行為、標準與平台限制，讀取基準日為 2026-11-28；開工時應核對並鎖定實際使用版本。沒有以過往對話中的成本、版本或能力敘述作為驗收證據。

- **[R1] Aeneas 官方**：https://github.com/AeneasVerif/aeneas · https://aeneasverif.github.io/projects/ 。用途：Rust／Lean 路線、子集、工具鏈與限制。
- **[R2] Lean 官方**：https://lean-lang.org/doc/reference/latest/ValidatingProofs/ · https://lean-lang.org/doc/reference/latest/Axioms/ 。用途：公理、Native Trust、可信命題與獨立重檢。
- **[R3] NIST FIPS 180-4**：https://csrc.nist.gov/pubs/fips/180-4/upd1/final 。用途：SHA-256 規格來源；實作固定版次並追蹤修訂。
- **[R4] Project Wycheproof**：https://github.com/C2SP/wycheproof 。用途：來源明確的對抗測試資料。
- **[R5] GitHub Actions 計費與限制**：https://docs.github.com/en/actions/concepts/billing-and-usage · https://docs.github.com/en/actions/reference/limits 。用途：免費條件與執行限制。
- **[R6] GitHub Actions 安全**：https://docs.github.com/en/actions/reference/security/secure-use · https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target 。用途：權限、PR、Cache 與 Injection 邊界。
- **[R7] OSS-Fuzz**：https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/ 。用途：資格與整合流程。
- **[R8] Rust FFI**：https://doc.rust-lang.org/nomicon/ffi.html 。用途：ABI、Pointer、Ownership、Panic／Unwind 邊界。
- **[R9] Go cgo**：https://pkg.go.dev/cmd/cgo 。用途：Go Native Interop 與建置條件。
- **[R10] Binding 工具**：https://wasm-bindgen.github.io/wasm-bindgen/ · https://napi.rs/docs/introduction/getting-started · https://pyo3.rs/main/index.html · https://mozilla.github.io/uniffi-rs/next/ 。用途：工具候選的實際能力；不是每個平台已完成的保證。
- **[R11] 供應鏈與維護控制**：https://slsa.dev/spec/ · https://baseline.openssf.org/ 。用途：Provenance、支援與安全控制；不是密碼學認證。
- **[R12] RFC 5869**：https://www.rfc-editor.org/info/rfc5869/ 。用途：HKDF 規格及其資料。
- **[R13] 平台亂數**：https://docs.rs/getrandom/latest/getrandom/ 。用途：WASM／WASI 等 Target 的來源差異；實際版本由 SDK Spike 固定。

## 25. 任務清單與啟動方式

後附為本計畫的具體任務拆分；機器可讀版本位於 `TASKS.json`。它是要實作的 Backlog，不是已完成證據。以 Dependencies 和實際阻塞決定順序，並保留使用者要求的完整範圍。

建議 Agent 啟動順序：ABC-001 → ABC-002，並行 ABC-003／ABC-004；接著 ABC-005 至 ABC-013 建立 M1；再推進 SHA-256 與 SDK。其餘任務按真實依賴平行執行。不要因目前沒有公開發布權而停止本地工程。

<!-- GENERATED_TASK_APPENDIX_START -->

### 25.1 Agent Task Backlog

The identifiers and task contracts below are English to be copied directly into the repository task board. All tasks start as `not_started`.

#### ABC-001 · M0 · Repository and scope audit

**Dependencies:** None  
**Owner role:** integration

**Deliverables**
- Repository inventory
- Scope and instruction decision record

**Acceptance**
- Preserve existing instructions, license, source, and uncommitted work.
- Record all seven required SDK ecosystems and the complete historical catalog scope.
- Identify actual repository ownership, available tools, and access blockers without inventing them.

#### ABC-002 · M0 · Minimal working monorepo and task state

**Dependencies:** ABC-001  
**Owner role:** integration

**Deliverables**
- Minimal workspace manifests
- Root command entry
- Task and progress records

**Acceptance**
- A documented root command executes real behavior.
- Keep one first-party repository and create only directories needed by working modules.
- Track incomplete work explicitly; empty packages are not deliverables.

#### ABC-003 · M0 · Pinned Rust-to-Lean toolchain spike

**Dependencies:** ABC-002  
**Owner role:** formal

**Deliverables**
- Toolchain lock and compatibility ADR
- Small extraction and proof reproduction
- Unsupported-feature notes

**Acceptance**
- Execute Rust to Charon to Aeneas to Lean with actual compatible versions or commits.
- Save commands, source/model digests, and real checker output.
- If unsupported, retain a minimal reproducer and mark the task blocked rather than substituting a mock.

#### ABC-004 · M0 · Trust, source rights, and CI threat policy

**Dependencies:** ABC-001  
**Owner role:** security

**Deliverables**
- Proof trust policy
- Source and literature rights policy
- CI threat model

**Acceptance**
- Define allowed axioms, native trust, theorem scope, external models, and compiler boundaries.
- Distinguish upstream maintenance responsibility from catalog inclusion.
- Separate untrusted code execution from release credentials and reviewed decision tools.

#### ABC-005 · M1 · Versioned registry and evidence contracts

**Dependencies:** ABC-002, ABC-004  
**Owner role:** registry

**Deliverables**
- JSON Schemas
- Semantic and reference validator
- Positive and negative fixtures

**Acceptance**
- Represent algorithms, parameters, specifications, implementations, modules/tasks, bindings, targets, evidence, and releases.
- Reject duplicate IDs, invalid references, unknown fields, unsafe paths, and malformed schema versions.
- Keep catalog, maintenance, evidence, and production policy states independent.

#### ABC-006 · M1 · Initial taxonomy and source-backed catalog

**Dependencies:** ABC-005  
**Owner role:** registry

**Deliverables**
- Taxonomy
- Representative historical and modern entries
- Literature and standards records

**Acceptance**
- Include historical, broken, standardized, and experimental examples with traceable sources.
- Separate mathematical parameters from algorithms, constructions, and protocols.
- Mark all unavailable implementations and proofs honestly; redistribute only permitted content.

#### ABC-007 · M1 · Module ownership and dependency extraction

**Dependencies:** ABC-005  
**Owner role:** automation

**Deliverables**
- Module manifest contract
- Cargo and Lean dependency adapters
- Ownership diagnostics

**Acceptance**
- Map files, native manifests, imports, generators, vectors, policies, toolchains, and features to module inputs.
- Detect missing ownership and invalid or undeclared inputs.
- Use actual module/import granularity and document any conservative dependency approximation.

#### ABC-008 · M1 · Typed graphs and executable task DAG

**Dependencies:** ABC-007  
**Owner role:** automation

**Deliverables**
- Knowledge and evidence graph views
- Task DAG projection
- Cycle diagnostics

**Acceptance**
- Use consumer-to-prerequisite dependency direction consistently.
- Allow non-execution relation cycles while rejecting cycles in the actual executable graph.
- Generate deterministic graphs and explain edge provenance.

#### ABC-009 · M1 · Base-head incremental impact planner

**Dependencies:** ABC-008  
**Owner role:** automation

**Deliverables**
- Plan generator
- Reason traces
- Change and refactoring fixtures

**Acceptance**
- Analyze both base and head for removals, renames, changed edges, features, and tool inputs.
- Use their union only for impact, and execute surviving head tasks with deletion compatibility checks.
- Unknown inputs or missing base cause conservative work or failure, never silent empty success.

#### ABC-010 · M1 · Task runner, cache, and evidence verification

**Dependencies:** ABC-004, ABC-008  
**Owner role:** automation

**Deliverables**
- Structured task runner
- Content-addressed cache
- Evidence result verifier

**Acceptance**
- Fingerprints cover transitive sources, models, tools, flags, target, policy, verifier, and trust domain.
- Reject stale, forged, missing, or mismatched evidence and untrusted release promotions.
- Distinguish execution failure, timeout, cancellation, not-run, and successful work.

#### ABC-011 · M1 · Modular GitHub Actions and final gate

**Dependencies:** ABC-009, ABC-010  
**Owner role:** automation

**Deliverables**
- Plan and reusable module workflows
- Stable final status gate
- Untrusted-PR security fixtures

**Acceptance**
- Validate dynamic matrices and compare expected tasks with all actual results.
- Pin actions and separate PR, main, and release permissions and trust domains.
- Candidate planner/verifier changes are checked using approved baseline rules and independent fixtures.

#### ABC-012 · M1 · Complete isolated proof and fuzz probe

**Dependencies:** ABC-003, ABC-004, ABC-005, ABC-010, ABC-011  
**Owner role:** formal

**Deliverables**
- Small non-production arithmetic or byte probe
- Real proof and fuzz evidence
- Adversarial verification fixtures

**Acceptance**
- Run specification, implementation, extraction, proof, tests, fuzz, and evidence end to end.
- Reject hidden axioms, changed theorem statements, stale models, forged pass output, and contaminated cache.
- Clearly label the probe as infrastructure validation, not production cryptography.

#### ABC-013 · M1 · Generated documentation and milestone report

**Dependencies:** ABC-006, ABC-009, ABC-012  
**Owner role:** documentation

**Deliverables**
- Minimal static explorer
- Generated status pages
- M1 acceptance report

**Acceptance**
- Generate identities and status from canonical records and verified evidence.
- Show theorem scope, limitations, TCB, and actual incomplete states.
- Removing or invalidating evidence removes the corresponding valid status.

#### ABC-014 · M2 · Independent SHA-256 specification

**Dependencies:** ABC-003, ABC-005, ABC-006  
**Owner role:** formal

**Deliverables**
- Lean SHA-256 specification
- Standard mapping and claim inventory
- Executable specification tests

**Acceptance**
- Pin the standard and relevant errata and define endianness, padding, length, and streaming semantics.
- Keep the specification independent from the Rust implementation being verified.
- Document exact theorems and input domains before claiming full implementation correctness.

#### ABC-015 · M2 · Portable SHA-256 Rust implementation

**Dependencies:** ABC-003, ABC-014  
**Owner role:** runtime

**Deliverables**
- Portable crate implementation
- Streaming API
- Boundary and known-answer tests

**Acceptance**
- Use the verified toolchain subset and avoid unplanned SIMD, assembly, or unsafe code.
- Pass source-traceable vectors, empty inputs, padding boundaries, chunking, and overflow behavior.
- Do not derive the only oracle from the same implementation or generator.

#### ABC-016 · M2 · SHA-256 implementation refinement

**Dependencies:** ABC-004, ABC-014, ABC-015  
**Owner role:** formal

**Deliverables**
- Regenerable extracted model
- Named refinement theorems
- Axiom and trusted-statement checks

**Acceptance**
- Prove the promised API behavior over the declared valid input domain against the independent specification.
- Bind proof to exact source, model, target/features, tools, assumptions, and excluded behavior.
- Keep incomplete proofs blocked or partial; do not claim collision resistance, constant time, or binary proof from functional correctness.

#### ABC-017 · M2 · SHA-256 differential and fuzz suite

**Dependencies:** ABC-011, ABC-015  
**Owner role:** testing

**Deliverables**
- Independent comparison adapter
- Stateful fuzz targets
- Minimized regression corpus

**Acceptance**
- Test boundary lengths and streaming operation sequences with meaningful input-sensitive harnesses.
- Record actual oracle lineage, budgets, coverage type, failures, and target.
- A deliberately faulty implementation or disabled harness is detected.

#### ABC-018 · M2 · Common runtime and SDK behavior contract

**Dependencies:** ABC-005, ABC-015  
**Owner role:** runtime

**Deliverables**
- Typed API and capability contract
- Provider identity interface
- Error, ownership, RNG, and format specifications

**Acceptance**
- Define bytes, lengths, errors, streaming states, thread guarantees, and observable implementation identity.
- Do not expose or advertise cryptographic operations that are not implemented.
- Reserve explicit boundaries for platform randomness, non-exportable keys, and versioned policies.

#### ABC-019 · M2 · Packaged Rust SDK and external consumer

**Dependencies:** ABC-015, ABC-017, ABC-018  
**Owner role:** sdk

**Deliverables**
- Installable source package
- External consumer fixture
- Feature and toolchain support table

**Acceptance**
- Install and run from the packaged artifact outside the workspace.
- Validate included files, locked dependencies, features, and example behavior.
- Keep research status until all applicable proof and production gates are satisfied.

#### ABC-020 · M2 · npm TypeScript and WASM SDK

**Dependencies:** ABC-019  
**Owner role:** sdk

**Deliverables**
- npm tarball with WASM and types
- Browser and Node consumers
- Binding and artifact evidence

**Acceptance**
- Run actual consumers in declared browser and Node environments.
- Validate loading, binary conversion, initialization, streaming, and errors.
- Distinguish core proof coverage from binding tests and WASM runtime assumptions.

#### ABC-021 · M2 · HMAC and HKDF dependency modules

**Dependencies:** ABC-014, ABC-015, ABC-018  
**Owner role:** formal-runtime

**Deliverables**
- HMAC-SHA256 and HKDF-SHA256 modules
- Separate specifications and evidence targets
- Real dependency propagation fixtures

**Acceptance**
- Implement source-backed vectors, key and output-length boundaries, and actual SHA-256 dependencies.
- Maintain separate functional and security claims; complete the selected functional refinement claims before this task is done.
- A SHA-256 implementation change schedules both dependent modules without inventing graph edges.

#### ABC-022 · M2 · Independent SHA-3 control module

**Dependencies:** ABC-005, ABC-007, ABC-011  
**Owner role:** runtime-testing

**Deliverables**
- Real SHA-3 module or fixed upstream integration
- Source and evidence records
- Incremental isolation fixtures

**Acceptance**
- Distinguish SHA3-256 from Keccak-256 and preserve actual source/proof status.
- A SHA-256 leaf change does not schedule unrelated SHA-3 work.
- A genuinely shared imported foundation change schedules both applicable closures.

#### ABC-023 · M3 · Versioned C ABI and C package

**Dependencies:** ABC-018, ABC-019  
**Owner role:** sdk

**Deliverables**
- C header and native artifacts
- ABI and caller-obligation specification
- External C consumer

**Acceptance**
- Specify handles, allocation, buffers, integer conversions, errors, thread behavior, and panic boundaries.
- Link and run the packaged library from a separate C project on declared targets.
- Fuzz valid-memory boundary cases and establish ABI baselines without claiming arbitrary invalid-pointer safety.

#### ABC-024 · M3 · C++ SDK and packaging

**Dependencies:** ABC-023  
**Owner role:** sdk

**Deliverables**
- RAII wrapper
- CMake package configuration
- External C++ consumer

**Acceptance**
- Install and use the actual package from a clean C++ build.
- Validate object lifetime, errors, move/copy policy, and streaming semantics.
- Depend on the versioned C ABI rather than exposing Rust internal layout.

#### ABC-025 · M3 · Python package and wheels

**Dependencies:** ABC-018, ABC-019  
**Owner role:** sdk

**Deliverables**
- PyO3 binding
- Wheel and source distribution
- External Python consumers

**Acceptance**
- Install artifacts in clean environments for each declared supported Python/platform combination.
- Validate byte conversion, error mapping, object lifetime, and bundled native dependencies.
- Record binding evidence independently and mark untested targets planned.

#### ABC-026 · M3 · Node native-backend decision and delivery

**Dependencies:** ABC-019, ABC-020  
**Owner role:** sdk

**Deliverables**
- Measured backend-selection ADR
- Node-API package if selected
- Runtime backend identity tests

**Acceptance**
- Choose WASM-only or an additional native backend using actual integration needs and measurements.
- If native is selected, package and test it; otherwise record the decision without claiming a native implementation exists.
- Any backend selection is observable, policy-constrained, and behaviorally tested.

#### ABC-027 · M3 · Go SDK and deployment contract

**Dependencies:** ABC-023  
**Owner role:** sdk

**Deliverables**
- Go module
- cgo or explicitly selected native route
- External Go consumer

**Acceptance**
- Build, link, test, and run a consumer using packaged native artifacts.
- Document cgo, compiler, linker, OS, and architecture requirements.
- Do not advertise pure Go unless an independently tracked pure Go implementation is actually delivered.

#### ABC-028 · M3 · Java SDK and JVM distribution

**Dependencies:** ABC-023  
**Owner role:** sdk

**Deliverables**
- JDK baseline and JNI/FFM ADR
- Maven/Gradle artifacts
- External JVM consumer

**Acceptance**
- Select and test an actual minimum JDK and native loading approach.
- Validate lifecycle, errors, byte buffers, native library packaging, and platform classifiers.
- Do not imply Android compatibility solely from JVM support.

#### ABC-029 · M3 · Seven-ecosystem conformance and compatibility

**Dependencies:** ABC-019, ABC-020, ABC-023, ABC-024, ABC-025, ABC-026, ABC-027, ABC-028  
**Owner role:** integration-testing

**Deliverables**
- Common conformance corpus
- External consumer matrix
- Cross-version compatibility baseline

**Acceptance**
- Rust, C, C++, Go, Java, npm, and PyPI artifacts install and run real consumers.
- Check common bytes, errors, streaming, provider identity, and supported runtime baselines.
- Retain old artifacts and verify applicable cross-version data behavior rather than workspace-only compilation.

#### ABC-030 · M4 · Release verification and supply-chain gate

**Dependencies:** ABC-004, ABC-010, ABC-011, ABC-016, ABC-029  
**Owner role:** release-security

**Deliverables**
- Release-set manifest
- Clean verification and packaging workflow
- SBOM, provenance, and artifact verification

**Acceptance**
- Rebuild and verify the supported release closure using reviewed tools, policies, and sources.
- Reject research-only dependencies, missing review, stale evidence, forged artifacts, or incorrect consumer packages.
- Produce reviewable artifacts locally; production claims and external publication require actual satisfied gates and session authorization.
- Engineering completion means the implemented gate correctly rejects candidates without independent review. Actual production approval is a separate ReleaseSet state and may remain blocked without blocking maintenance-policy engineering.

#### ABC-031 · M4 · Upstream continuity and vulnerability drill

**Dependencies:** ABC-005, ABC-008, ABC-030  
**Owner role:** maintenance-security

**Deliverables**
- Upstream/advisory monitoring
- Affected-release query
- Backport and migration rehearsal

**Acceptance**
- Map a simulated upstream issue to exact versions, features, targets, and consumers.
- Demonstrate patch/backport or provider migration while checking data and API compatibility.
- Do not silence scanners globally; any scoped exception has owner, justification, and expiry.

#### ABC-032 · M4 · Governance, support, and industry participation

**Dependencies:** ABC-004, ABC-013, ABC-031  
**Owner role:** governance

**Deliverables**
- Maintainer and backup-role records
- RFC and review process
- Support/EOL and disclosure policies

**Acceptance**
- Use real role assignments or explicit vacancies; never invent independent reviewers or a legal foundation.
- Publish support commitments that actual resources can satisfy.
- Keep public evidence and security updates separate from commercial certification services.

#### ABC-033 · M5 · First secret-bearing production profile

**Dependencies:** ABC-018, ABC-030, ABC-039  
**Owner role:** formal-runtime-security

**Deliverables**
- Reviewed AEAD/KDF use-case selection
- Modular primitive and composition work items
- RNG, nonce, key, and format integration

**Acceptance**
- Select an established suite through a source-backed ADR and split every component into normal implementation/proof tasks.
- Complete the profile-required correctness, state, side-channel, misuse, and interop evidence before production approval.
- RNG failure, nonce ownership, key-use limits, and unauthorized fallbacks have explicit negative tests.

#### ABC-034 · M5 · Signature and wallet-use-case expansion

**Dependencies:** ABC-018, ABC-030, ABC-039  
**Owner role:** formal-runtime-security

**Deliverables**
- Explicit signing and wallet requirements
- Algorithm/curve/encoding module tasks
- Key lifecycle and interoperability fixtures

**Acceptance**
- Distinguish curves, schemes, hashes, encodings, HD derivation, and protocol-level assumptions.
- Validate invalid inputs, canonicalization, key usage, target-specific leakage, and applicable exact refinement claims.
- Do not claim a complete wallet or protocol is secured by a primitive proof alone.

#### ABC-035 · M5 · Catalog expansion and literature ingestion

**Dependencies:** ABC-006, ABC-013  
**Owner role:** registry-research

**Deliverables**
- Bounded-source importers
- Deduplication and provenance pipeline
- Expansion task generator

**Acceptance**
- Demonstrate a versioned source snapshot with aliases, variants, errata, rights, and human-reviewable changes.
- Generate per-module tasks for classical, mainstream, PQC, ZK, MPC, FHE, and other declared domains.
- Report coverage against the specific source set; completing this importer is not completing all cryptography.

#### ABC-036 · M5 · Original-language upstream verification pilot

**Dependencies:** ABC-014, ABC-017, ABC-030  
**Owner role:** formal-upstream

**Deliverables**
- One fixed original-language upstream implementation
- Verification route ADR
- Separate source and proof evidence

**Acceptance**
- Preserve original revision, language, license, local patches, and responsibility level.
- Establish a checked connection to the shared Lean specification or remain explicitly blocked.
- Never substitute proof of a rewrite for verification of the original source.

#### ABC-037 · M5 · Swift and Android Kotlin SDKs

**Dependencies:** ABC-018, ABC-023  
**Owner role:** sdk-mobile

**Deliverables**
- Swift packaging and consumer
- Android artifact and consumer
- Per-platform evidence

**Acceptance**
- Create separate child tasks and complete actual packaging for each ecosystem.
- Record real-device, simulator, emulator, and compile-only evidence distinctly.
- Handle native ABI, lifecycle, randomness, and non-exportable provider boundaries explicitly.

#### ABC-038 · M5 · .NET, WASI, and embedded target expansion

**Dependencies:** ABC-018, ABC-023  
**Owner role:** sdk-platform

**Deliverables**
- Per-runtime expansion ADRs and child tasks
- Installable selected SDK artifacts
- Target capability matrix

**Acceptance**
- Complete each selected child target independently; planned targets cannot be counted as shipped.
- Test real runtimes and document native library and capability requirements.
- Keep WASI, browser WASM, and embedded randomness/platform assumptions separate.

#### ABC-039 · M4 · Benchmark and side-channel evidence method

**Dependencies:** ABC-004, ABC-017  
**Owner role:** assurance-testing

**Deliverables**
- Benchmark environment schema
- Leakage-model and timing-test method
- Reproduction and regression workflow

**Acceptance**
- Record hardware, compiler, flags, input distribution, environment noise, and result uncertainty.
- Treat shared CI timings as coarse regression data rather than definitive performance or constant-time proof.
- Define profile-specific evidence needed before adding secret-bearing optimized implementations.

#### ABC-040 · M5 · Reviewable research and maintenance automation

**Dependencies:** ABC-009, ABC-010, ABC-013, ABC-035  
**Owner role:** research-automation

**Deliverables**
- Task templates and resumable orchestration
- Deterministic verification integration
- Change-review and resource controls

**Acceptance**
- Agents may propose metadata, specifications, proofs, code, and harnesses but cannot self-approve policy or production claims.
- Every proposed result flows through the same trusted evidence and review gates.
- Checkpoint real work and budgets without converting generated text into evidence of execution.

## 26. Copyable Agent Start Prompt

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
