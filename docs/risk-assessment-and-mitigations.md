# 聲音照相證據平台 - 風險評估與緩解方案

> **版本**: v1.0
> **日期**: 2026-03-05
> **作者**: 資安與程式專家審查
> **狀態**: 審查完成

---

## 1. 專家提出的風險評估

### 1.1 風險清單總覽

| # | 風險 | 嚴重度 | 可能性 | 評估結論 |
|---|------|--------|--------|----------|
| R1 | P2 後端工期超時 | 中 | 高 | **合理** - 後端整合複雜度常被低估 |
| R2 | Key Attestation root rotation | 高 | 確定 | **合理且緊急** - Google 已公告時程 |
| R3 | 跨 repo 規格漂移 | 中 | 中 | **合理** - 多團隊協作常見問題 |
| R4 | Nonce 重用導致安全漏洞 | 極高 | 中 | **合理且嚴重** - AES-GCM 致命弱點 |
| R5 | 用戶誤解「已上傳=已上鏈」 | 低 | 高 | **合理** - UX 問題但非技術風險 |

### 1.2 遺漏的關鍵風險

經審查，原規劃遺漏以下重要風險：

| # | 遺漏風險 | 嚴重度 | 說明 |
|---|----------|--------|------|
| R6 | DEK 金鑰洩漏或遺失 | 極高 | 證據無法解密或被偽造 |
| R7 | 時間來源不可信 | 高 | 裝置時間可被竄改 |
| R8 | 離線期間裝置被 Root | 高 | Key Attestation 無法即時驗證 |
| R9 | 平台私鑰洩漏 | 極高 | 所有證據可信度歸零 |
| R10 | Merkle Tree 碰撞攻擊 | 低 | 理論風險，SHA-256 目前安全 |
| R11 | 重放攻擊 (Replay Attack) | 中 | 舊證據被重新提交 |
| R12 | 中間人攻擊 (MITM) | 中 | 上傳過程被攔截 |

---

## 2. 各風險詳細分析與解決方案

### R1: P2 後端工期超時

**風險描述**：
後端開發涉及 WORM 儲存、透明日誌、TSA 整合等多個外部依賴，工期常被低估。

**原緩解措施評估**：
> 預留 1-2 週緩衝；核心功能優先

**評估**：措施合理但不夠具體。

**建議解決方案**：

```yaml
mitigation:
  # 1. 明確定義 MVP 功能範圍
  mvpScope:
    must_have:
      - Session API (裝置認證)
      - Chunk upload (WORM 儲存)
      - Provisional proof (透明日誌)
    nice_to_have:
      - TSA 整合
      - 區塊鏈錨定
    defer_to_p3:
      - 離線驗證包生成
      - 驗證報告 PDF

  # 2. 設立明確的 Go/No-Go 檢查點
  checkpoints:
    - date: "Week 1 End"
      criteria: "Session API 可接收請求"
      fallback: "使用 mock attestation"

    - date: "Week 2 End"
      criteria: "單一 chunk 上傳成功"
      fallback: "暫用本地檔案系統"

    - date: "Week 3 End"
      criteria: "完整上傳流程可運作"
      fallback: "TSA/OTS 改為 Phase 3"

  # 3. 技術降級策略
  degradationPaths:
    worm_storage:
      primary: "AWS S3 Object Lock"
      fallback: "PostgreSQL + 稽核日誌"

    transparency_log:
      primary: "自建 Trillian"
      fallback: "Append-only PostgreSQL table"

    tsa:
      primary: "DigiCert TSA"
      fallback: "內部時間戳 + 後補 TSA"
```

---

### R2: Key Attestation Root Rotation

**風險描述**：
Google 將於 2026-04-10 輪換 Key Attestation 根憑證，舊 root 將失效。

**原緩解措施評估**：
> 時程寫死；提前更新信任庫

**評估**：方向正確，但缺少具體實作細節和監控機制。

**建議解決方案**：

```yaml
mitigation:
  # 1. 信任庫管理
  trustStore:
    location: "app/src/main/res/raw/attestation_roots.pem"
    updateStrategy: "compile-time embedding"

    roots:
      - name: "Google Hardware Attestation Root 1"
        validUntil: "2026-04-10"
        fingerprint: "sha256:..."

      - name: "Google Hardware Attestation Root 2"
        validFrom: "2026-02-01"
        fingerprint: "sha256:..."

  # 2. 雙軌驗證期
  dualValidation:
    period: "2026-02-01 to 2026-04-10"
    logic: |
      if (certChain.verifiedBy(newRoot)) return VALID;
      if (certChain.verifiedBy(legacyRoot) && now < "2026-04-10") return VALID;
      return INVALID;

  # 3. 監控與告警
  monitoring:
    metrics:
      - name: "attestation_root_usage"
        labels: ["root_version"]
        alert: "legacy_root_usage > 10% after 2026-03-15"

      - name: "attestation_failure_rate"
        threshold: "5%"
        alert: "P1 - 可能是 root 問題"

  # 4. 緊急更新機制
  emergencyUpdate:
    # 雖然規範禁止 runtime 動態抓取，但保留緊急 App 更新能力
    forceUpdateVersion: "配合 Play Store 強制更新"
    rolloutPlan:
      - "2026-03-01: 發布含新 root 的版本"
      - "2026-03-15: 強制更新提示"
      - "2026-04-01: 阻止舊版本使用"

  # 5. 後端驗證邏輯
  backendVerification:
    code: |
      fun verifyAttestationChain(chain: List<X509Certificate>): AttestationResult {
          val now = Instant.now()

          // 嘗試新 root
          if (verifyChainAgainstRoot(chain, NEW_ROOT)) {
              return AttestationResult.valid(rootVersion = "v2")
          }

          // 過渡期允許舊 root
          if (now.isBefore(LEGACY_CUTOFF) && verifyChainAgainstRoot(chain, LEGACY_ROOT)) {
              metrics.increment("attestation_legacy_root_used")
              return AttestationResult.valid(rootVersion = "v1", warning = "legacy_root")
          }

          return AttestationResult.invalid("root_verification_failed")
      }
```

---

### R3: 跨 Repo 規格漂移

**風險描述**：
`evidence-contracts`、`noisecamara-app`、`evidence-platform` 三個 repo 的實作可能與規格不一致。

**原緩解措施評估**：
> contracts repo + CI 契約測試

**評估**：方向正確，需要更具體的執行機制。

**建議解決方案**：

```yaml
mitigation:
  # 1. 契約測試自動化
  contractTesting:
    # App repo 的 CI
    app_ci:
      steps:
        - name: "Fetch latest contracts"
          run: "git submodule update --remote evidence-contracts"

        - name: "Run conformance tests"
          run: "./gradlew :app:testConformance"

        - name: "Verify test vector compatibility"
          run: |
            kotlin reference-impl/kotlin/AadBuilderTest.kt
            # 必須與 contracts repo 的 test-vectors 一致

    # Backend repo 的 CI
    backend_ci:
      steps:
        - name: "Generate types from schema"
          run: "npx json-schema-to-typescript schemas/*.json > src/types/"

        - name: "Run contract tests"
          run: "npm run test:contracts"

  # 2. Schema 版本鎖定
  versionLocking:
    strategy: "git submodule + version tag"

    # 各 repo 的 package.json / build.gradle
    dependencies:
      app: "evidence-contracts@v0.1.0"
      backend: "evidence-contracts@v0.1.0"

    # 升級流程
    upgradeProcess:
      - "contracts repo 發布新 tag"
      - "更新各 repo 的 submodule reference"
      - "CI 自動執行 conformance tests"
      - "所有測試通過才允許 merge"

  # 3. Breaking Change 保護
  breakingChangeProtection:
    # contracts repo 的 CI
    checks:
      - name: "Schema backward compatibility"
        run: |
          # 比較 HEAD 與上一個 release tag
          ajv validate --schema schemas/manifest.v2.schema.json \
                       --data test-fixtures/v2.0-sample.json

      - name: "Test vector stability"
        run: |
          # 確保舊的 test vectors 仍然有效
          python verify_vectors.py --include-deprecated

  # 4. 規格變更流程
  changeProcess:
    steps:
      - "1. 在 contracts repo 開 PR"
      - "2. 更新 schema + test vectors"
      - "3. 更新 reference implementations"
      - "4. CI 驗證跨語言一致性"
      - "5. Merge 後發布新 tag"
      - "6. 各 repo 更新 submodule"
      - "7. 各 repo CI 驗證相容性"
```

---

### R4: Nonce 重用導致安全漏洞

**風險描述**：
AES-GCM 如果 (key, nonce) 對重複使用，攻擊者可透過 XOR 推導出兩個明文的關係，導致**災難性安全漏洞**。

**原緩解措施評估**：
> 嚴格重試規則 + conformance tests

**評估**：**風險被低估**。這是 AES-GCM 的致命弱點，需要多層防護。

**建議解決方案**：

```yaml
mitigation:
  # 1. 架構層防護：DEK 綁定單一 Evidence
  dekIsolation:
    rule: "每個 evidenceId 使用獨立的 DEK"
    enforcement:
      - "DEK 生成時綁定 evidenceId"
      - "wrappedDek 包含 evidenceId，後端驗證綁定關係"
      - "禁止任何跨 evidence 共用 DEK 的 API"

  # 2. Nonce 結構設計（已在規格中）
  nonceStructure:
    format: "noncePrefix (4 bytes) || chunkIndex (8 bytes)"
    guarantees:
      - "noncePrefix 每個 evidence 隨機生成"
      - "chunkIndex 單調遞增，由 App 控制"
      - "同一 evidence 內 nonce 不可能重複"

  # 3. 重試安全機制
  retryProtection:
    # App 端實作
    app_implementation: |
      class ChunkEncryptor {
          private val encryptedChunks = mutableMapOf<Int, EncryptedChunk>()

          fun encryptAndCache(chunkIndex: Int, plaintext: ByteArray): EncryptedChunk {
              // 檢查是否已加密過
              encryptedChunks[chunkIndex]?.let { return it }

              // 首次加密
              val ciphertext = encrypt(plaintext, chunkIndex)
              val chunk = EncryptedChunk(chunkIndex, ciphertext)

              // 必須持久化！
              persistToStorage(chunk)
              encryptedChunks[chunkIndex] = chunk

              return chunk
          }

          fun getForRetry(chunkIndex: Int): EncryptedChunk? {
              // 重試時必須返回相同密文
              return encryptedChunks[chunkIndex]
                  ?: loadFromStorage(chunkIndex)
          }
      }

    # 後端驗證
    backend_validation: |
      // 檢測重複上傳但內容不同的情況
      fun validateChunkUpload(evidenceId: UUID, chunkIndex: Long, ciphertext: ByteArray) {
          val existing = chunkRepository.find(evidenceId, chunkIndex)

          if (existing != null) {
              if (existing.hash != sha256(ciphertext)) {
                  // 嚴重安全事件！
                  securityLog.alert("NONCE_REUSE_ATTEMPT", evidenceId, chunkIndex)
                  throw SecurityException("Chunk content mismatch - possible nonce reuse")
              }
              // 相同內容，冪等處理
              return
          }

          // 新 chunk，正常存儲
          chunkRepository.save(evidenceId, chunkIndex, ciphertext)
      }

  # 4. 監控與告警
  monitoring:
    metrics:
      - name: "chunk_hash_mismatch_count"
        alert: "any > 0 → P0 安全事件"

      - name: "same_nonce_prefix_across_evidence"
        alert: "probability > 1/2^32 → 調查隨機數生成器"

  # 5. Conformance Tests
  conformanceTests:
    - name: "nonce_uniqueness_within_evidence"
      test: |
        val evidence = createEvidence()
        val nonces = mutableSetOf<ByteArray>()

        repeat(1000) { i ->
            val nonce = evidence.buildNonce(chunkIndex = i.toLong())
            assertFalse(nonces.contains(nonce), "Nonce collision at chunk $i")
            nonces.add(nonce)
        }

    - name: "retry_returns_same_ciphertext"
      test: |
        val chunk = encryptor.encrypt(chunkIndex = 0, plaintext)
        val retry = encryptor.getForRetry(chunkIndex = 0)

        assertEquals(chunk.ciphertext, retry.ciphertext)

    - name: "reject_reencryption_attempt"
      test: |
        encryptor.encrypt(chunkIndex = 0, plaintext)

        // 嘗試用不同明文重新加密相同 chunk
        assertThrows<IllegalStateException> {
            encryptor.encrypt(chunkIndex = 0, differentPlaintext)
        }

  # 6. 備援：考慮 AES-256-GCM-SIV
  fallbackOption:
    algorithm: "AES-256-GCM-SIV"
    benefit: "nonce misuse resistant - 即使 nonce 重用也不會洩漏金鑰"
    tradeoff: "效能略低，Android API 要求較高"
    recommendation: |
      如果目標裝置支援（API 28+），考慮預設使用 GCM-SIV。
      aeadSuiteId = 0x02 已在 AAD 規格中預留。
```

---

### R5: 用戶誤解「已上傳=已上鏈」

**風險描述**：
用戶可能以為上傳成功就代表證據已經上鏈，但實際上需要等待 TSA/區塊鏈確認。

**原緩解措施評估**：
> UI 明確區分狀態；SLA 文件

**評估**：合理，這是 UX 問題而非技術風險。

**建議解決方案**：

```yaml
mitigation:
  # 1. UI 狀態設計
  uiStates:
    UPLOADING:
      icon: "cloud_upload"
      color: "blue"
      text: "上傳中..."
      subtext: "正在傳輸至安全伺服器"

    UPLOADED:
      icon: "cloud_done"
      color: "green"
      text: "已安全儲存"
      subtext: "證據已存入防竄改儲存"

    PROVISIONAL:
      icon: "verified_user"
      color: "light_green"
      text: "已記錄"
      subtext: "已寫入透明日誌，等待時間戳"

    ANCHORED_TSA:
      icon: "schedule"
      color: "teal"
      text: "已取得時間戳"
      subtext: "RFC 3161 時間戳已取得"

    ANCHORED_PENDING:
      icon: "hourglass_empty"
      color: "orange"
      text: "區塊鏈確認中"
      subtext: "等待區塊鏈最終確認（約 1-6 小時）"

    FINALITY_REACHED:
      icon: "verified"
      color: "gold"
      text: "完全上鏈"
      subtext: "證據已獲得區塊鏈不可逆確認"

  # 2. 進度條設計
  progressBar:
    stages:
      - { name: "儲存", weight: 20 }
      - { name: "記錄", weight: 10 }
      - { name: "時間戳", weight: 20 }
      - { name: "區塊鏈", weight: 50 }

  # 3. 通知策略
  notifications:
    - trigger: "PROVISIONAL"
      message: "證據已安全記錄，正在等待區塊鏈確認"
      importance: "DEFAULT"

    - trigger: "FINALITY_REACHED"
      message: "證據已完全上鏈，具有法律效力"
      importance: "HIGH"
```

---

### R6: DEK 金鑰洩漏或遺失（新增風險）

**風險描述**：
- **洩漏**：攻擊者可解密所有該 DEK 加密的 chunk
- **遺失**：證據永久無法解密

**建議解決方案**：

```yaml
mitigation:
  # 1. DEK 生命週期管理
  dekLifecycle:
    generation:
      location: "Android Keystore (hardware-backed)"
      algorithm: "AES-256"
      extractable: false  # 不可導出明文

    wrapping:
      method: "RSA-OAEP with server KEK"
      storage: "wrappedDek 存於 manifest"

    destruction:
      trigger: "evidence 上傳完成且確認"
      method: "Keystore.deleteEntry()"

  # 2. 金鑰備份策略
  keyBackup:
    # DEK 本身不備份（Envelope Encryption 設計）
    # 只要 wrappedDek 和 server KEK 存在，即可恢復

    serverKekProtection:
      primary: "AWS KMS / GCP Cloud KMS"
      backup: "HSM with multi-party key ceremony"
      rotation: "yearly with backward compatibility"

  # 3. 異常檢測
  anomalyDetection:
    - "同一 DEK 加密超過 1TB 資料 → 告警"
    - "DEK 使用時間超過 24 小時 → 告警"
    - "wrappedDek 解密失敗 → 調查 KEK 狀態"
```

---

### R7: 時間來源不可信（新增風險）

**風險描述**：
裝置系統時間可被用戶或惡意軟體修改，導致事件時間戳不可信。

**建議解決方案**：

```yaml
mitigation:
  # 1. 多重時間來源
  timeSources:
    primary: "serverIssuedAtUtc (Session API 返回)"
    secondary: "TSA timestamp (RFC 3161)"
    reference: "device clock (僅供參考)"

    validation: |
      // 檢測裝置時間偏移
      val serverTime = session.serverIssuedAtUtc
      val deviceTime = System.currentTimeMillis()
      val drift = abs(serverTime - deviceTime)

      if (drift > 5.minutes) {
          manifest.anomalyFlags.add("DEVICE_CLOCK_DRIFT")
          metrics.record("clock_drift_seconds", drift.seconds)
      }

  # 2. 事件鏈時間約束
  eventChainConstraints:
    rules:
      - "event[i].timestamp >= event[i-1].timestamp"
      - "所有 event.timestamp 在 session 時間範圍內"
      - "event timestamp 與 server time 偏差 < 1 hour"

    violation: "標記 anomalyFlag，不拒絕但降低可信度"

  # 3. TSA 作為權威時間
  tsaAuthority:
    role: "TSA timestamp 是唯一可信的時間證明"
    ui_display: "顯示 TSA 時間，而非裝置時間"
```

---

### R8: 離線期間裝置被 Root（新增風險）

**風險描述**：
如果用戶在離線狀態下錄製證據，期間裝置被 root，Key Attestation 無法即時偵測。

**建議解決方案**：

```yaml
mitigation:
  # 1. 離線錄製限制
  offlineRestrictions:
    maxOfflineDuration: "24 hours"
    maxOfflineEvidence: "10 件"
    enforcement: |
      if (lastServerContact > 24.hours) {
          // 提示用戶連網驗證
          showWarning("請連接網路以驗證裝置完整性")
          // 允許繼續但標記
          manifest.anomalyFlags.add("EXTENDED_OFFLINE")
      }

  # 2. 連網時重新驗證
  reconnectValidation:
    steps:
      - "重新執行 Key Attestation"
      - "比對 deviceKeyId 是否一致"
      - "檢查 attestation 時間是否在離線期間"

    mismatch_action: |
      if (currentAttestation.deviceKeyId != session.deviceKeyId) {
          rejectEvidence("DEVICE_KEY_CHANGED")
      }

  # 3. Play Integrity API 補充驗證
  playIntegrity:
    usage: "Session 建立時檢查 device integrity"
    checks:
      - "MEETS_DEVICE_INTEGRITY"
      - "MEETS_BASIC_INTEGRITY"

    recommendation: |
      即使 Key Attestation 通過，Play Integrity 失敗
      也應標記 anomalyFlag。
```

---

### R9: 平台私鑰洩漏（新增風險）

**風險描述**：
如果平台的 KEK 或簽章私鑰洩漏，所有證據的加密和簽章都失去可信度。

**建議解決方案**：

```yaml
mitigation:
  # 1. 金鑰分級管理
  keyHierarchy:
    kek:
      storage: "Cloud KMS (AWS/GCP) with CMK"
      access: "IAM role-based, audit logged"
      rotation: "Yearly, with key version tracking"

    platform_signing_key:
      storage: "HSM (FIPS 140-2 Level 3)"
      access: "Multi-party authorization"
      rotation: "Bi-yearly"

  # 2. 金鑰洩漏應變計劃
  keyCompromiseResponse:
    detection:
      - "異常解密請求模式"
      - "未授權 API 呼叫"
      - "Canary token 觸發"

    response:
      immediate:
        - "撤銷受影響的 KEK version"
        - "通知所有受影響的用戶"
        - "啟動事件調查"

      recovery:
        - "使用新 KEK 重新包裝未受影響的 DEK"
        - "受影響的證據標記為 COMPROMISED"
        - "提供重新蒐證指引"

  # 3. 前向保密設計
  forwardSecrecy:
    design: |
      即使 KEK 洩漏，攻擊者仍需要：
      1. wrappedDek（存於 manifest）
      2. 對應的密文 chunks

      如果 chunks 使用獨立的 DEK，單一 KEK 洩漏
      不會影響所有證據。
```

---

### R11: 重放攻擊（新增風險）

**風險描述**：
攻擊者可能重新提交舊的有效證據，偽造新的蒐證事件。

**建議解決方案**：

```yaml
mitigation:
  # 1. Session 綁定
  sessionBinding:
    components:
      - sessionId (server-generated UUID)
      - serverIssuedAtUtc (server timestamp)
      - appSignatureDigest (app integrity)
      - deviceKeyId (hardware key binding)

    hash: "sessionBindingHash = SHA-256(above)"
    inclusion: "寫入 sealHash 計算"

  # 2. 一次性使用保證
  oneTimeUse:
    evidenceIdUniqueness:
      - "後端檢查 evidenceId 是否已存在"
      - "存在則拒絕（除非是重試相同內容）"

    sessionExpiry:
      - "Session 有效期 24 小時"
      - "過期後無法上傳新證據"

  # 3. 時間戳驗證
  timestampValidation:
    rules:
      - "TSA timestamp 必須在 session 時間範圍內"
      - "區塊鏈錨定時間必須晚於 session 開始"
```

---

### R12: 中間人攻擊（新增風險）

**風險描述**：
上傳過程可能被攔截，攻擊者替換 chunks 或竊取 DEK。

**建議解決方案**：

```yaml
mitigation:
  # 1. TLS 強制
  tlsRequirements:
    minVersion: "TLS 1.3"
    certificatePinning: true
    pinnedCerts:
      - "sha256/AAAA..."  # Primary
      - "sha256/BBBB..."  # Backup

  # 2. 端到端完整性
  e2eIntegrity:
    design: |
      1. DEK 在 App 端生成，從未明文傳輸
      2. wrappedDek 使用 server 公鑰加密
      3. sealHash 包含所有 chunk 的 Merkle root
      4. 任何 chunk 被替換都會導致驗證失敗

  # 3. 上傳確認機制
  uploadConfirmation:
    flow:
      - "App 上傳 chunk"
      - "Server 返回 chunk hash"
      - "App 驗證 hash 一致"
      - "所有 chunk 確認後提交 manifest"

    mismatch: "中止上傳，報告安全事件"
```

---

## 3. 解決方案優先級

| 優先級 | 風險 | 建議行動 | 時程 |
|--------|------|----------|------|
| P0 | R4 Nonce 重用 | 實作 conformance tests + 監控 | Phase 1 |
| P0 | R2 Key Attestation Rotation | 更新信任庫 + 雙軌驗證 | 2026-03-15 前 |
| P1 | R6 DEK 管理 | 實作 Envelope Encryption | Phase 1 |
| P1 | R9 平台私鑰保護 | 配置 KMS/HSM | Phase 2 |
| P1 | R7 時間來源 | 實作 server timestamp | Phase 2 |
| P2 | R3 規格漂移 | 建立 CI 契約測試 | Phase 0 (已完成) |
| P2 | R8 離線 Root | 實作重連驗證 | Phase 2 |
| P2 | R11 重放攻擊 | Session 綁定 + 唯一性檢查 | Phase 2 |
| P2 | R12 MITM | TLS 1.3 + Certificate Pinning | Phase 1 |
| P3 | R1 工期超時 | 設立檢查點 + 降級策略 | 持續 |
| P3 | R5 UX 誤解 | UI 設計 | Phase 3 |

---

## 4. 結論

原規劃文件中提出的 5 項風險**全部合理**，但經審查發現：

1. **R4 (Nonce 重用)** 風險被低估，需要多層防護
2. **R2 (Key Attestation Rotation)** 時間緊迫，需立即行動
3. 遺漏 7 項重要風險 (R6-R12)

**建議**：
1. 將本文件納入專案規格
2. 按優先級排序，P0 風險必須在對應 Phase 完成前解決
3. 建立風險追蹤看板，定期審查狀態

---

## 附錄：風險追蹤表

| 風險 ID | 狀態 | 負責人 | 預計解決日期 | 驗證方式 |
|---------|------|--------|--------------|----------|
| R1 | OPEN | - | Phase 2 End | 檢查點通過 |
| R2 | OPEN | - | 2026-03-15 | CI 驗證雙軌 |
| R3 | MITIGATED | - | - | CI 契約測試 |
| R4 | OPEN | - | Phase 1 End | Conformance tests |
| R5 | OPEN | - | Phase 3 | UI Review |
| R6 | OPEN | - | Phase 1 End | Code review |
| R7 | OPEN | - | Phase 2 End | Integration test |
| R8 | OPEN | - | Phase 2 End | Security review |
| R9 | OPEN | - | Phase 2 Start | HSM 配置確認 |
| R10 | ACCEPTED | - | - | 理論風險，暫不處理 |
| R11 | OPEN | - | Phase 2 End | Penetration test |
| R12 | OPEN | - | Phase 1 End | SSL Labs A+ |
