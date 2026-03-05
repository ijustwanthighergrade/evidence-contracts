# Security Requirements Specification

> **版本**: 1.0
> **狀態**: 規格凍結
> **適用階段**: Phase 1 (App) + Phase 2 (Backend)
> **優先級**: P1

---

## 1. 概述

本文件定義 Evidence Platform 的安全需求。所有實作必須符合這些規格才能通過 conformance tests。

### 1.1 風險對照

| 風險 ID | 風險名稱 | 本文件章節 |
|---------|----------|------------|
| R6 | DEK 金鑰洩漏或遺失 | §2 DEK 管理 |
| R7 | 時間來源不可信 | §3 時間戳安全 |
| R9 | 平台私鑰洩漏 | §4 平台金鑰管理 |
| R12 | 中間人攻擊 | §5 傳輸層安全 |

### 1.2 實作責任

| 需求章節 | App 責任 | Backend 責任 |
|----------|----------|--------------|
| §2 DEK 管理 | ✅ | ✅ |
| §3 時間戳安全 | ✅ | ✅ |
| §4 平台金鑰管理 | - | ✅ |
| §5 傳輸層安全 | ✅ | ✅ |

---

## 2. DEK 管理 (R6)

### 2.1 DEK 生成

#### 2.1.1 要求

| 項目 | 要求 | 驗證方式 |
|------|------|----------|
| 演算法 | AES-256 | Code review |
| 金鑰來源 | Android Keystore | Key Attestation |
| 可提取性 | 不可提取 (extractable=false) | Key Attestation |
| 用途限制 | 僅加密 (PURPOSE_ENCRYPT) | Key Attestation |

#### 2.1.2 Android Keystore 配置

```kotlin
// REQUIRED: DEK 必須使用此配置生成
val keyGenSpec = KeyGenParameterSpec.Builder(
    "dek_${evidenceId}",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
    .setKeySize(256)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(false)  // 允許背景加密
    .setRandomizedEncryptionRequired(true)
    .setIsStrongBoxBacked(isStrongBoxAvailable)  // 優先使用 StrongBox
    .build()

val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
)
keyGenerator.init(keyGenSpec)
val dek = keyGenerator.generateKey()
```

#### 2.1.3 禁止事項

```kotlin
// PROHIBITED: 禁止以下做法

// ❌ 使用軟體金鑰
val badKey = KeyGenerator.getInstance("AES").generateKey()

// ❌ 可提取金鑰
val badSpec = KeyGenParameterSpec.Builder(...)
    .setRandomizedEncryptionRequired(false)  // ❌
    .build()

// ❌ 金鑰重用
fun getOrCreateDek(evidenceId: UUID): SecretKey {
    // ❌ 檢查並重用已存在的金鑰
    return keyStore.getKey(evidenceId) ?: createNewDek(evidenceId)
}
```

### 2.2 DEK 綁定

#### 2.2.1 Evidence-DEK 一對一綁定

```
┌─────────────────┐
│   evidenceId    │
│ (UUID, unique)  │
└────────┬────────┘
         │ 1:1 binding
         │
         ▼
┌─────────────────┐
│      DEK        │
│ (AES-256 key)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   wrappedDek    │
│ (encrypted DEK) │
└─────────────────┘
```

#### 2.2.2 wrappedDek 結構

```kotlin
data class WrappedDek(
    val version: Int = 1,
    val evidenceId: UUID,           // MUST match evidence
    val dekId: String,              // Unique DEK identifier
    val wrappedKeyMaterial: ByteArray,  // RSA-OAEP encrypted DEK
    val wrappingKeyId: String,      // Server KEK identifier
    val wrappedAt: Instant
)

// Serialization format (for manifest)
fun toBase64(): String {
    val buffer = ByteBuffer.allocate(...)
    buffer.putInt(version)
    buffer.putLong(evidenceId.mostSignificantBits)
    buffer.putLong(evidenceId.leastSignificantBits)
    // ... rest of fields
    return Base64.encode(buffer.array())
}
```

#### 2.2.3 後端驗證

```typescript
// Backend MUST verify DEK binding
async function validateWrappedDek(
    evidenceId: string,
    wrappedDekBase64: string
): Promise<ValidationResult> {
    const wrappedDek = parseWrappedDek(wrappedDekBase64);

    // Rule 1: evidenceId must match
    if (wrappedDek.evidenceId !== evidenceId) {
        return { valid: false, error: 'DEK_EVIDENCE_MISMATCH' };
    }

    // Rule 2: DEK must not be used elsewhere
    const existingUsage = await dekUsageRepository.find(wrappedDek.dekId);
    if (existingUsage && existingUsage.evidenceId !== evidenceId) {
        await securityAlert('DEK_REUSE_ATTEMPT', {
            dekId: wrappedDek.dekId,
            existingEvidence: existingUsage.evidenceId,
            attemptedEvidence: evidenceId
        });
        return { valid: false, error: 'DEK_ALREADY_USED' };
    }

    // Rule 3: Verify wrapping key is valid
    const kekStatus = await kms.getKeyStatus(wrappedDek.wrappingKeyId);
    if (kekStatus !== 'ACTIVE') {
        return { valid: false, error: 'INVALID_WRAPPING_KEY' };
    }

    return { valid: true };
}
```

### 2.3 DEK 生命週期

```
┌──────────┐  Session 建立   ┌──────────┐  首次加密   ┌──────────┐
│  INIT    │ ─────────────> │ CREATED  │ ──────────> │  ACTIVE  │
└──────────┘                └──────────┘             └──────────┘
                                                          │
                            ┌─────────────────────────────┤
                            │                             │
                            ▼                             ▼
                     ┌──────────┐                  ┌──────────┐
                     │  SEALED  │                  │ ABANDONED│
                     │(上傳完成) │                  │(遺失/錯誤)│
                     └────┬─────┘                  └──────────┘
                          │
                          ▼
                     ┌──────────┐
                     │DESTROYED │
                     │(DEK 銷毀) │
                     └──────────┘
```

#### 2.3.1 狀態轉換規則

| 當前狀態 | 允許轉換 | 觸發條件 |
|----------|----------|----------|
| INIT | CREATED | DEK 生成成功 |
| CREATED | ACTIVE | 首次 chunk 加密 |
| CREATED | ABANDONED | noncePrefix 遺失 |
| ACTIVE | SEALED | 上傳完成並確認 |
| ACTIVE | ABANDONED | 錯誤或超時 |
| SEALED | DESTROYED | 確認保留期後銷毀 |

#### 2.3.2 DEK 銷毀

```kotlin
// REQUIRED: 上傳確認後銷毀本地 DEK
fun destroyDek(evidenceId: UUID) {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)

    val alias = "dek_${evidenceId}"
    if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias)
        log.info("DEK destroyed for evidence $evidenceId")
    }

    // Also clear any cached key references
    dekCache.remove(evidenceId)
}
```

### 2.4 DEK 遺失處理

#### 2.4.1 遺失檢測

```kotlin
sealed class DekStatus {
    object Available : DekStatus()
    object Lost : DekStatus()
    data class Recoverable(val source: RecoverySource) : DekStatus()
}

fun checkDekStatus(evidenceId: UUID): DekStatus {
    // 1. Check local Keystore
    if (isInKeystore(evidenceId)) {
        return DekStatus.Available
    }

    // 2. Check if evidence was already uploaded (can recover from server)
    if (hasUploadedManifest(evidenceId)) {
        return DekStatus.Recoverable(RecoverySource.SERVER_MANIFEST)
    }

    // 3. DEK is lost
    return DekStatus.Lost
}
```

#### 2.4.2 遺失處理流程

```kotlin
fun handleDekLoss(evidenceId: UUID): RecoveryAction {
    val status = checkDekStatus(evidenceId)

    return when (status) {
        is DekStatus.Lost -> {
            // Mark evidence as abandoned
            evidenceRepository.markAbandoned(evidenceId, "DEK_LOST")

            // Notify user
            notifyUser(
                title = "證據無法完成",
                message = "加密金鑰遺失，請重新錄製"
            )

            RecoveryAction.ABANDON_AND_RERECORD
        }

        is DekStatus.Recoverable -> {
            // Attempt recovery
            RecoveryAction.RESTORE_FROM_SERVER
        }

        is DekStatus.Available -> {
            RecoveryAction.NONE_NEEDED
        }
    }
}
```

---

## 3. 時間戳安全 (R7)

### 3.1 時間來源層級

| 優先級 | 來源 | 可信度 | 用途 |
|--------|------|--------|------|
| 1 | RFC 3161 TSA | 最高 | 法律證明 |
| 2 | Server timestamp | 高 | 業務邏輯 |
| 3 | Device clock | 低 | 僅供參考 |

### 3.2 Server Timestamp 規格

#### 3.2.1 Session API 回應

```yaml
POST /api/v2/sessions

Response:
  sessionId: "uuid"
  serverIssuedAtUtc: "2026-03-05T14:30:00.000Z"  # REQUIRED
  serverTimezone: "UTC"
  ntpSyncStatus: "SYNCED"  # SYNCED | DRIFT_DETECTED | UNKNOWN
```

#### 3.2.2 時間同步驗證

```kotlin
// App MUST verify server time reasonableness
fun validateServerTime(serverIssuedAtUtc: Instant): TimeValidation {
    val deviceTime = Instant.now()
    val drift = Duration.between(serverIssuedAtUtc, deviceTime).abs()

    return when {
        drift < Duration.ofMinutes(1) -> TimeValidation.VALID
        drift < Duration.ofMinutes(5) -> TimeValidation.ACCEPTABLE_DRIFT
        drift < Duration.ofHours(1) -> TimeValidation.SIGNIFICANT_DRIFT
        else -> TimeValidation.INVALID
    }
}
```

### 3.3 裝置時間偏移處理

#### 3.3.1 偏移檢測

```kotlin
data class ClockDriftInfo(
    val serverTime: Instant,
    val deviceTime: Instant,
    val driftMs: Long,
    val direction: DriftDirection  // AHEAD | BEHIND
)

fun detectClockDrift(session: SessionResponse): ClockDriftInfo {
    val serverTime = session.serverIssuedAtUtc
    val deviceTime = Instant.now()
    val driftMs = ChronoUnit.MILLIS.between(serverTime, deviceTime)

    return ClockDriftInfo(
        serverTime = serverTime,
        deviceTime = deviceTime,
        driftMs = driftMs.absoluteValue,
        direction = if (driftMs > 0) DriftDirection.AHEAD else DriftDirection.BEHIND
    )
}
```

#### 3.3.2 Manifest 異常標記

```kotlin
// When drift > 5 minutes, add anomaly flag
if (clockDrift.driftMs > 5 * 60 * 1000) {
    manifest.anomalyFlags.add(
        AnomalyFlag(
            type = "DEVICE_CLOCK_DRIFT",
            severity = "WARNING",
            details = mapOf(
                "driftMs" to clockDrift.driftMs,
                "direction" to clockDrift.direction.name,
                "serverTime" to clockDrift.serverTime.toString(),
                "deviceTime" to clockDrift.deviceTime.toString()
            )
        )
    )
}
```

### 3.4 事件時間戳約束

#### 3.4.1 事件鏈時序規則

```typescript
// Backend validation
function validateEventChainTimestamps(events: Event[]): ValidationResult {
    const errors: string[] = [];

    for (let i = 1; i < events.length; i++) {
        const prev = events[i - 1];
        const curr = events[i];

        // Rule 1: Timestamps must be monotonically increasing
        if (curr.timestamp < prev.timestamp) {
            errors.push(`Event ${i} timestamp before event ${i-1}`);
        }

        // Rule 2: No event can be more than 1 hour after previous
        const gap = curr.timestamp - prev.timestamp;
        if (gap > 3600000) {  // 1 hour in ms
            errors.push(`Suspicious gap of ${gap}ms between events ${i-1} and ${i}`);
        }
    }

    return {
        valid: errors.length === 0,
        errors
    };
}
```

#### 3.4.2 Session 時間範圍驗證

```typescript
function validateEventWithinSession(
    event: Event,
    session: Session
): boolean {
    const eventTime = new Date(event.timestamp);
    const sessionStart = new Date(session.serverIssuedAtUtc);
    const sessionEnd = new Date(session.expiresAt);

    // Event must be within session validity period
    return eventTime >= sessionStart && eventTime <= sessionEnd;
}
```

---

## 4. 平台金鑰管理 (R9)

### 4.1 金鑰層級架構

```
┌─────────────────────────────────────────────────────────────┐
│                    Platform Key Hierarchy                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐                                           │
│  │ Master Key  │  ← HSM (FIPS 140-2 Level 3)               │
│  │  (CMK)      │    Never exported                          │
│  └──────┬──────┘                                           │
│         │                                                   │
│         │ wraps                                              │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │    KEK      │  ← Cloud KMS (AWS/GCP)                    │
│  │ (Key Enc Key)│   Rotated yearly                          │
│  └──────┬──────┘                                           │
│         │                                                   │
│         │ wraps                                              │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │    DEK      │  ← Per-evidence, client-generated         │
│  │ (Data Enc)  │    Wrapped by KEK                          │
│  └─────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 KEK 管理

#### 4.2.1 KEK 規格

| 屬性 | 要求 |
|------|------|
| 演算法 | RSA-4096 或 EC P-384 |
| 用途 | 僅 wrap/unwrap |
| 存儲 | Cloud KMS (AWS KMS / GCP Cloud KMS) |
| 輪換週期 | 每年 |
| 保留期 | 輪換後保留 5 年（供解密舊資料）|

#### 4.2.2 KEK 輪換

```typescript
// KEK rotation policy
const kekPolicy = {
    rotationPeriodDays: 365,
    retentionPeriodYears: 5,

    // On rotation:
    onRotate: async (oldKekId: string, newKekId: string) => {
        // 1. New evidence uses new KEK
        config.set('activeKekId', newKekId);

        // 2. Old KEK remains for unwrapping existing evidence
        await kekRegistry.markAsLegacy(oldKekId);

        // 3. Log rotation event
        await auditLog.record({
            type: 'KEK_ROTATED',
            oldKekId,
            newKekId,
            timestamp: new Date()
        });
    }
};
```

### 4.3 簽章金鑰管理

#### 4.3.1 Platform Signing Key

| 用途 | 規格 |
|------|------|
| 透明日誌簽章 | ECDSA P-256 |
| 驗證報告簽章 | ECDSA P-256 |
| 存儲 | HSM |
| 輪換週期 | 每兩年 |

#### 4.3.2 金鑰洩漏應變

```yaml
keyCompromiseResponse:
  detection:
    - "Anomalous decryption patterns"
    - "Unauthorized API access"
    - "Canary token triggers"

  immediateActions:
    - "Revoke compromised key within 1 hour"
    - "Notify affected users within 24 hours"
    - "Issue security bulletin"

  recovery:
    kek:
      - "Re-wrap unaffected DEKs with new KEK"
      - "Mark affected evidence as COMPROMISED"
      - "Provide re-collection guidance"

    signingKey:
      - "Re-sign transparency log with new key"
      - "Update trust anchors in clients"
      - "Force app update"
```

### 4.4 存取控制

```yaml
accessControl:
  kek:
    read: ["evidence-service", "verification-service"]
    admin: ["security-team"]
    audit: ["compliance-team"]

  signingKey:
    sign: ["transparency-log-service"]
    admin: ["security-team"]

  masterKey:
    admin: ["security-team-lead", "cto"]
    ceremony: "Requires 2 of 3 key holders"
```

---

## 5. 傳輸層安全 (R12)

### 5.1 TLS 要求

#### 5.1.1 協定要求

| 項目 | 要求 |
|------|------|
| 最低版本 | TLS 1.3 |
| 禁止版本 | TLS 1.0, 1.1, 1.2 |
| 密碼套件 | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |

#### 5.1.2 Android 配置

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.evidence-platform.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
</network-security-config>
```

### 5.2 Certificate Pinning

#### 5.2.1 Pinning 策略

| 項目 | 要求 |
|------|------|
| Pin 數量 | 至少 2 個（主要 + 備用）|
| Pin 對象 | SPKI (Subject Public Key Info) |
| 過期日 | 不超過 18 個月 |
| 更新機制 | App 強制更新 |

#### 5.2.2 OkHttp 配置

```kotlin
// REQUIRED: Configure certificate pinning
val certificatePinner = CertificatePinner.Builder()
    .add(
        "api.evidence-platform.com",
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // Primary
        "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="   // Backup
    )
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))  // TLS 1.3 only
    .build()
```

#### 5.2.3 Pin 更新流程

```kotlin
// Pin update via app config (not hardcoded fallback)
class PinUpdateManager(
    private val configService: ConfigService
) {
    suspend fun checkPinUpdate(): PinUpdateResult {
        // Fetch new pins using existing pinned connection
        val newPins = configService.fetchLatestPins()

        if (newPins.version > currentPins.version) {
            // Verify new pins are signed by platform key
            if (verifyPinSignature(newPins)) {
                savePins(newPins)
                return PinUpdateResult.UPDATED
            }
        }

        return PinUpdateResult.NO_UPDATE
    }
}
```

### 5.3 上傳完整性驗證

#### 5.3.1 Chunk 上傳確認

```kotlin
// App-side: Verify server received correct data
suspend fun uploadChunk(
    evidenceId: UUID,
    chunkIndex: Int,
    ciphertext: ByteArray
): UploadResult {
    val localHash = sha256(ciphertext)

    val response = api.uploadChunk(evidenceId, chunkIndex, ciphertext)

    // Verify server computed same hash
    if (response.serverComputedHash != localHash.toHex()) {
        // MITM or corruption detected
        securityLog.alert("CHUNK_HASH_MISMATCH", evidenceId, chunkIndex)
        return UploadResult.INTEGRITY_FAILURE
    }

    return UploadResult.SUCCESS
}
```

#### 5.3.2 後端回應格式

```yaml
POST /api/v2/evidence/{id}/chunks/{index}

Response:
  chunkIndex: 0
  receivedBytes: 8388608
  serverComputedHash: "sha256:abcd1234..."  # Server computes hash
  storedAt: "2026-03-05T14:30:00Z"
  status: "STORED"
```

---

## 6. 監控與告警

### 6.1 安全指標

```yaml
metrics:
  # DEK 管理
  - name: dek_creation_total
    type: counter
    labels: [evidence_id, device_id]

  - name: dek_reuse_attempt_total
    type: counter
    alert: "> 0 → P0"

  - name: dek_recovery_total
    type: counter
    labels: [source]

  # 時間戳
  - name: clock_drift_seconds
    type: histogram
    buckets: [60, 300, 3600]

  - name: timestamp_validation_failures
    type: counter
    labels: [reason]

  # 傳輸安全
  - name: tls_version_used
    type: counter
    labels: [version]
    alert: "tls_1_2 > 0 → P1"

  - name: certificate_pin_failures
    type: counter
    alert: "> 0 → P1"

  - name: chunk_hash_mismatch_total
    type: counter
    alert: "> 0 → P0"
```

### 6.2 告警規則

```yaml
groups:
  - name: security_p1
    rules:
      - alert: DekReuseAttempt
        expr: increase(dek_reuse_attempt_total[5m]) > 0
        labels:
          severity: critical
          priority: P0
        annotations:
          summary: "DEK reuse attempt detected"

      - alert: ChunkIntegrityFailure
        expr: increase(chunk_hash_mismatch_total[5m]) > 0
        labels:
          severity: critical
          priority: P0
        annotations:
          summary: "Chunk integrity verification failed"

      - alert: TlsDowngradeAttempt
        expr: increase(tls_version_used{version!="1.3"}[1h]) > 0
        labels:
          severity: warning
          priority: P1
        annotations:
          summary: "Non-TLS 1.3 connection attempted"

      - alert: HighClockDrift
        expr: histogram_quantile(0.95, clock_drift_seconds) > 3600
        for: 10m
        labels:
          severity: warning
          priority: P2
        annotations:
          summary: "High device clock drift detected"
```

---

## 7. Conformance Tests

### 7.1 Phase 1 必過測試（App 端）

```python
# conformance-tests/security_conformance.py

class TestDekManagement:
    def test_dek_in_keystore(self):
        """DEK must be stored in Android Keystore"""
        pass  # Verify via Key Attestation

    def test_dek_not_extractable(self):
        """DEK must not be extractable"""
        pass  # Verify attestation extension

    def test_dek_bound_to_evidence(self):
        """DEK must be bound to single evidenceId"""
        pass  # Verify wrappedDek contains matching evidenceId

    def test_dek_destroyed_after_upload(self):
        """DEK must be destroyed after upload confirmation"""
        pass  # Verify key deleted from Keystore


class TestTimeSource:
    def test_server_time_used(self):
        """Events must use server-issued timestamp as reference"""
        pass

    def test_clock_drift_detected(self):
        """Clock drift > 5 min must be flagged"""
        pass

    def test_event_timestamps_monotonic(self):
        """Event timestamps must be monotonically increasing"""
        pass


class TestTransportSecurity:
    def test_tls_1_3_only(self):
        """Only TLS 1.3 connections allowed"""
        pass

    def test_certificate_pinning_enforced(self):
        """Certificate pinning must be enforced"""
        pass

    def test_chunk_hash_verified(self):
        """Server-computed chunk hash must be verified"""
        pass
```

### 7.2 Phase 2 必過測試（Backend 端）

```typescript
// conformance-tests/backend_security.test.ts

describe('DEK Management', () => {
    it('rejects mismatched evidenceId in wrappedDek', async () => {
        const wrappedDek = createWrappedDek('evidence-1');
        const result = await uploadComplete('evidence-2', wrappedDek);
        expect(result.error).toBe('DEK_EVIDENCE_MISMATCH');
    });

    it('rejects reused DEK', async () => {
        const dek = generateDek();
        await createEvidence('evidence-1', dek);
        const result = await createEvidence('evidence-2', dek);
        expect(result.error).toBe('DEK_ALREADY_USED');
    });
});

describe('Time Validation', () => {
    it('validates event timestamps within session', async () => {
        const session = await createSession();
        const events = [
            { timestamp: session.serverIssuedAtUtc - 1000 }  // Before session
        ];
        const result = await validateEvents(events, session);
        expect(result.valid).toBe(false);
    });
});

describe('Transport Security', () => {
    it('returns chunk hash in response', async () => {
        const chunk = randomBytes(1024);
        const response = await uploadChunk(chunk);
        expect(response.serverComputedHash).toBe(sha256(chunk).hex());
    });
});
```

---

## 8. 實作檢查清單

### 8.1 App 端 (Phase 1)

```markdown
## DEK 管理
- [ ] DEK 使用 Android Keystore 生成
- [ ] DEK 設定 extractable=false
- [ ] DEK alias 包含 evidenceId
- [ ] wrappedDek 結構正確且包含 evidenceId
- [ ] 上傳確認後銷毀 DEK
- [ ] DEK 遺失時正確處理

## 時間戳
- [ ] Session 回應的 serverIssuedAtUtc 被存儲
- [ ] 檢測並記錄時鐘偏移
- [ ] 偏移 > 5 分鐘時添加 anomalyFlag
- [ ] 事件時間戳單調遞增

## 傳輸安全
- [ ] network_security_config.xml 配置 TLS 1.3
- [ ] Certificate pinning 配置（至少 2 pins）
- [ ] 上傳後驗證 server 返回的 hash
- [ ] 連線失敗時正確處理
```

### 8.2 Backend 端 (Phase 2)

```markdown
## DEK 管理
- [ ] 驗證 wrappedDek 中的 evidenceId 匹配
- [ ] 追蹤 DEK 使用記錄
- [ ] 拒絕 DEK 重用
- [ ] KEK 配置在 Cloud KMS

## 時間戳
- [ ] Session API 返回 serverIssuedAtUtc
- [ ] 驗證事件時間戳在 session 範圍內
- [ ] 驗證事件時間戳單調性

## 平台金鑰
- [ ] KEK 存儲在 KMS
- [ ] 簽章金鑰存儲在 HSM
- [ ] 金鑰輪換策略配置
- [ ] 存取控制配置

## 傳輸安全
- [ ] 強制 TLS 1.3
- [ ] 返回 chunk hash 供驗證
- [ ] 配置安全監控
```

---

## 附錄 A: 錯誤碼

| 錯誤碼 | 含義 | 處理方式 |
|--------|------|----------|
| DEK_EVIDENCE_MISMATCH | wrappedDek 與 evidenceId 不匹配 | 拒絕，記錄安全事件 |
| DEK_ALREADY_USED | DEK 已用於其他證據 | 拒絕，P0 告警 |
| INVALID_WRAPPING_KEY | KEK 無效或已撤銷 | 拒絕，檢查 KEK 狀態 |
| TIMESTAMP_OUT_OF_RANGE | 事件時間超出 session 範圍 | 拒絕或標記異常 |
| CHUNK_HASH_MISMATCH | 上傳 chunk hash 不一致 | 拒絕，P0 告警 |
| TLS_VERSION_REJECTED | 使用不支援的 TLS 版本 | 拒絕連線 |
| CERTIFICATE_PIN_FAILED | Certificate pinning 驗證失敗 | 拒絕連線 |

---

## 附錄 B: 相關規格

- [nonce-lifecycle.md](./nonce-lifecycle.md) - Nonce 安全規則
- [key-attestation-roots.md](./key-attestation-roots.md) - Key Attestation 政策
- [proof-state-machine.md](./proof-state-machine.md) - Proof 狀態定義
