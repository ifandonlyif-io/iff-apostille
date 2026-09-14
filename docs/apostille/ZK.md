# 企業內部 ZK budget 試用

這是可在企業內部執行的 **Go SDK／CLI 實驗功能**。部門可以證明來源已簽署的
支出向量合計沒有超過指定額度，接收部門不需要取得支出金額明細。
來源資料的真實性及 ERP 匯出完整性仍需企業治理；輸出明確保留這些限制。

第一版支援 1–16 筆、每筆 48-bit 非負整數金額；金額使用約定幣別的最小單位。
不支援負數沖銷、匯率轉換、任意 LLM 行為證明或即時預算扣款。
目前 Web console、瀏覽器查驗包與 JavaScript SDK **不執行 ZK 驗證**。
既有 Core 簽章驗證成功，不能代替這個 profile 的 ZK 與接收方政策檢查。

## 可重現的本機流程

以下全部是合成資料，沒有網路請求。需要 Go 1.25.7 以上；repository 的既有
toolchain 為 Go 1.26.6。`.apostille-private/` 同時由 Git 和 Docker 排除。
`mkdir` 及產生檔案的命令故意不覆寫舊資料；再次測試請選新的目錄名稱。
ZK SDK 與 CLI 各有獨立的 Go module；production 的 gnark-crypto 保持 0.18.1，
只有實驗模組使用 0.21.0。不要用 `go.work` 合併這三個 module 的依賴。

```bash
make apostille-build
mkdir -p .apostille-private
chmod 0700 .apostille-private
umask 077

./bin/apostille keygen --out .apostille-private/zk-source-key.json --role department-source
./bin/apostille zk-setup --development --out-dir .apostille-private/zk-setup
./bin/apostille zk-circuit

cat > .apostille-private/zk-amounts.json <<'JSON'
{"amounts":["12500","20000","37500"]}
JSON

./bin/apostille zk-snapshot \
  --amounts .apostille-private/zk-amounts.json \
  --key .apostille-private/zk-source-key.json \
  --agent-id aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --scope project-demo --currency USD \
  --period-start 2026-09-01T00:00:00Z --period-end 2026-09-14T00:00:00Z \
  --out-dir .apostille-private/zk-snapshot

./bin/apostille zk-request \
  --snapshot .apostille-private/zk-snapshot/snapshot.json \
  --policy-id budget-review-v1 --audience urn:example:audit --limit 70000 \
  --out .apostille-private/zk-request.json
```

`zk-request` 應由接收部門建立。它綁定已審閱的 snapshot、政策、額度、audience、
nonce 及 5 分鐘效期。請在有效期內執行下一步。將以下兩個占位符換成 setup
輸出的 verification-key hash，以及 source key 的 key ID；正式整合必須透過
獨立可信管道取得這兩個 pin，不能直接抄待驗 proof 裡的值。

```bash
./bin/apostille zk-prove \
  --private .apostille-private/zk-snapshot/private.json \
  --source-bundle .apostille-private/zk-snapshot/source-bundle.json \
  --request .apostille-private/zk-request.json \
  --proving-key .apostille-private/zk-setup/proving-key.bin \
  --verifying-key .apostille-private/zk-setup/verifying-key.bin \
  --vk-sha256 REPLACE_WITH_INDEPENDENT_VERIFICATION_KEY_SHA256 \
  --out .apostille-private/zk-proof.json

./bin/apostille zk-verify --offline \
  --proof .apostille-private/zk-proof.json \
  --request .apostille-private/zk-request.json \
  --verifying-key .apostille-private/zk-setup/verifying-key.bin \
  --vk-sha256 REPLACE_WITH_INDEPENDENT_VERIFICATION_KEY_SHA256 \
  --source-key-id REPLACE_WITH_INDEPENDENT_SOURCE_KEY_ID
```

只將 `zk-proof.json`、公開 verification key 與接收方已核定的 request 帶到
查驗環境。`private.json`、原始金額、source 私鑰及 blinding 留在原部門。
接收方不需要 proving key。`zk-snapshot --registration` 可取代 `--agent-id`，
沿用既有 administrator delegation；兩個參數只能擇一。

若需要額外的 issuer 認證，可使用既有 Core 發證流程為這份 snapshot 的
statement 簽發 certificate，再把得到的 bundle 傳給 `zk-prove --source-bundle`。
驗證時必須一起傳 `--issuer` 與 `--issuer-key-id`。證明綁定完整 source bundle，
事後增加或替換 certificate 需要重新產生 proof。

`zk-verify` 成功輸出有 `valid: true`，proof／政策驗證失敗則有 `valid: false`。
兩者都記錄 `evaluated_at`。指定 `--at` 會記錄換算為 UTC 整秒的歷史評估時間，
不能把歷史通過結果當作現在仍可行動的授權。

`zk-circuit` 不產生 setup，會輸出本機電路的 `circuit_sha256`、constraint 數與
public input 數。可以比對 `parameters.json` 的指紋來稽核相同版本的重編譯結果；
這不能證明別人給的 verification key 確實出自該電路，獨立 VK pin 仍是必要條件。

目前 circuit ID 是 `budget-16x48-mimc-bls12381-v2`，有 9,867 個 constraints、
9 個 public inputs。未發佈的 v1 測試參數與 proof 不相容；若已有 v1 本機資料，
請重新建立 snapshot／來源簽章、request、setup 與 pin。Core 0.1 簽章格式沒有改變。

## Go SDK

Import `github.com/ifandonlyif-io/iff-apostille/apostille/zkbudget`。
`NewSnapshot`／`SignSnapshot` 建立來源簽署的公開承諾與私有 witness；
`NewRequest` 建立接收方的政策；`NewProver`／`Prove` 產生真實 Groth16 proof。
套件初始化時會關閉**整個 process 的 gnark logger**，避免 compile／prove／verify
在 stdout 的 JSON 前插入進度訊息。若整合程式也使用 gnark 且需要 logging，
只能在啟動、尚未執行任何並行工作前以 `gnark/logger.Set` 明確配置；不要在每次
呼叫前後切換全域 logger。solver 的 witness logging 仍保持關閉。

```go
verifier, err := zkbudget.NewVerifier(localVerificationKey, independentKeySHA256)
if err != nil { return err }
result, err := verifier.VerifyJSON(presentationJSON, zkbudget.VerifyOptions{
    ExpectedRequest: receiverApprovedRequest,
    TrustedSourceKeyIDs: []string{departmentSourceKeyID},
    Now: time.Now(),
})
if err != nil { return err }
// result.ProofIntegrity == "valid" and result.Predicate == "sum_within_limit".
// result.EvaluatedAt records the exact UTC evaluation time supplied above.
// Consume the request nonce in your workflow before performing a one-time action.
```

此 SDK 不讀取環境變數、不載入私鑰、不連 RPC 或 API，亦不自行抓取 pin。
`Verify` 接受已解析的 `Document`；`VerifyJSON` 額外檢查完整 JSON 形狀及大小。
接收方仍需管理自己的 nonce 使用紀錄、授權政策及資料來源。
模組安裝與獨立測試方式見 [SDK 文件](SDK.md#experimental-local-zk-budget-sdk)。

## 上線前提

`zk-setup --development` 是單方 trusted setup。保留其秘密參數的惡意操作者
可能偽造證明；目前沒有 ceremony 或獨立資安稽核。這版適合用合成資料評估
流程與效能，不能宣稱企業正式付款授權已完成。不同部門的資料完整性、簽署
責任與 proof 查詢規則，也必須先由企業決定。

公開 scope、period、筆數、source key、snapshot hash 與額度仍能串聯紀錄。
重複查詢不同門檻可能逼近總額；此 profile 隱藏金額，沒有匿名身分或不可串聯
保證。ERC-8004、上鏈、public visibility 都不會因產生 ZK proof 而自動啟用。

精確欄位、電路、proof bytes 與結果語意見 [英文規格](spec/zk-budget-0.1.md)。
