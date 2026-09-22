# Apostille by IFF

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[網站](https://ifandonlyif.io/zh-hant/apostille) · [下載與安裝](https://ifandonlyif.io/zh-hant/apostille/downloads) · [Alpha 發佈](https://github.com/ifandonlyif-io/iff-apostille/releases/tag/v0.1.0-alpha.1)

為 agent 產物提供可攜、與 issuer 無關的簽章。Agent 簽署檔案 manifest，管理員授權其金鑰，issuer 記錄已執行的檢查。收件者可在本機查驗 bundle，不需要 IFF 帳號或網際網路連線。你可以使用 SDK，也可以依公開規格與相容性向量自行實作。

**目前為 Alpha。** Core protocol `0.1`、Go 模組版本 `v0.1.0-alpha.1` 與 SDK 套件版本 `0.1.0-alpha.1` 是不同的版本命名空間。Go root 模組（`apostille`、`apostille/client`、`util`）已發佈 `v0.1.0-alpha.1`；CLI 與 ZK 模組的標籤分別為 `cmd/apostille/v0.1.0-alpha.1`、`apostille/zkbudget/v0.1.0-alpha.1`。尚未發佈 npm 套件或預編譯 CLI 執行檔。Core 0.2 規格已通過審查，實作與向量仍待完成；詳見[路線圖](#roadmap)。

此版本包含 215 個共同相容性案例、Go/JavaScript differential 測試、fuzz 測試，以及未配對 Unicode surrogate 的處理修正。IFF 託管服務使用固定版本的公開 Go 模組。

## 誰該使用哪一種工具

- **收到 bundle 的收件者**：使用託管服務或本 repo 提供的瀏覽器查驗器，也可使用本機 CLI。兩者的查驗都不需要 IFF 帳號、金鑰查詢或網路連線。若已有 Go 工具鏈：

  ```sh
  go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
  ```

  將 `GOBIN`（未設定時為 `GOPATH/bin`）加入 `PATH`。依[CLI 查驗指引](docs/apostille/CLI.md)指定你獨立選定的 issuer/key pin；若信任條件不符時必須讓指令失敗，請加上 `--require-trusted`。
- **Go 開發者**：加入已發佈的模組。

  ```sh
  go get github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1
  ```

  API 參考：[pkg.go.dev](https://pkg.go.dev/github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1/apostille)。整合指引：[docs/apostille/SDK.md](docs/apostille/SDK.md)。
- **JavaScript 開發者**：依下方步驟，從這份 checkout 打包 SDK；registry 發佈另行規劃。
- **審查者與獨立實作者**：從規格、schema、相容性案例及 GitHub 標籤原始碼開始。

| 元件 | 原始碼 | 提供內容 |
| --- | --- | --- |
| Core 0.1 | [規格](docs/apostille/spec/core-0.1.md)、[schema](web/apostille-0.1.schema.json)、[vectors](testdata/apostille/core-0.1.json)、[cases](testdata/apostille/core-0.1-cases.json) | 確切位元組，以及接受／拒絕查驗案例 |
| Go | [core](apostille/)、[API client](apostille/client/) | 離線簽署與查驗；明確呼叫才會使用託管 API |
| JavaScript / TypeScript | [SDK](sdk/apostille-js/) | 預設 import 離線運作，另有獨立 `/client` 入口 |
| 本機 CLI | [指令](docs/apostille/CLI.md) | 金鑰產生、簽署、本機簽發與查驗 |
| 瀏覽器查驗器 | [原始碼](web/)、`make verifier` | 四語系本機查驗；不查詢金鑰、不使用 RPC 或遙測 |
| ERC-8004 profile | [規格](docs/apostille/spec/erc8004-binding-0.1.md) | 由 issuer 檢查的獨立歷史所有權證據 |
| 實驗性 ZK | [指引](docs/apostille/ZK.md)、[模組](apostille/zkbudget/) | 本機查驗已承諾預算的條件，僅支援 Go/CLI |

## 從原始碼試用

需要 Go 工具鏈 `go1.26.6`（各模組的最低語言版本見 `go.mod`）、Node.js 22 以上、npm、Python 3 與 make。首次建置會下載公開依賴；簽署與離線查驗不需要網路。

```sh
make check
make apostille-build
make verifier
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist/verifier
```

開啟 `http://127.0.0.1:8080/`。瀏覽器 ES modules 需要 HTTP origin，因此不支援 `file://`。頁面只使用本機資產，並套用 `connect-src 'none'`。匯入 bundle，以及由獨立來源取得的 issuer/key pin。瀏覽器不產生或查驗 ZK proof；請使用獨立的 CLI/Go 模組。

打包 JS SDK，但不發佈：

```sh
make sdk
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

詳見 [SDK 範例](sdk/apostille-js/README.md)、[Go 整合](docs/apostille/SDK.md)及[發佈指引](docs/apostille/RELEASE.md)。CLI 與 ZK 模組釘選已發佈的 root 模組，而非目前 checkout；root 的修改要等下一個 root tag 才會傳入。RELEASE.md 提供本機開發時的替代作法。

<a id="roadmap"></a>

## 路線圖

Core 0.2（[規格](docs/apostille/spec/core-0.2.md)、[schema](web/apostille-0.2.schema.json)）加入明確的識別字文法、嚴格 Ed25519 查驗與版本命名空間。規格已通過審查，但尚無參考實作或相容性向量，目前不得宣稱符合 0.2。[實作計畫](docs/apostille/proposals/core-0.2-implementation-plan.md)追蹤進度。JS SDK 的 npm 發佈與預編譯 CLI 執行檔也在規劃中，均不屬於 `v0.1.0-alpha.1`。

## 查驗結果代表什麼

有效簽章證明完整性與金鑰持有。接受 issuer 需要你自行指定、完全相符的 issuer/key pin。它不證明內容真實性、完整 bot 歷史、組織身分、目前未撤銷狀態、付款安全或法律效力。本專案不是海牙 Apostille 或政府認證。雜湊仍可用來識別或串聯紀錄；雜湊不等於匿名化。

ERC-8004 binding 回報 `issuer_checked` 的歷史觀測，目前所有權仍未知。ZK 證明的是已承諾輸入向量的某項條件，不證明上游資料完整或真實。單方開發用 setup 屬於實驗性質，尚無外部稽核，也不是正式環境的信任建立儀式。Coinbase verification、LEI/vLEI 與 Cloudflare Wallets 仍為規劃中的整合。

託管 API 實作、租戶資料庫、issuer 憑證與正式部署設定不包含在這次原始碼發佈中。[API 契約](docs/apostille/API.md)說明 client 整合介面，並非自行託管套件。這些 producer 紀錄不會匯入 IFF 的 x402 monitor、transparency log 或 reputation。

## 相關 IFF 專案

[iff-x402-transparency](https://github.com/ifandonlyif-io/iff-x402-transparency) 提供 x402 觀測、透明日誌與 Service Receipt 的公開查驗實作。[IFF Monitor](https://ifandonlyif.io/zh-hant/monitor) 是託管的端點監測服務。Apostille 簽署 producer 產物，各產品的聲明與信任政策維持分離。

## 參與專案

[貢獻指引](CONTRIBUTING.md) · [治理](GOVERNANCE.md) · [安全](SECURITY.md) · [相容性](docs/apostille/CONFORMANCE.md)

原創程式碼、規格、schema 與 vectors 採 MIT 授權；請保留既有著作權及[第三方 notices](docs/apostille/NOTICES.md)。合成 fixture 金鑰是公開測試資料，不可部署或信任。公開原始碼不證明託管伺服器實際執行哪個執行檔。
