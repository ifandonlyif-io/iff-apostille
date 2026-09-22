# Apostille by IFF

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[Web サイト](https://ifandonlyif.io/ja/apostille) · [ダウンロード・インストール](https://ifandonlyif.io/ja/apostille/downloads) · [Alpha リリース](https://github.com/ifandonlyif-io/iff-apostille/releases/tag/v0.1.0-alpha.1)

Agent が生成したファイルに、持ち運べる issuer 非依存の署名を付けます。Agent がファイルの manifest に署名し、管理者がその鍵に権限を委任し、issuer が実施した確認を記録します。受信者は IFF アカウントやインターネット接続なしで bundle をローカル検証できます。SDK を利用するほか、公開仕様と適合性テストベクトルに基づく独自実装も可能です。

**Alpha 版です。** Core protocol `0.1`、Go module のリリース `v0.1.0-alpha.1`、SDK package の `0.1.0-alpha.1` は別のバージョン体系です。Go root module（`apostille`、`apostille/client`、`util`）は `v0.1.0-alpha.1` として公開済みです。CLI と ZK module のタグは、それぞれ `cmd/apostille/v0.1.0-alpha.1` と `apostille/zkbudget/v0.1.0-alpha.1` です。npm package とビルド済み CLI binary は未公開です。Core 0.2 は仕様が承認済みですが、実装とテストベクトルはまだありません。[ロードマップ](#roadmap)を参照してください。

このリリースには、215 件の共通適合性テストケース、Go/JavaScript 差分テスト、fuzz テスト、未対の Unicode surrogate 処理の修正が含まれます。IFF の hosted service は、この公開 Go リリースをバージョン固定で利用しています。

## 用途別の入口

- **Bundle の受信者**：hosted service またはこの repository の browser verifier、あるいはローカル CLI を利用します。どちらの検証も IFF アカウント、鍵の問い合わせ、ネットワーク接続を必要としません。Go toolchain があれば、次のコマンドで CLI をインストールできます。

  ```sh
  go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
  ```

  `GOBIN`（未設定なら `GOPATH/bin`）を `PATH` に追加してください。[CLI 検証ガイド](docs/apostille/CLI.md)に従い、独立して選んだ issuer/key pin を指定します。信頼条件の不一致でコマンドを失敗させる場合は `--require-trusted` を使用してください。
- **Go 開発者**：公開済み module を導入します。

  ```sh
  go get github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1
  ```

  API reference：[pkg.go.dev](https://pkg.go.dev/github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1/apostille)。統合ガイド：[docs/apostille/SDK.md](docs/apostille/SDK.md)。
- **JavaScript 開発者**：以下の手順で、この checkout から SDK package を作成します。Registry への公開は別途予定しています。
- **レビュアー・独立実装の開発者**：仕様、schema、適合性テストケース、GitHub のタグ付きソースから始めてください。

| 構成要素 | ソース | 提供するもの |
| --- | --- | --- |
| Core 0.1 | [仕様](docs/apostille/spec/core-0.1.md)、[schema](web/apostille-0.1.schema.json)、[vectors](testdata/apostille/core-0.1.json)、[cases](testdata/apostille/core-0.1-cases.json) | 正確な bytes と、受理・拒否の検証ケース |
| Go | [core](apostille/)、[API client](apostille/client/) | オフライン署名・検証と、明示的に呼び出す hosted API |
| JavaScript / TypeScript | [SDK](sdk/apostille-js/) | オフラインの default import と、独立した `/client` entry |
| ローカル CLI | [コマンド](docs/apostille/CLI.md) | 鍵生成、署名、ローカル発行、検証 |
| Browser verifier | [ソース](web/)、`make verifier` | 4 言語のローカル検証。鍵の問い合わせ、RPC、telemetry は行いません |
| ERC-8004 profile | [仕様](docs/apostille/spec/erc8004-binding-0.1.md) | Issuer が確認した過去の所有権を示す、独立した証拠 |
| 実験的 ZK | [ガイド](docs/apostille/ZK.md)、[module](apostille/zkbudget/) | Commitment 済み予算の条件をローカル検証。Go/CLI のみ |

## ソースから試す

必要なもの：Go toolchain `go1.26.6`（言語の最低バージョンは各 `go.mod` を参照）、Node.js 22 以上、npm、Python 3、make。初回ビルドでは公開依存関係をダウンロードします。署名とオフライン検証にはネットワークが不要です。

```sh
make check
make apostille-build
make verifier
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist/verifier
```

`http://127.0.0.1:8080/` を開きます。Browser ES modules には HTTP origin が必要なため、`file://` は非対応です。ページはローカル資産のみを使い、`connect-src 'none'` を適用します。Bundle と、独立して取得した issuer/key pin を読み込んでください。Browser は ZK proof の生成・検証に対応していません。別の CLI/Go module を使用します。

公開せずに JS SDK package を作成するには：

```sh
make sdk
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

[SDK の例](sdk/apostille-js/README.md)、[Go 統合](docs/apostille/SDK.md)、[リリース手順](docs/apostille/RELEASE.md)を参照してください。CLI と ZK module は、この checkout ではなく公開済み root module に固定されています。Root の変更が反映されるのは次の root tag の公開時です。ローカル開発時の方法は RELEASE.md にあります。

<a id="roadmap"></a>

## ロードマップ

Core 0.2（[仕様](docs/apostille/spec/core-0.2.md)、[schema](web/apostille-0.2.schema.json)）は、厳密な識別子文法、厳格な Ed25519 検証、バージョン付き namespace を追加します。仕様は承認済みですが、reference implementation と適合性テストベクトルは未提供です。現時点で 0.2 準拠を主張できる実装はありません。[実装計画](docs/apostille/proposals/core-0.2-implementation-plan.md)で状態を管理しています。JS SDK の npm 公開とビルド済み CLI binary も予定していますが、いずれも `v0.1.0-alpha.1` には含まれません。

## 検証結果の意味

有効な署名は、データの完全性と鍵の所持を示します。Issuer を受け入れるには、自分で定めた完全一致の issuer/key pin が必要です。内容の真実性、bot の完全な履歴、組織の身元、現在の未失効、支払いの安全性、法的効力は証明しません。このプロジェクトはハーグ条約のアポスティーユや政府の認証ではありません。Hash でも記録の識別・関連付けが可能なため、hash 化は匿名化ではありません。

ERC-8004 binding は `issuer_checked` の過去の観測を報告し、現在の所有権は不明のままです。ZK が証明するのは commitment 済み入力ベクトルについての条件であり、上流データの完全性や真実性ではありません。単独の運用者による開発用 setup は実験的で、外部監査も本番用の信頼確立 ceremony も実施していません。Coinbase verification、LEI/vLEI、Cloudflare Wallets は予定段階です。

Hosted API の実装、tenant database、issuer credentials、本番デプロイ設定は、このソース公開には含まれません。[API contract](docs/apostille/API.md)は client の統合仕様であり、self-hosting package ではありません。これらの producer record は、IFF の x402 monitor、transparency log、reputation に取り込まれません。

## 関連する IFF プロジェクト

[iff-x402-transparency](https://github.com/ifandonlyif-io/iff-x402-transparency) は、x402 観測、transparency log、Service Receipt の公開検証機能を提供します。[IFF Monitor](https://ifandonlyif.io/ja/monitor) は hosted endpoint monitoring service です。Apostille は producer artifact に署名し、それぞれの製品の主張と信頼ポリシーは分離されています。

## 参加する

[貢献方法](CONTRIBUTING.md) · [ガバナンス](GOVERNANCE.md) · [セキュリティ](SECURITY.md) · [適合性](docs/apostille/CONFORMANCE.md)

独自のコード・仕様・schema・vectors は MIT License です。既存の著作権表示と[第三者 notices](docs/apostille/NOTICES.md)を保持してください。合成 fixture の鍵は公開テスト用です。本番で使用したり、信頼したりしないでください。ソースの公開だけでは、hosted server で実行される binary は証明できません。
