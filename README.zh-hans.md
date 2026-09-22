# Apostille by IFF

[English](README.md) · [日本語](README.ja.md) · [繁體中文](README.zh-hant.md) · [简体中文](README.zh-hans.md)

[网站](https://ifandonlyif.io/zh-hans/apostille) · [下载与安装](https://ifandonlyif.io/zh-hans/apostille/downloads) · [Alpha 发布](https://github.com/ifandonlyif-io/iff-apostille/releases/tag/v0.1.0-alpha.1)

为 agent 产物提供可携带、不绑定特定 issuer 的签名。Agent 签署文件 manifest，管理员授权其密钥，issuer 记录已执行的检查。接收者可在本地验证 bundle，无需 IFF 账号或互联网连接。你可以使用 SDK，也可以依照公开规范与兼容性向量自行实现。

**目前为 Alpha。** Core protocol `0.1`、Go 模块版本 `v0.1.0-alpha.1` 与 SDK 软件包版本 `0.1.0-alpha.1` 属于不同的版本命名空间。Go root 模块（`apostille`、`apostille/client`、`util`）已发布 `v0.1.0-alpha.1`；CLI 与 ZK 模块的标签分别为 `cmd/apostille/v0.1.0-alpha.1`、`apostille/zkbudget/v0.1.0-alpha.1`。尚未发布 npm 软件包或预编译 CLI 可执行文件。Core 0.2 规范已通过审查，实现与向量仍待完成；详见[路线图](#roadmap)。

此版本包含 215 个共同兼容性案例、Go/JavaScript differential 测试、fuzz 测试，以及未配对 Unicode surrogate 的处理修复。IFF 托管服务使用固定版本的公开 Go 模块。

## 按用途选择工具

- **收到 bundle 的接收者**：使用托管服务或本仓库提供的浏览器验证器，也可使用本地 CLI。两者的验证都无需 IFF 账号、密钥查询或网络连接。若已安装 Go 工具链：

  ```sh
  go install github.com/ifandonlyif-io/iff-apostille/cmd/apostille@v0.1.0-alpha.1
  ```

  将 `GOBIN`（未设置时为 `GOPATH/bin`）加入 `PATH`。依照 [CLI 验证指南](docs/apostille/CLI.md)指定独立选定的 issuer/key pin；若信任条件不符时必须让命令失败，请加上 `--require-trusted`。
- **Go 开发者**：添加已发布的模块。

  ```sh
  go get github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1
  ```

  API 参考：[pkg.go.dev](https://pkg.go.dev/github.com/ifandonlyif-io/iff-apostille@v0.1.0-alpha.1/apostille)。集成指南：[docs/apostille/SDK.md](docs/apostille/SDK.md)。
- **JavaScript 开发者**：按下方步骤，从此 checkout 打包 SDK；registry 发布另行规划。
- **审查者与独立实现者**：从规范、schema、兼容性案例及 GitHub 标签源代码开始。

| 组件 | 源代码 | 提供内容 |
| --- | --- | --- |
| Core 0.1 | [规范](docs/apostille/spec/core-0.1.md)、[schema](web/apostille-0.1.schema.json)、[vectors](testdata/apostille/core-0.1.json)、[cases](testdata/apostille/core-0.1-cases.json) | 确切字节，以及接受／拒绝验证案例 |
| Go | [core](apostille/)、[API client](apostille/client/) | 离线签名与验证；显式调用才会使用托管 API |
| JavaScript / TypeScript | [SDK](sdk/apostille-js/) | 默认 import 离线运行，另有独立 `/client` 入口 |
| 本地 CLI | [命令](docs/apostille/CLI.md) | 密钥生成、签名、本地签发与验证 |
| 浏览器验证器 | [源代码](web/)、`make verifier` | 四种语言的本地验证；不查询密钥、不使用 RPC 或遥测 |
| ERC-8004 profile | [规范](docs/apostille/spec/erc8004-binding-0.1.md) | 由 issuer 检查的独立历史所有权证据 |
| 实验性 ZK | [指南](docs/apostille/ZK.md)、[模块](apostille/zkbudget/) | 本地验证已承诺预算的条件，仅支持 Go/CLI |

## 从源代码试用

需要 Go 工具链 `go1.26.6`（各模块的最低语言版本见 `go.mod`）、Node.js 22 及以上、npm、Python 3 与 make。首次构建会下载公开依赖；签名与离线验证无需网络。

```sh
make check
make apostille-build
make verifier
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist/verifier
```

打开 `http://127.0.0.1:8080/`。浏览器 ES modules 需要 HTTP origin，因此不支持 `file://`。页面仅使用本地资源，并应用 `connect-src 'none'`。导入 bundle，以及从独立来源取得的 issuer/key pin。浏览器不生成或验证 ZK proof；请使用独立的 CLI/Go 模块。

打包 JS SDK，但不发布：

```sh
make sdk
mkdir -p dist
npm pack ./sdk/apostille-js --pack-destination ./dist
```

详见 [SDK 示例](sdk/apostille-js/README.md)、[Go 集成](docs/apostille/SDK.md)及[发布指南](docs/apostille/RELEASE.md)。CLI 与 ZK 模块固定使用已发布的 root 模块，而非当前 checkout；root 的修改要等下一个 root tag 才会传入。RELEASE.md 提供本地开发时的替代方法。

<a id="roadmap"></a>

## 路线图

Core 0.2（[规范](docs/apostille/spec/core-0.2.md)、[schema](web/apostille-0.2.schema.json)）加入明确的标识符语法、严格 Ed25519 验证与版本命名空间。规范已通过审查，但尚无参考实现或兼容性向量，目前不得宣称符合 0.2。[实现计划](docs/apostille/proposals/core-0.2-implementation-plan.md)跟踪进度。JS SDK 的 npm 发布与预编译 CLI 可执行文件也在规划中，均不属于 `v0.1.0-alpha.1`。

## 验证结果代表什么

有效签名证明完整性与密钥持有。接受 issuer 需要你自行指定、完全匹配的 issuer/key pin。它不证明内容真实性、完整 bot 历史、组织身份、当前未撤销状态、支付安全或法律效力。本项目不是海牙 Apostille 或政府认证。哈希仍可用于识别或关联记录；哈希不等于匿名化。

ERC-8004 binding 报告 `issuer_checked` 的历史观测，当前所有权仍未知。ZK 证明的是已承诺输入向量的某项条件，不证明上游数据完整或真实。单方开发用 setup 属于实验性质，尚无外部审计，也不是生产环境的信任建立仪式。Coinbase verification、LEI/vLEI 与 Cloudflare Wallets 仍为规划中的集成。

托管 API 实现、租户数据库、issuer 凭证与生产部署配置不包含在此次源代码发布中。[API 契约](docs/apostille/API.md)说明 client 集成接口，并非自行托管软件包。这些 producer 记录不会导入 IFF 的 x402 monitor、transparency log 或 reputation。

## 相关 IFF 项目

[iff-x402-transparency](https://github.com/ifandonlyif-io/iff-x402-transparency) 提供 x402 观测、透明日志与 Service Receipt 的公开验证实现。[IFF Monitor](https://ifandonlyif.io/zh-hans/monitor) 是托管的端点监测服务。Apostille 签署 producer 产物，各产品的声明与信任策略保持分离。

## 参与项目

[贡献指南](CONTRIBUTING.md) · [治理](GOVERNANCE.md) · [安全](SECURITY.md) · [兼容性](docs/apostille/CONFORMANCE.md)

原创代码、规范、schema 与 vectors 采用 MIT 许可；请保留现有版权及[第三方 notices](docs/apostille/NOTICES.md)。合成 fixture 密钥是公开测试数据，不可部署或信任。公开源代码不证明托管服务器实际运行哪个可执行文件。
