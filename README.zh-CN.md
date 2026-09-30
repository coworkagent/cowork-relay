# Cowork Relay

[English](README.md)

`cowork-relay` 是可自行部署的 Cowork 连接中继，让手机和电脑在不同网络下连接。
电脑主动向中继建立出站连接，无需把电脑的局域网端口暴露到互联网。一个实例可以
服务多台电脑和手机，每个设备使用独立凭据，每份客户端登记明确绑定一台电脑。

**0.1.1** 提供中继服务和本机管理 CLI。使用时需要支持中继的 Cowork 桌面与手机客户端，
电脑还需匹配的远程服务组件；桌面 0.15.0 及更早版本不能仅填写 URL 就使用中继。
只更新手机不会更新电脑。本地和模拟器检查不代表真实公网部署已通过验收。
容器镜像通过仓库提供的 Dockerfile 在本地构建。

## 下载与安装

从 [0.1.1 发布页](https://github.com/coworkagent/cowork-relay/releases/tag/v0.1.1)
下载对应压缩包和 `SHA256SUMS`。

| 平台 | 压缩包 | 运行要求 |
| --- | --- | --- |
| Linux x64 | `cowork-relay-0.1.1-linux-x64.tar.gz` | 静态 musl；不依赖系统 libc |
| Linux ARM64 | `cowork-relay-0.1.1-linux-arm64.tar.gz` | 静态 musl；不依赖系统 libc |
| macOS Intel | `cowork-relay-0.1.1-darwin-x64.tar.gz` | macOS 12+ |
| macOS Apple Silicon | `cowork-relay-0.1.1-darwin-arm64.tar.gz` | macOS 12+ |

按服务器架构选择。从 0.1.1 起，Linux 下载包静态链接 musl，可用于 glibc 和 musl 发行版，
不需要升级 libc 或另行安装 musl。旧版 0.1.0 下载包仍动态链接 glibc，不包含这项兼容修复。
CI 在原生 Ubuntu 24.04 上运行发布二进制，并在 Ubuntu 20.04 与 Alpine 3.22 用户空间
检查启动和本机管理。容器共享构建机器的内核，这不代表所有旧内核都已通过验证。
Mac 二进制用于开发验证，未进行 Developer ID 公证。当前不提供原生
Windows 二进制，因为本机管理依赖 Unix socket 和文件权限；可使用 Linux 服务器或虚拟机。

```sh
# Linux 校验；macOS 使用 shasum -a 256 计算压缩包摘要，与清单对应行比较。
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf cowork-relay-0.1.1-linux-x64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 0755 cowork-relay-0.1.1-linux-x64/cowork-relay "$HOME/.local/bin/cowork-relay"
"$HOME/.local/bin/cowork-relay" --version
```

压缩包包含双语指南和部署模板。状态目录应独立于安装目录；从已认证的发布来源取得
校验和，校验和本身不证明发布者身份。升级时先停服、备份私有状态，再替换可执行文件，
不要对原状态目录重新初始化。

## 连接电脑和手机

1. 按下文选择一种信任方式，初始化并启动中继。
2. 创建电脑登记，再创建指向该电脑的手机登记，私下将 `computer.json` 和 `phone.json`
   分别交付对应设备。
3. 在电脑的远程控制设置中导入登记，核对中继地址和 CA 指纹，开启互联网连接。
4. 手机导入中继登记并确认同一服务器身份。信任仅对该中继生效，不安装到系统信任库。
5. 电脑为所需项目、操作和互联网访问生成配对邀请；手机扫描或导入，两端核对六位验证码，
   最后在电脑批准。

中继客户端要求 iOS 17+ 或 Android 10+；应用支持的较旧系统仍可使用局域网连接。
每份手机登记只指向一台电脑，连接其他电脑需导入对应登记。可用局域网连接优先使用。
电脑身份变更需要明确重新配对；同一已保存 CA 下的叶证书更新可通过签名证明安全恢复。

## 安全与兼容性

- 公网入口只接受 TLS 1.3。域名使用有效的 HTTPS 证书；IP 可自动生成私有 CA 和
  包含 IP SAN 的证书。IP 模式必须把公开 CA 导入应用专用信任库，并校验证书中的 IP。
  不支持关闭证书验证。
- 手机与电脑之间的 TLS 在中继连接内部运行。中继只转发加密字节；业务凭据、消息、
  文件和授权由已配对端点处理。中继可看到来源 IP、设备 ID、时间和字节数，也可以断流。
- 每份客户端凭据只允许访问同一组内指定的电脑。设备密钥为随机 256 位值，登记表只
  保存哈希。登记文件包含密钥，必须私下传送给对应应用。
- 管理接口仅使用本机 Unix socket；目录权限为 `0700`，socket 与状态文件为 `0600`。
  没有公网管理 API。
- 不提供通用上网代理、SOCKS、任意 CONNECT 目标、Agent 执行或项目授权。电脑端仍然
  验证配对、权限和每次业务请求。

服务面向 Linux，macOS 可用于原生开发验证；未实现 Windows 原生服务管理。
需要服务器拥有可达 IP、允许入站的 TCP 端口，且两端可出站访问。位于运营商 NAT 后、
没有入站转发的 IP 不足以部署公网中继。当前每个状态目录只支持一个进程，多个副本不共享
在线设备状态。请直接使用 TLS 监听器或 TCP 透传负载均衡，不要放在普通 HTTP 反向代理后。

## 构建与检查

安装 `rust-toolchain.toml` 指定的 Rust 工具链，然后执行：

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
npm ci
npm run test:acceptance
```

最后一项需要 Node.js 22.12+ 和 OpenSSL，仅使用合成设备及回环地址。
Rust 生产服务不依赖 Node.js 或 OpenSSL。二进制位于 `target/release/cowork-relay`。
Linux 默认源码构建使用本机 libc，并不是通用发布构建。

在对应架构的 Ubuntu/Debian 机器上安装 `musl-tools`，使用 `rustup target add` 添加
`x86_64-unknown-linux-musl` 或 `aarch64-unknown-linux-musl`，然后通过
`CC=musl-gcc cargo build --release --locked --target TARGET` 构建；还需像
[工作流](.github/workflows/build.yml)一样将对应 Cargo target 的 linker 设置为 `musl-gcc`。

GitHub Actions 为四个平台运行格式、Clippy、Rust 测试及公开验收。Linux ELF 检查
拒绝依赖动态加载器或共享库的二进制。PR、main 更新和手动运行会生成可下载产物；
推送与包版本一致的 `vX.Y.Z` 标签后，只有全部平台通过才会新建 Release，不覆盖已有发布。
压缩包内的 `BUILD.json` 记录源码提交、目标平台和二进制摘要。打包实现见
[工作流](.github/workflows/build.yml)和 `scripts/`。Mac 构建设置 macOS 12 部署目标，
CI 实际运行系统为 macOS 15。

## 初始化 IP 服务

将 `203.0.113.10` 替换为服务器的实际可达 IP。有防火墙端口转发时，公网端口可以与监听端口不同。

```sh
umask 077
cowork-relay --data-dir ./relay-state init-ip \
  --ip 203.0.113.10 --port 8443 --listen 0.0.0.0:8443
cowork-relay --data-dir ./relay-state trust-export --out ./relay-trust.json
cowork-relay --data-dir ./relay-state serve
```

初始化只接受新的空私有目录，不覆盖已有身份。未明确指定时默认监听 `127.0.0.1:8443`。
`relay-trust.json` 只包含地址、公开 CA 和 SHA-256 指纹；导入前应通过可信渠道核对指纹。
从未验证的网络连接下载 CA 并直接信任，不能证明服务器身份。不要分发 `ca-key.pem` 或任何服务器私钥。

## 初始化域名服务

先向客户端信任的 CA 申请证书并取得完整证书链。私钥应为 `0600`，由服务账号读取。

```sh
cowork-relay --data-dir ./relay-state init-domain \
  --origin https://relay.example.com:8443 --listen 0.0.0.0:8443 \
  --certificate /absolute/path/fullchain.pem \
  --private-key /absolute/path/privkey.pem
cowork-relay --data-dir ./relay-state serve
```

服务检查证书有效期、SAN 和私钥匹配；客户端仍须通过平台信任库验证证书链。
向 `init-domain` 提供不受信任的证书，不会使客户端自动信任它。

## 管理设备

服务运行期间，在服务器本机以服务账号执行这些命令，使用相同的 `--data-dir`。
`--json` 输出结构化数据，`--lang zh-CN` 选择中文输出；帮助同时提供中英文。

```sh
cowork-relay --data-dir ./relay-state devices add-host \
  --name workstation --group personal --credential-out ./computer.json
cowork-relay --data-dir ./relay-state devices add-client \
  --name phone --group personal --host HOST_DEVICE_ID \
  --credential-out ./phone.json
cowork-relay --data-dir ./relay-state status
cowork-relay --data-dir ./relay-state devices list
cowork-relay --data-dir ./relay-state devices inspect DEVICE_ID
cowork-relay --data-dir ./relay-state connections
cowork-relay --data-dir ./relay-state devices kick DEVICE_ID
cowork-relay --data-dir ./relay-state devices disable DEVICE_ID
cowork-relay --data-dir ./relay-state devices enable DEVICE_ID
```

登记命令在 stdout 输出公开设备 ID，密钥仅写入新建的 `0600` 凭据文件，不覆盖已有文件。
请把每份凭据私下传给对应端点，删除服务器上不必要的副本，不把密钥放入命令行参数或日志。
默认有效期为 30 天，`--days` 可选 1–90 天。默认开启自动续期。
使用 `devices renew` 可以保留原身份手动续期；新建登记时传 `--auto-renew false` 可改为固定有效期。

| 命令 | 效果 |
| --- | --- |
| `kick` | 断开当前控制／数据连接并取消等待中的票据；原凭据仍可重连。 |
| `disable` | 持久保存禁用状态，断开并拒绝后续访问；重启后仍生效。 |
| `enable` | 重新允许原凭据使用，但不会延长有效期。 |

禁用或踢掉电脑会断开它的手机中继连接；这不会撤销局域网配对，也不会取消电脑已接受的 Agent 任务。
需要撤销业务访问时，应在电脑端撤销设备授权。

## 容量、证书与运维

`config.json` 支持有界容量配置：默认最多 512 个网络 socket、128 台在线电脑、总共 256 条数据流，
每台电脑 32 条、每份客户端登记 8 条。每条数据流占手机和电脑各一个 socket，控制连接也计入总数。
另限制最多 64 个并行 TLS／HTTP 接入握手。停服修改配置后重启。CLI 提供本机管理，不是持久审计日志。

数据消息上限为 64 KiB；90 秒无字节传输时断开，每条连接最长一小时。
客户端重连后必须核对命令状态，不能盲目重放执行结果不确定的操作。

自动生成的叶证书有效期为一年，私有 CA 为十年。IP 叶证书默认提前自动续签。需要手动续签时，停服后执行以下命令并重启，可以在原 CA 下续签叶证书。
续签需要 `ca-key.pem`，应保存加密的离线备份。公开 CA 指纹不变，已导入的信任可继续使用。

```sh
cowork-relay --data-dir ./relay-state renew-ip
```

续签先写入新私钥和证书，再原子切换配置；旧证书文件留在私有目录，由管理员按需清理。
域名证书通过原证书服务续签后，运行中的服务在一分钟内重新加载有效的新证书。CA 泄漏、过期或服务器 IP 改变时，应新建身份，明确分发并核对新的信任材料。
安全备份私有状态；恢复旧登记表可能撤销后来的禁用操作。不要复制运行中的登记表到第二个服务实例。

`GET /health/live` 通过已验证 HTTPS 返回最小进程健康状态，不暴露设备数据。TLS 证书与密钥支持重新加载，其余运行配置在启动时读取。
SIGINT／SIGTERM 会关闭连接，服务恢复后客户端可以重连。

[deploy](deploy/) 提供容器和 systemd 模板。使用前应调整路径和网络配置；这些示例不会自动执行公网部署。

## 过期时间与自动续期

新建电脑、手机登记默认自动续期。服务器在到期前延长有效期，也会在服务重启后
按已保存的自动续期策略恢复，不改变设备 ID、秘密、分组或绑定电脑。升级时只给
仍启用且未过期的旧登记开启默认续期；过期、禁用的旧登记不自动恢复。禁用始终
优先。登记文件中的日期是导出时的快照；新版客户端连接时由中继核验实时状态。

```sh
cowork-relay --data-dir ./relay-state devices renew DEVICE_ID --days 30
cowork-relay --data-dir ./relay-state devices auto-renew DEVICE_ID --enabled false
cowork-relay --data-dir ./relay-state devices auto-renew DEVICE_ID --enabled true
```

`renew` 保证有效期至少覆盖从现在起指定的天数（1–90 天），保留原秘密和绑定，
不会启用已禁用设备。过期登记先手动续期，再开启自动策略。新建 `add-host`、
`add-client` 时可传 `--auto-renew false` 使用固定有效期；`--days` 设置续期周期。
`devices inspect`、`devices list` 显示 `expiresAt`、`autoRenew`、`renewalDays`。
停止访问使用 `disable`；`kick` 只断开当前连接，不阻止续期和重连。

自动生成的 IP 叶证书默认在到期前 30 天续签，并供新连接加载，已有隧道继续工作。
CA 和地址保持不变，无需重新导入登记。私有配置的 `autoRenewCertificate` 设为
`false` 可关闭。域名证书仍由证书提供方或 ACME 客户端续签，中继每分钟重新加载
有效的新证书。`status` 显示当前加载证书的到期时间和自动续期设置。私有根证书
不会自动替换；根即将到期时，需要管理员处理并重新分发信任登记。保留私有 CA
签名密钥，并严格限制状态目录权限。

请配套升级支持续期的桌面端、手机端和 Server `0.0.6-renewal.0` 或更新版本。
本节描述尚未发布的源码，现有发行版及 TestFlight 不会自动获得功能。升级前停服
备份私有状态；新版登记格式不能被旧中继读取，回滚需同时恢复旧二进制和匹配备份。
