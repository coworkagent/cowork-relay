# Cowork Relay

[English](README.md)

`cowork-relay` 是可自行部署的 Cowork 连接中继，让手机和电脑在不同网络下连接。
电脑主动向中继建立出站连接，无需把电脑的局域网端口暴露到互联网。一个实例可以
服务多台电脑和手机，每个设备使用独立凭据，每份客户端登记明确绑定一台电脑。

当前为开发候选：中继服务和 CLI 已实现，桌面与手机应用的接入仍在进行。
已发布的应用不能仅靠填写该 URL 使用中继。目前没有发布二进制或容器镜像。

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
默认有效期为 30 天，`--days` 可选 1–90 天。当前没有自动续期；应在过期前重新登记。
重新登记电脑会生成新 ID，客户端也需要重新登记并绑定该 ID。

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

自动生成的叶证书有效期为一年，私有 CA 为十年。停服后执行以下命令并重启，可以在原 CA 下续签叶证书。
续签需要 `ca-key.pem`，应保存加密的离线备份。公开 CA 指纹不变，已导入的信任可继续使用。

```sh
cowork-relay --data-dir ./relay-state renew-ip
```

续签先写入新私钥和证书，再原子切换配置；旧证书文件留在私有目录，由管理员按需清理。
域名证书通过原证书服务续签后重启。CA 泄漏、过期或服务器 IP 改变时，应新建身份，明确分发并核对新的信任材料。
安全备份私有状态；恢复旧登记表可能撤销后来的禁用操作。不要复制运行中的登记表到第二个服务实例。

`GET /health/live` 通过已验证 HTTPS 返回最小进程健康状态，不暴露设备数据。TLS 密钥和配置在启动时读取。
SIGINT／SIGTERM 会关闭连接，服务恢复后客户端可以重连。

[deploy](deploy/) 提供容器和 systemd 模板。使用前应调整路径和网络配置；这些示例不会自动执行公网部署。
