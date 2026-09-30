# Deployment templates / 部署模板

Read the root README for trust and credential handling. Replace the documentation
IP below with your public IP. / 先阅读根目录 README 的信任与凭据说明，将示例 IP 替换为公网 IP。

## Docker Compose

```sh
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml run --rm relay init-ip \
  --ip 203.0.113.10 --port 8443 --listen 0.0.0.0:8443
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml exec relay \
  cowork-relay --data-dir /data status
docker compose -f deploy/compose.yaml exec relay \
  cowork-relay --data-dir /data trust-export --out /data/relay-trust.json
umask 077
docker compose -f deploy/compose.yaml cp relay:/data/relay-trust.json ./relay-trust.json
```

Use `exec relay cowork-relay --data-dir /data devices ...` for administration.
Registration outputs must be inside `/data` in this read-only container. Copy
each credential file privately to its endpoint and remove unnecessary copies.
Never remove the data volume during a routine upgrade. Initialize only once.

管理命令使用 `exec relay cowork-relay --data-dir /data devices ...`。
容器根文件系统只读，凭据输出路径须位于 `/data`。把凭据文件私下复制到对应端点，删除不必要副本。
普通升级不要删除数据卷；初始化只执行一次。

For renewal: stop the service, run `docker compose -f deploy/compose.yaml run --rm relay renew-ip`,
then start it. / 续签时先停服，执行上述 `run --rm relay renew-ip`，再启动。

## systemd

Create a dedicated `cowork-relay` system account and a `0700` state directory
owned by that account. Install the verified binary at `/usr/local/bin/cowork-relay`.
Initialize as that account, using `/var/lib/cowork-relay` and an unprivileged port
such as 8443. Install the unit in `/etc/systemd/system/` and enable it after
checking its paths. Domain certificates must be readable within its filesystem
restrictions. A certificate stored under a home directory is hidden by `ProtectHome`.

创建独立的 `cowork-relay` 系统账号和由它拥有的 `0700` 状态目录。把已验证二进制安装到
`/usr/local/bin/cowork-relay`，以该账号初始化 `/var/lib/cowork-relay`，使用 8443 等非特权端口。
核对路径后将 unit 安装到 `/etc/systemd/system/` 并启用。域名证书须在文件系统限制内可读；
`ProtectHome` 会隐藏用户主目录中的证书。

```sh
sudo -u cowork-relay /usr/local/bin/cowork-relay --data-dir /var/lib/cowork-relay \
  init-ip --ip 203.0.113.10 --port 8443 --listen 0.0.0.0:8443
sudo systemctl daemon-reload
sudo systemctl enable --now cowork-relay
sudo -u cowork-relay /usr/local/bin/cowork-relay --data-dir /var/lib/cowork-relay status
```

Permit only the chosen TLS port through the host firewall and cloud network
rules. Administration stays on the local socket. The container and systemd
templates require validation on the deployment host; local macOS acceptance
does not qualify a Linux container deployment.

主机防火墙和云网络规则只需放行所选 TLS 端口，管理仍走本机 socket。
容器和 systemd 模板须在实际部署主机验证；macOS 本地验收不等于 Linux 容器部署验收。
