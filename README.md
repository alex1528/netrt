# netrt

多线 ISP 策略路由管理守护进程，支持远程路由同步、策略路由维护、故障探测与默认路由切换。

## 功能概览

- 多线 ISP 路由同步：定期拉取远程路由并写入各 ISP 专用表
- 策略路由维护：自动维护 `ip rule`，并清理重复规则
- 故障探测切换：默认出口故障时自动切换可用出口
- 主表同步去重：同一 CIDR 前缀不会重复写入主表
- 默认网关智能跳过：ISP 网关等于系统默认网关时，不写冗余主表静态路由
- 路由看门狗：周期检查路由缺失并触发重同步
- `rt_tables` 自愈：缺失时自动初始化 `/etc/iproute2/rt_tables`
- 特殊目标路由开关：`special_targets_enabled` 默认关闭

## 配置文件

默认路径：`/etc/netrt/config.yaml`

```yaml
# ================= 故障探测配置 =================
detect:
  interval_secs: 180
  dest_ips:
    - "119.29.29.29"
    - "223.5.5.5"
    - "8.8.8.8"
  probe_protocol: "udp"  # tcp / udp / icmp
  probe_port: 53
  cn_probe_isps:          # 仅 tcp 生效：强制走大陆域名组的 ISP 名称
    - "ctc"
    - "cmc"
  intl_probe_isps:        # 仅 tcp 生效：强制走海外域名组的 ISP 名称
    - "defaultrt"
  cn_probe_domains:       # 仅 tcp 生效：大陆域名组
    - "dns.alidns.com"
    - "doh.pub"
  intl_probe_domains:     # 仅 tcp 生效：海外域名组
    - "one.one.one.one"
    - "dns.google"
  min_alive: 1
  timeout_secs: 3

# ================= 同步策略 =================
sync:
  interval_hours: 1
  jitter_secs: 600

# ================= 全局特殊路由 =================
special_targets_enabled: false
gateway: "1.1.1.1"
targets:
  - "11.11.11.11"
  - "12.12.12.0/24"

# ================= 多线 ISP 配置 =================
isps:
  - name: "defaultrt"
    gateway: "192.168.0.1"
    table: "defaultrt"
    src_ip: "192.168.0.100"
    sync_to_main: false

  - name: "ctc"
    gateway: "2.2.2.2"
    table: "ctc"
    remote_url: "http://example.com/telecom.rsc"
    sync_to_main: true
```

## 依赖

- Go 1.21+
- `ip`（iproute2）
- systemd（若使用服务安装）

## 快速构建

```bash
go build -o /usr/sbin/netrt main.go
```

打包：

```bash
bash make_deb.sh
```

## Git Hooks 集成

仓库内置 `.githooks/post-commit`，用于自动递增版本 tag 并同步 `make_deb.sh` 中的 `VERSION`。

### 启用 hooks（克隆后执行一次）

```bash
git config core.hooksPath .githooks
```

### 解决 Windows 下可执行位与换行问题

仓库已提供 `.gitattributes`，强制 `.githooks/*` 与 `*.sh` 使用 LF。

若需要手动设置可执行位，请使用：

```bash
git add --chmod=+x -- .githooks/post-commit
```

### post-commit 行为

- 不执行 `go build .`
- 若当前提交未打语义化版本 tag，则自动创建下一个版本 tag
- 版本从 `v0.0.1` 开始递增，并按“每满 10 进 1”规则进位
- 同步 `make_deb.sh` 的 `VERSION="x.y.z"`

单次跳过：

```bash
SKIP_AUTO_TAG=1 git commit -m "message"
```

## 日志

- 程序日志：`/var/log/netrt.log`
- systemd 查看：

```bash
journalctl -u netrt -f
```

## License

MIT
