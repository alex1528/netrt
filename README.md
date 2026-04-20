# netrt

多线 ISP 策略路由管理守护进程，支持远程路由表自动同步、多出口故障探测与默认路由自动切换。

## 功能概览

- **多线 ISP 路由同步** — 定期从远程 URL 拉取路由列表，自动下发到各 ISP 专用路由表
- **策略路由管理** — 自动维护 `ip rule`，为每个 ISP 出口绑定 `from <src_ip> lookup <table>` 规则
- **故障探测与自动切换** — 独立 goroutine 定期 TCP 探测各出口连通性，默认出口故障时自动切换到可用备用出口
- **私有 IP 过滤** — 自动过滤 RFC1918 地址（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`），防止私有路由污染 ISP 专用表
- **路由表自动注册** — 自动分配 ID 并写入 `/etc/iproute2/rt_tables`，无需手动维护
- **双格式路由解析** — 兼容 Linux `route add -net` 格式和 MikroTik RouterOS `add address=` 格式

## 目录结构

```
netrt/
├── main.go       # 主程序
└── go.mod
```

## 配置文件

默认路径：`/etc/netrt/config.yaml`

```yaml
# ================= 故障探测配置 =================
detect:
  interval_secs: 180     # 探测间隔（秒）
  dest_ips:
    - "119.29.29.29"
    - "223.5.5.5"
    - "8.8.8.8"
  probe_port: 53         # TCP 探测端口
  min_alive: 1           # 判定存活的最低成功探测数
  timeout_secs: 3        # 单次探测超时（秒）

# ================= 同步策略 =================
sync:
  interval_hours: 1      # 路由同步间隔（小时）
  jitter_secs: 600       # 随机抖动范围（秒），防止集中请求

# ================= 全局特殊路由 =================
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

### ISP 字段说明

| 字段 | 说明 |
|---|---|
| `name` | ISP 标识名 |
| `gateway` | 该 ISP 出口网关 IP |
| `src_ip` | 本机对应出口 IP（留空则自动探测） |
| `table` | 策略路由表名（`defaultrt` 为系统默认表，不添加 ip rule） |
| `remote_url` | 远程路由列表 URL |
| `sync_to_main` | 是否同时将路由写入主路由表 |

## 安装

### 手动编译

```bash
go build -o /usr/sbin/netrt main.go
systemctl daemon-reload
systemctl enable --now netrt
```

## 运行逻辑

程序启动后并行运行两个循环：

```
main()
 ├── goroutine: runDetectLoop()   每 interval_secs 秒
 │    ├── 读取各 ISP 的 gateway / src_ip
 │    ├── TCP 探测各出口到 dest_ips 的连通性
 │    ├── 非默认出口全不通 → 删除其非默认路由
 │    └── 默认出口不通 + 有可用备用 → 替换默认路由
 │
 └── loop: runTask()              每 interval_hours 小时 + 随机抖动
      ├── 同步全局特殊路由
      └── 遍历各 ISP
           ├── 注册路由表 ID
           ├── flush 并重建默认路由
           ├── 同步 ip rule（defaultrt 跳过）
           └── 拉取远程路由列表并下发（过滤私有 IP）
```

## 支持的远程路由格式

**Linux 格式**
```
route add -net 223.252.221.0/24 gw 1.2.3.4
```

**MikroTik RouterOS 格式**
```
add address=223.252.214.0/23 comment="" list=List_ChinaTelecom
```

## 依赖

- Go 1.21+
- `ip` 命令（iproute2）

## 日志

运行日志写入 `/var/log/netrt.log`，同时输出到 stdout（systemd journal 可查）。

```bash
journalctl -u netrt -f
# 或
tail -f /var/log/netrt.log
```

## License

MIT
