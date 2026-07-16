#!/bin/bash

# ================= 配置区 =================
APP_NAME="netrt"
VERSION="1.0.5"
ARCH="amd64"
PKG_DIR="${APP_NAME}_v${VERSION}_${ARCH}"

# 路径定义
BIN_TARGET="usr/sbin/$APP_NAME"
CONF_TARGET="etc/netrt/config.yaml"
SERVICE_TARGET="etc/systemd/system/$APP_NAME.service"
# ==========================================

echo -e "\033[32m>>> 开始构建 Debian 软件包: $PKG_DIR ...\033[0m"

# 1. 环境准备
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/etc/netrt"
mkdir -p "$PKG_DIR/etc/systemd/system"
mkdir -p "$PKG_DIR/usr/sbin"
mkdir -p "$PKG_DIR/var/log"
mkdir -p "$PKG_DIR/var/cache/netrt"
mkdir -p "$PKG_DIR/usr/share/doc/netrt"

# 2. 编译 Go 程序
echo "正在编译 Go 源码..."
go build -o "$PKG_DIR/$BIN_TARGET" main.go
if [ $? -ne 0 ]; then
    echo -e "\033[31m编译失败！\033[0m"
    exit 1
fi

# 3. 准备配置文件模版
cat <<'EOF' > "$PKG_DIR/$CONF_TARGET"
# ================= 全局路由配置 =================
# ================= 故障探测配置 =================
detect:
  # 探测间隔（秒）
  interval_secs: 180
  # 探测目的IP列表
  dest_ips:
    - "119.29.29.29"
    - "223.5.5.5"
    - "223.6.6.6"
    - "180.76.76.76"
    - "8.8.8.8"
    - "8.8.4.4"
  # 探测端口（TCP），0 表示用 ICMP ping
  probe_port: 53
  # 判定出口存活的最低成功探测数（dest_ips 中至少几个通）
  min_alive: 1
  # 探测超时（秒）
  timeout_secs: 3

# ================= 同步策略 =================
sync:
  interval_hours: 1    # 同步间隔小时数 (原 SYNC_INTERVAL_HOURS)
  jitter_secs: 600     # 随机抖动范围秒数 (原 RANDOM_JITTER_SECS)

# ==== 特殊目标路由 ====
special_targets_enabled: false
gateway: "1.1.1.1"
targets:
  - "11.11.11.11"
  - "12.12.12.0/24"

# ================= 多线ISP配置 =================
isps:
  - name: "defaultrt"
    gateway: "192.168.0.1"
    table: "defaultrt"
    src_ip: "192.168.0.100"
    sync_to_main: false

  - name: "ctc"
    gateway: "2.2.2.2"
    table: "ctc"
    remote_url: "http://ros.tcp5.com/list/telecom_latest.rsc"
    sync_to_main: true

  - name: "cuc"
    gateway: "3.3.3.3"
    table: "cuc"
    remote_url: "http://ros.tcp5.com/list/unicom_latest.rsc"
    sync_to_main: true

  - name: "cmc"
    gateway: "4.4.4.4"
    table: "cmc"
    remote_url: "http://ros.tcp5.com/list/mobile_latest.rsc"
    sync_to_main: true

  - name: "cnt"
    gateway: "5.5.5.5"
    table: "cnt"
    remote_url: "http://ros.tcp5.com/list/cernet_latest.rsc"
    sync_to_main: true

#  - name: "other"
#    gateway: "6.6.6.6"
#    table: "other"
#    remote_url: "http://ros.tcp5.com/list/other_latest.rsc"
#    sync_to_main: true

#  - name: "china"
#    gateway: "7.7.7.7"
#    table: "china"
#    remote_url: "http://ros.tcp5.com/list/all_china_latest.rsc"
#    sync_to_main: true
EOF

# 4. 准备 Systemd 服务文件
cat <<EOF > "$PKG_DIR/$SERVICE_TARGET"
[Unit]
Description=NetRoute Manager Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/$BIN_TARGET
Restart=always
RestartSec=15
StandardOutput=append:/var/log/$APP_NAME.log
StandardError=inherit

[Install]
WantedBy=multi-user.target
EOF

# 5. 写入 README.md 到包内
cat <<'EOF' > "$PKG_DIR/usr/share/doc/netrt/README.md"
# netrt 网络路由管理说明

本工具支持从远程 URL 自动获取并更新路由，兼容以下内容格式：

### 1. 传统 Linux 格式
`route add -net 223.252.221.0/24 gw DESTGW`

### 2. MikroTik 地址池格式
`add address=223.252.214.0/23 list=List_ChinaTelecom`

### 核心机制
- **幂等更新**: 使用 `ip route replace`，不匹配则修正。
- **自动适配**: 安装时自动将本地网卡 IP 写入 `src_ip` 字段。
- **安全备份**: 更新前将旧路由备份至 `/tmp/rt_bak_*.txt`。
- **下载重试**: 远程路由列表下载失败时自动重试3次（间隔10秒）。
- **本地缓存降级**: 下载成功后缓存至 \`/var/cache/netrt/\`，网络不可用时自动使用缓存。
- **路由去重**: 同一 CIDR 前缀不会重复写入主路由表。
- **默认网关智能跳过**: ISP 网关与系统默认网关相同时，不添加冗余主表路由。
- **路由看门狗**: 每5分钟检查 ISP 网关是否在路由表中，缺失时自动重载。
EOF

# 6. 写入 DEBIAN/control
cat <<EOF > "$PKG_DIR/DEBIAN/control"
Package: $APP_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: lynn<lyt.lu@qq.com>
Description: NetRoute Manager Daemon,兼容 Linux Route 和 RouterOS 地址列表格式
 Automatically syncs routes and manages multi-ISP policy routing.
 支持双重格式自动识别:
 1. Linux route-add 脚本格式 (route add -net ...)
 2. MikroTik RouterOS 导出格式 (add address=... list=...)
 具备自动网卡匹配、策略路由管理及随机更新机制。
EOF

# 6. 写入 DEBIAN/conffiles (保护配置文件不被覆盖)
cat <<EOF > "$PKG_DIR/DEBIAN/conffiles"
/$CONF_TARGET
/$SERVICE_TARGET
EOF

# 7. 写入 DEBIAN/postinst (包含复杂多 ISP 适配逻辑)
cat <<'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/bash
set -e
CONF_FILE="/etc/netrt/config.yaml"

refine_isp_configs() {
    echo "[netrt] 正在执行多 ISP 网络环境自动适配..."
    # 提取 ISP 块中的所有网关 (排除第一行全局网关)
    GATEWAYS=$(grep 'gateway:' "$CONF_FILE" | sed '1d' | awk -F'"' '{print $2}')

    for GW in $GATEWAYS; do
        # 探测到达该网关的本地出口 IP
        LOCAL_IP=$(ip -4 route get "$GW" 2>/dev/null | grep -oP 'src \K[\d.]+')

        if [ -n "$LOCAL_IP" ]; then
            echo "  -> 网关 $GW 匹配本地 IP: $LOCAL_IP"
            # 使用 Perl 跨行匹配修改对应 ISP 块的 src_ip
            perl -i -0777 -pe "s/(gateway:\s*\"$GW\".*?src_ip:\s*\")[^\"]*/\${1}$LOCAL_IP/s" "$CONF_FILE"
        else
            echo "  -> [警告] 无法为网关 $GW 探测到出口地址"
        fi
    done
}

if [ -f "$CONF_FILE" ]; then refine_isp_configs; fi

systemctl daemon-reload
systemctl enable netrt.service
systemctl restart netrt.service
exit 0
EOF

# 8. 写入 DEBIAN/prerm (卸载前停止服务)
cat <<'EOF' > "$PKG_DIR/DEBIAN/prerm"
#!/bin/bash
systemctl stop netrt.service
systemctl disable netrt.service
exit 0
EOF

# 8.1 写入 DEBIAN/postrm (卸载后清理缓存)
cat <<'EOF' > "$PKG_DIR/DEBIAN/postrm"
#!/bin/bash
if [ "$1" = "purge" ]; then
    rm -rf /var/cache/netrt
    rm -rf /etc/netrt
    rm -f /var/log/netrt.log
fi
exit 0
EOF

# 9. 设置权限并打包
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/DEBIAN/postrm"
echo "正在生成 .deb 安装包..."
dpkg-deb --build "$PKG_DIR"

echo -e "\033[32m>>> 打包完成: ${PKG_DIR}.deb\033[0m"
