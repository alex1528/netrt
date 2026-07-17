package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ================= 探测配置常量 =================
const (
	DEFAULT_DETECT_INTERVAL = 180 // 默认探测间隔（秒）
	DEFAULT_PROBE_PORT      = 53  // 默认探测端口
	DEFAULT_MIN_ALIVE       = 1   // 默认最低存活数
	DEFAULT_PROBE_TIMEOUT   = 3   // 默认探测超时（秒）
)

// ================= 配置常量 =================
const (
	CONFIG              = "/etc/netrt/config.yaml"
	RT_TABLES           = "/etc/iproute2/rt_tables"
	LOG_FILE            = "/var/log/netrt.log"
	ROUTE_CACHE_DIR     = "/var/cache/netrt"
	DEFAULT_SYNC_HOURS  = 1                // 默认同步间隔（小时）
	DEFAULT_JITTER_SECS = 600              // 默认随机抖动（秒）
	MAX_RETRIES         = 3                // 下载最大重试次数
	RETRY_INTERVAL      = 10 * time.Second // 重试间隔
	WATCHDOG_INTERVAL   = 5 * time.Minute  // 路由看门狗检查间隔
)

// ================= 数据结构 =================
type ISPConfig struct {
	Name       string `yaml:"name"`
	Gateway    string `yaml:"gateway"`
	SrcIP      string `yaml:"src_ip"`
	Table      string `yaml:"table"`
	RemoteURL  string `yaml:"remote_url"`
	SyncToMain bool   `yaml:"sync_to_main"`
}

type SyncConfig struct {
	IntervalHours int `yaml:"interval_hours"` // 同步间隔小时数
	JitterSecs    int `yaml:"jitter_secs"`    // 随机抖动范围（秒）
}

// DetectConfig 对应 config.yaml 中的 detect 节
type DetectConfig struct {
	IntervalSecs     int      `yaml:"interval_secs"`      // 探测间隔（秒）
	DestIPs          []string `yaml:"dest_ips"`           // 探测目的IP列表
	ProbeProtocol    string   `yaml:"probe_protocol"`     // 探测协议: tcp/udp/icmp
	ProbePort        int      `yaml:"probe_port"`         // 探测端口（tcp/udp 使用）
	CNProbeISPs      []string `yaml:"cn_probe_isps"`      // 强制走大陆域名组的 ISP 名称
	IntlProbeISPs    []string `yaml:"intl_probe_isps"`    // 强制走海外域名组的 ISP 名称
	CNProbeDomains   []string `yaml:"cn_probe_domains"`   // 大陆域名组
	IntlProbeDomains []string `yaml:"intl_probe_domains"` // 海外域名组
	MinAlive         int      `yaml:"min_alive"`          // 判定存活的最低成功数
	TimeoutSecs      int      `yaml:"timeout_secs"`       // 单次探测超时（秒）
}

type Config struct {
	SpecialTargetsEnabled bool         `yaml:"special_targets_enabled"`
	Gateway               string       `yaml:"gateway"`
	Targets               []string     `yaml:"targets"`
	ISPs                  []ISPConfig  `yaml:"isps"`
	Sync                  SyncConfig   `yaml:"sync"`
	Detect                DetectConfig `yaml:"detect"`
}

// ================= 全局变量 =================
var cidrRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$`)

const defaultRtTablesContent = `#
# reserved values
#
255     local
254     main
253     default
0       unspec
#
# local
#
#1      inr.ruhep
`

// ================= 主函数 =================
func main() {
	rand.Seed(time.Now().UnixNano())

	// 加载配置获取同步间隔
	conf := loadConfig()
	syncHours := conf.Sync.IntervalHours
	jitterSecs := conf.Sync.JitterSecs

	// 使用默认值兜底
	if syncHours <= 0 {
		syncHours = DEFAULT_SYNC_HOURS
	}
	if jitterSecs <= 0 {
		jitterSecs = DEFAULT_JITTER_SECS
	}

	fmt.Println("netrt 路由策略管理服务已启动 (支持私网与公网环境)...")
	fmt.Printf("配置路径：%s | 日志路径：%s\n", CONFIG, LOG_FILE)
	fmt.Printf("同步间隔：%d 小时 (+0~%d 秒随机抖动)\n", syncHours, jitterSecs)

	// 启动独立的故障探测 goroutine（与路由同步并行运行）
	go runDetectLoop()

	// 启动路由看门狗 goroutine（定期检查 ISP 网关是否在路由表中）
	go runRouteWatchdog()

	for {
		runTask()
		nextRun := time.Duration(syncHours)*time.Hour + time.Duration(rand.Intn(jitterSecs))*time.Second
		fmt.Printf("[%s] 任务完成，下次同步：%v\n", time.Now().Format("15:04:05"), nextRun)
		time.Sleep(nextRun)
	}
}

// ================= 配置加载函数 =================
func loadConfig() Config {
	data, err := os.ReadFile(CONFIG)
	if err != nil {
		fmt.Printf("[警告] 读取配置失败：%v，使用默认配置\n", err)
		return Config{
			Sync: SyncConfig{
				IntervalHours: DEFAULT_SYNC_HOURS,
				JitterSecs:    DEFAULT_JITTER_SECS,
			},
		}
	}

	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		fmt.Printf("[警告] 解析 YAML 失败：%v，使用默认配置\n", err)
		return Config{
			Sync: SyncConfig{
				IntervalHours: DEFAULT_SYNC_HOURS,
				JitterSecs:    DEFAULT_JITTER_SECS,
			},
		}
	}

	return conf
}

// ================= 核心任务函数 =================
func runTask() {
	logF, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("无法创建日志：%v\n", err)
		return
	}
	defer logF.Close()

	logger := func(format string, a ...interface{}) {
		msg := fmt.Sprintf(format, a...)
		fmt.Print(msg)
		logF.WriteString(time.Now().Format("2006-01-02 15:04:05 ") + msg)
	}

	logger("=== 路由同步任务开始 ===\n")

	// 重新加载最新配置
	conf := loadConfig()

	if len(conf.ISPs) == 0 && len(conf.Targets) == 0 {
		logger("[警告] 配置为空，跳过本次同步\n")
		return
	}

	// 1. 处理基础全局路由 (带网关地址范围校验，支持私有地址)
	if conf.SpecialTargetsEnabled && conf.Gateway != "" && len(conf.Targets) > 0 {
		// 检查本机是否有网卡 IP 与 gateway 在同一网段（包含私有地址）
		matchedIP, matchedDev, isInRange := checkGatewayRange(conf.Gateway)
		if isInRange {
			logger("[全局] 网关匹配成功 (本机 IP:%s, 设备:%s), 正在同步 %d 条特殊路由\n", matchedIP, matchedDev, len(conf.Targets))
			for _, target := range conf.Targets {
				applyRoute(target, conf.Gateway, "", matchedDev)
			}
		} else {
			// 尝试通过路由表查找出口（支持私有网关）
			localIP, device, err := findInterfaceInfo(conf.Gateway)
			if err == nil && localIP != "" && device != "" {
				logger("[全局] 通过路由表匹配成功 (本机 IP:%s, 设备:%s), 正在同步 %d 条特殊路由\n", localIP, device, len(conf.Targets))
				for _, target := range conf.Targets {
					applyRoute(target, conf.Gateway, "", device)
				}
			} else {
				logger("[全局] 网关 %s 不在本机网卡地址范围内，跳过特殊路由规则\n", conf.Gateway)
			}
		}
	} else if !conf.SpecialTargetsEnabled && len(conf.Targets) > 0 {
		logger("[全局] 特殊目标路由开关未启用，跳过 %d 条目标\n", len(conf.Targets))
	}

	// 2. 处理各 ISP (包含私网和公网)
	// 获取系统当前默认网关，用于判断是否跳过 defaultrt
	systemDefaultGW := getDefaultGateway()

	// 用于跟踪已同步到主表的 CIDR，避免多 ISP 重复写入
	mainTableSynced := make(map[string]bool)
	for _, isp := range conf.ISPs {
		// 当 defaultrt 的网关与系统默认网关一致时，无需添加静态路由表项
		if isp.Table == "defaultrt" && isp.Gateway == systemDefaultGW {
			logger("[ISP] %s 网关 %s 与系统默认网关一致，跳过\n", isp.Name, isp.Gateway)
			continue
		}

		logger("[ISP] 正在同步：%s\n", isp.Name)

		// A. 自动管理路由表 ID (注册到 /etc/iproute2/rt_tables)
		if err := ensureRtTable(isp.Table); err != nil {
			logger(" [失败] 注册表 %s: %v\n", isp.Table, err)
			continue
		}

		// B. 探测网卡信息 (自动识别私网/公网网卡)
		localIP, device, err := findInterfaceInfo(isp.Gateway)
		if err != nil {
			logger(" [警告] 无法为网关 %s 探测接口：%v\n", isp.Gateway, err)
			continue
		}
		if isp.SrcIP == "" {
			isp.SrcIP = localIP
		}

		// C. 备份当前路由表 (升级保护)
		backupPath := fmt.Sprintf("/tmp/rt_bak_%s.txt", isp.Table)
		exec.Command("sh", "-c", fmt.Sprintf("ip route show table %s > %s 2>/dev/null", isp.Table, backupPath)).Run()

		// D. 【关键】先 flush 清空路由表，再重新添加默认路由 (确保状态一致)
		if isp.Gateway != "" && device != "" && isp.SrcIP != "" {
			// 执行 flush 清空旧路由
			exec.Command("ip", "route", "flush", "table", isp.Table).Run()
			logger(" [操作] 已清空路由表 %s\n", isp.Table)
			// 添加默认路由
			ensureTableDefaultRoute(isp.Gateway, device, isp.SrcIP, isp.Table)
		}

		// E. 【优化】强制同步策略规则 (ip rule) - 先删除重复项再添加
		if isp.SrcIP != "" && isp.Table != "defaultrt" {
			ensureIpRuleClean(isp.SrcIP, isp.Table, logger)
		}

		// F. 获取并下发远程路由
		if isp.RemoteURL != "" {
			targets, err := fetchAndVerifyRoutes(isp.RemoteURL, isp.Table)
			if err != nil {
				logger(" [拒绝] 远程数据校验失败：%v\n", err)
				continue
			}

			// 遍历添加路由
			addedCount := 0
			for _, t := range targets {
				// 1. 添加到 ISP 专用路由表
				applyRoute(t, isp.Gateway, isp.Table, device)

				norm := normalizeCIDR(t)
				allowMainSync := isp.SyncToMain && isp.Gateway != systemDefaultGW

				// 2. 主路由表同步：仅在允许条件下写入，否则清理该 ISP 对应静态路由残留
				if allowMainSync {
					if !mainTableSynced[norm] {
						mainTableSynced[norm] = true
						applyRouteClean(t, isp.Gateway, "", device)
					}
				} else if !mainTableSynced[norm] {
					removeRouteClean(t, "")
				}

				addedCount++
			}

			logger(" [完成] %s 同步成功 (IP:%s, Dev:%s, 条目:%d, 主表同步:%v)\n",
				isp.Name, isp.SrcIP, device, addedCount, isp.SyncToMain)
		}
	}

	logger("=== 路由同步任务结束 ===\n")
}

// ================= 辅助函数 =================

// checkGatewayRange: 检查本机是否有网卡 IP 与 gateway 在同一网段
// 返回：匹配的 IP、设备名、是否匹配（支持私有地址 10.x/172.16-31.x/192.168.x）
func checkGatewayRange(gatewayStr string) (string, string, bool) {
	gwIP := net.ParseIP(gatewayStr)
	if gwIP == nil {
		return "", "", false
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", false
	}

	for _, iface := range ifaces {
		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// 检查 gateway 是否在当前网段内（包含私有地址）
			if ipNet.Contains(gwIP) {
				return ipNet.IP.String(), iface.Name, true
			}
		}
	}

	return "", "", false
}

// findInterfaceInfo: 通过内核路由表自动锁定出口 IP 和设备（支持私有地址网关）
func findInterfaceInfo(gatewayStr string) (string, string, error) {
	out, err := exec.Command("ip", "route", "get", gatewayStr).Output()
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(string(out))
	var localIP, device string
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			device = fields[i+1]
		}
		if f == "src" && i+1 < len(fields) {
			localIP = fields[i+1]
		}
	}
	if localIP == "" || device == "" {
		return "", "", fmt.Errorf("解析地址失败")
	}
	return localIP, device, nil
}

// ensureTableDefaultRoute: 强制同步表内默认路由
func ensureTableDefaultRoute(gw, dev, src, table string) {
	exec.Command("ip", "route", "replace", "default", "via", gw, "dev", dev, "src", src, "table", table).Run()
}

// ensureIpRuleClean: 【优化版】清理重复规则后添加唯一策略规则
// 先删除所有匹配的规则，再添加一条新规则，确保唯一性
func ensureIpRuleClean(srcIP, tableName string, logger func(string, ...interface{})) {
	// 步骤 1: 获取当前所有 rule
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		logger(" [警告] 无法获取当前 rule 列表：%v\n", err)
		return
	}

	// 步骤 2: 查找并删除所有匹配的规则 (from SRCIP lookup TABLE)
	lines := strings.Split(string(out), "\n")
	targetPattern := fmt.Sprintf("from %s lookup %s", srcIP, tableName)

	deletedCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 检查是否包含目标规则 (忽略优先级数字)
		if strings.Contains(line, targetPattern) {
			exec.Command("ip", "rule", "del", "from", srcIP, "table", tableName).Run()
			deletedCount++
			logger(" [清理] 删除重复 rule: %s\n", line)
		}
	}

	// 步骤 3: 添加唯一的新规则
	exec.Command("ip", "rule", "add", "from", srcIP, "table", tableName).Run()

	if deletedCount > 0 {
		logger(" [完成] 已清理 %d 条重复 rule，添加新规则 from %s lookup %s\n", deletedCount, srcIP, tableName)
	} else {
		logger(" [完成] 添加 rule: from %s lookup %s\n", srcIP, tableName)
	}
}

// isPrivateIP reports whether the given CIDR or IP string belongs to an RFC1918 private address range.
func isPrivateIP(cidr string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	if ip == nil {
		return false
	}
	for _, r := range privateRanges {
		_, network, _ := net.ParseCIDR(r)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ================= 故障探测与默认路由切换 =================

// probeDestTCP: 用 TCP 拨测探测目的IP是否可达（从指定 src_ip 出口）
func probeDestTCP(srcIP, destIP string, port, timeoutSecs int) bool {
	if port <= 0 {
		return false
	}
	timeout := time.Duration(timeoutSecs) * time.Second
	addr := fmt.Sprintf("%s:%d", destIP, port)

	// 绑定源IP出口
	localAddr, err := net.ResolveTCPAddr("tcp", srcIP+":0")
	if err != nil {
		return false
	}
	dialer := net.Dialer{
		LocalAddr: localAddr,
		Timeout:   timeout,
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// buildDNSQuery: 构造最小 DNS 查询报文（A 记录）
func buildDNSQuery(domain string, txid uint16) []byte {
	msg := make([]byte, 0, 64)
	// Header
	msg = append(msg,
		byte(txid>>8), byte(txid), // ID
		0x01, 0x00, // Flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	)

	parts := strings.Split(strings.Trim(domain, "."), ".")
	for _, p := range parts {
		if p == "" || len(p) > 63 {
			continue
		}
		msg = append(msg, byte(len(p)))
		msg = append(msg, []byte(p)...)
	}
	msg = append(msg, 0x00)       // end of QNAME
	msg = append(msg, 0x00, 0x01) // QTYPE=A
	msg = append(msg, 0x00, 0x01) // QCLASS=IN

	return msg
}

// probeDestUDP: 用 UDP 探测目的IP端口可达性；53 端口使用 DNS 查询提高有效性
func probeDestUDP(srcIP, destIP string, port, timeoutSecs int) bool {
	if port <= 0 {
		return false
	}
	timeout := time.Duration(timeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(DEFAULT_PROBE_TIMEOUT) * time.Second
	}

	var localAddr *net.UDPAddr
	if srcIP != "" {
		ip := net.ParseIP(srcIP)
		if ip == nil {
			return false
		}
		localAddr = &net.UDPAddr{IP: ip, Port: 0}
	}

	dialer := net.Dialer{LocalAddr: localAddr, Timeout: timeout}
	conn, err := dialer.Dial("udp4", fmt.Sprintf("%s:%d", destIP, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var payload []byte
	var txid uint16
	if port == 53 {
		txid = uint16(rand.Intn(65536))
		payload = buildDNSQuery("www.example.com", txid)
	} else {
		payload = []byte("netrt-udp-probe")
	}

	if _, err := conn.Write(payload); err != nil {
		return false
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return false
	}

	// 对 DNS 响应做最小校验：返回包长度足够且事务 ID 匹配
	if port == 53 {
		if n < 12 {
			return false
		}
		respID := uint16(buf[0])<<8 | uint16(buf[1])
		return respID == txid
	}

	return true
}

// probeDestICMP: 用系统 ping 执行 ICMP 探测（从指定 src_ip 出口）
func probeDestICMP(srcIP, destIP string, timeoutSecs int) bool {
	if timeoutSecs <= 0 {
		timeoutSecs = DEFAULT_PROBE_TIMEOUT
	}

	args := []string{"-c", "1", "-W", strconv.Itoa(timeoutSecs)}
	if srcIP != "" {
		args = append(args, "-I", srcIP)
	}
	args = append(args, destIP)

	return exec.Command("ping", args...).Run() == nil
}

// probeDestIP: 按协议执行探测
func probeDestIP(srcIP, destIP, protocol string, port, timeoutSecs int) bool {
	switch strings.ToLower(protocol) {
	case "icmp":
		return probeDestICMP(srcIP, destIP, timeoutSecs)
	case "udp":
		return probeDestUDP(srcIP, destIP, port, timeoutSecs)
	default:
		return probeDestTCP(srcIP, destIP, port, timeoutSecs)
	}
}

// probeISP: 从 isp.SrcIP 出口探测 destIPs，返回成功探测数
func probeISP(isp ISPConfig, destIPs []string, protocol string, port, timeoutSecs int) int {
	alive := 0
	for _, dest := range destIPs {
		if probeDestIP(isp.SrcIP, dest, protocol, port, timeoutSecs) {
			alive++
		}
	}
	return alive
}

// buildISPGroupMap: 根据 ISP 名称构造分组映射，支持大小写无关匹配
func buildISPGroupMap(cnISPs, intlISPs []string) map[string]string {
	out := make(map[string]string)
	for _, n := range cnISPs {
		k := strings.ToLower(strings.TrimSpace(n))
		if k != "" {
			out[k] = "cn"
		}
	}
	for _, n := range intlISPs {
		k := strings.ToLower(strings.TrimSpace(n))
		if k != "" {
			out[k] = "intl"
		}
	}
	return out
}

// resolveDomainsToIPv4: 将域名列表解析为去重后的 IPv4 列表
func resolveDomainsToIPv4(domains []string, timeoutSecs int) []string {
	if timeoutSecs <= 0 {
		timeoutSecs = DEFAULT_PROBE_TIMEOUT
	}
	resolver := net.Resolver{}
	seen := make(map[string]bool)
	var out []string

	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
		addrs, err := resolver.LookupIPAddr(ctx, d)
		cancel()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			v4 := a.IP.To4()
			if v4 == nil {
				continue
			}
			s := v4.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}

	return out
}

// replaceDefaultGateway: 替换主路由表默认路由
// oldGW 为空时只执行 add，不执行 del
func replaceDefaultGateway(oldGW, newGW string, logger func(string, ...interface{})) {
	logger("[探测] 替换默认路由: %s → %s\n", oldGW, newGW)
	if oldGW != "" {
		exec.Command("ip", "route", "del", "default", "via", oldGW).Run()
	}
	exec.Command("ip", "route", "add", "default", "via", newGW).Run()
}

// deleteISPRoutes: 删除某 ISP 出口的所有非默认路由
func deleteISPRoutes(isp ISPConfig, logger func(string, ...interface{})) {
	logger("[探测] 出口 %s (%s) 全不通，删除其路由表 %s 中的非默认路由\n", isp.Name, isp.SrcIP, isp.Table)
	// 获取该路由表中所有非 default 路由并逐条删除
	out, err := exec.Command("ip", "route", "show", "table", isp.Table).Output()
	if err != nil {
		logger("[探测] 无法获取路由表 %s: %v\n", isp.Table, err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "default") {
			continue // 跳过空行和默认路由
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dest := fields[0]
		exec.Command("ip", "route", "del", dest, "table", isp.Table).Run()
		logger("[探测]   已删除路由: %s table %s\n", dest, isp.Table)
	}
}

// getDefaultGateway: 从主路由表读取当前默认网关
func getDefaultGateway() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// 输出格式: "default via 1.2.3.4 dev eth0 ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// runDetectLoop: 独立 goroutine，定期探测各 ISP 出口，故障时自动切换默认路由
// 由 config.yaml 的 isps[].gateway/src_ip 驱动
func runDetectLoop() {
	for {
		conf := loadConfig()
		dc := conf.Detect

		// 填充默认值
		if dc.IntervalSecs <= 0 {
			dc.IntervalSecs = DEFAULT_DETECT_INTERVAL
		}
		probeProtocol := strings.ToLower(strings.TrimSpace(dc.ProbeProtocol))
		if probeProtocol == "" {
			probeProtocol = "tcp"
		}
		switch probeProtocol {
		case "icmp":
			dc.ProbePort = 0
		case "udp", "tcp":
			if dc.ProbePort <= 0 {
				dc.ProbePort = DEFAULT_PROBE_PORT
			}
		default:
			probeProtocol = "tcp"
			if dc.ProbePort <= 0 {
				dc.ProbePort = DEFAULT_PROBE_PORT
			}
		}
		if dc.MinAlive <= 0 {
			dc.MinAlive = DEFAULT_MIN_ALIVE
		}
		if dc.TimeoutSecs <= 0 {
			dc.TimeoutSecs = DEFAULT_PROBE_TIMEOUT
		}
		hasDomainGroups := probeProtocol == "tcp" &&
			(len(dc.CNProbeDomains) > 0 || len(dc.IntlProbeDomains) > 0) &&
			(len(dc.CNProbeISPs) > 0 || len(dc.IntlProbeISPs) > 0)
		if len(dc.DestIPs) == 0 && !hasDomainGroups {
			// 无探测目标，跳过本轮
			time.Sleep(time.Duration(dc.IntervalSecs) * time.Second)
			continue
		}

		// 打开日志（追加模式，与 runTask 共用文件）
		logF, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		logger := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			if err == nil {
				logF.WriteString(time.Now().Format("2006-01-02 15:04:05 ") + msg)
			}
		}
		if err == nil {
			defer logF.Close()
		}

		probeMode := "ICMP"
		if probeProtocol != "icmp" {
			probeMode = fmt.Sprintf("%s:%d", strings.ToUpper(probeProtocol), dc.ProbePort)
		}
		logger("=== 故障探测开始 (mode:%s dest:%v) ===\n", probeMode, dc.DestIPs)

		ispGroupMap := buildISPGroupMap(dc.CNProbeISPs, dc.IntlProbeISPs)
		cnTargets := resolveDomainsToIPv4(dc.CNProbeDomains, dc.TimeoutSecs)
		intlTargets := resolveDomainsToIPv4(dc.IntlProbeDomains, dc.TimeoutSecs)
		if probeProtocol == "tcp" && len(ispGroupMap) > 0 {
			logger("[探测] TCP域名分组已启用 (cn_isps:%d, intl_isps:%d, cn_domains:%d -> %dIP, intl_domains:%d -> %dIP)\n",
				len(dc.CNProbeISPs), len(dc.IntlProbeISPs), len(dc.CNProbeDomains), len(cnTargets), len(dc.IntlProbeDomains), len(intlTargets))
		}

		// 获取当前默认网关
		currentDefaultGW := getDefaultGateway()
		logger("[探测] 当前默认网关: %s\n", currentDefaultGW)

		// 找出哪个 ISP 是当前默认出口（gateway 匹配当前默认网关）
		var defaultISP *ISPConfig
		for i := range conf.ISPs {
			if conf.ISPs[i].Gateway == currentDefaultGW {
				defaultISP = &conf.ISPs[i]
				break
			}
		}

		var defaultISPDown bool
		var fallbackGW string // 可用备用网关

		for _, isp := range conf.ISPs {
			// src_ip 留空时，通过网关自动探测本机出口 IP
			if isp.SrcIP == "" {
				localIP, _, err := findInterfaceInfo(isp.Gateway)
				if err != nil || localIP == "" {
					logger("[探测] %s (gw:%s) 无法探测出口IP，跳过\n", isp.Name, isp.Gateway)
					continue
				}
				isp.SrcIP = localIP
			}
			probeTargets := dc.DestIPs
			if probeProtocol == "tcp" && len(ispGroupMap) > 0 {
				group := ispGroupMap[strings.ToLower(strings.TrimSpace(isp.Name))]
				switch group {
				case "cn":
					if len(cnTargets) > 0 {
						probeTargets = cnTargets
					}
				case "intl":
					if len(intlTargets) > 0 {
						probeTargets = intlTargets
					}
				}
			}

			if len(probeTargets) == 0 {
				logger("[探测] %s (src:%s gw:%s) 无可用探测目标，跳过\n", isp.Name, isp.SrcIP, isp.Gateway)
				continue
			}

			aliveCount := probeISP(isp, probeTargets, probeProtocol, dc.ProbePort, dc.TimeoutSecs)
			logger("[探测] %s (src:%s gw:%s) 存活探测: %d/%d\n",
				isp.Name, isp.SrcIP, isp.Gateway, aliveCount, len(probeTargets))

			isDefault := defaultISP != nil && isp.Name == defaultISP.Name

			if aliveCount < dc.MinAlive {
				if isDefault {
					// 默认出口不通
					defaultISPDown = true
					logger("[探测] 默认出口 %s 不通\n", isp.Name)
				} else {
					// 非默认出口全不通 → 删除其非默认路由
					deleteISPRoutes(isp, logger)
				}
			} else if !isDefault {
				// 非默认出口可用，记录为备用
				if fallbackGW == "" {
					fallbackGW = isp.Gateway
					logger("[探测] 备用出口可用: %s (gw:%s)\n", isp.Name, fallbackGW)
				}
			}
		}

		// 当默认出口不通且有可用备用出口时，替换默认路由
		if defaultISPDown && fallbackGW != "" {
			replaceDefaultGateway(currentDefaultGW, fallbackGW, logger)
		}

		logger("=== 故障探测结束 ===\n")
		time.Sleep(time.Duration(dc.IntervalSecs) * time.Second)
	}
}

// ================= 路由看门狗 =================

// runRouteWatchdog: 定期检查各 ISP 网关是否仍在路由表中，缺失时自动触发重载
func runRouteWatchdog() {
	for {
		time.Sleep(WATCHDOG_INTERVAL)

		conf := loadConfig()
		if len(conf.ISPs) == 0 {
			continue
		}

		// 获取当前完整路由表
		out, err := exec.Command("ip", "route", "show").Output()
		if err != nil {
			continue
		}
		routeStr := string(out)

		// 同时检查各 ISP 专用表
		for _, isp := range conf.ISPs {
			if isp.Gateway == "" || isp.Table == "" || isp.RemoteURL == "" {
				continue
			}

			// 检查该 ISP 网关是否出现在其专用路由表中
			tableOut, err := exec.Command("ip", "route", "show", "table", isp.Table).Output()
			if err != nil {
				continue
			}
			tableStr := string(tableOut)

			// 如果专用表中不包含该网关（路由可能被清除了），触发一次完整同步
			if !strings.Contains(tableStr, isp.Gateway) && !strings.Contains(routeStr, isp.Gateway) {
				fmt.Printf("[%s] [看门狗] %s 网关 %s 在路由表中缺失，触发重新同步\n",
					time.Now().Format("15:04:05"), isp.Name, isp.Gateway)
				runTask()
				break // 一次 runTask 会同步所有 ISP，无需继续检查
			}
		}
	}
}

// applyRoute: 应用单条路由（支持主路由表和专用路由表）
func applyRoute(target, via, table, dev string) {
	if !strings.Contains(target, "/") {
		target += "/32"
	}

	// 构建命令参数
	args := []string{"route", "replace", target, "via", via}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	if table != "" {
		args = append(args, "table", table)
	}

	exec.Command("ip", args...).Run()
}

// applyRouteClean: 先删除目标前缀的所有旧路由（含不同 metric），再添加新路由
// 用于主路由表同步，避免因 metric 不同导致的重复条目
func applyRouteClean(target, via, table, dev string) {
	if !strings.Contains(target, "/") {
		target += "/32"
	}

	// 先删除该前缀在目标表中的所有现有路由（循环删除直到无匹配）
	removeRouteClean(target, table)

	// 再添加唯一一条新路由
	addArgs := []string{"route", "add", target, "via", via}
	if dev != "" {
		addArgs = append(addArgs, "dev", dev)
	}
	if table != "" {
		addArgs = append(addArgs, "table", table)
	}

	exec.Command("ip", addArgs...).Run()
}

// removeRouteClean: 删除目标前缀在指定路由表中的所有路由项（含不同 metric）
func removeRouteClean(target, table string) {
	if !strings.Contains(target, "/") {
		target += "/32"
	}

	for i := 0; i < 10; i++ {
		delArgs := []string{"route", "del", target}
		if table != "" {
			delArgs = append(delArgs, "table", table)
		}
		if err := exec.Command("ip", delArgs...).Run(); err != nil {
			break
		}
	}
}

// downloadWithRetry: 带重试的 HTTP 下载
func downloadWithRetry(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var lastErr error
	for i := 1; i <= MAX_RETRIES; i++ {
		resp, err := client.Get(url)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				return io.ReadAll(resp.Body)
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}
		if i < MAX_RETRIES {
			time.Sleep(RETRY_INTERVAL)
		}
	}
	return nil, lastErr
}

// getCachePath: 获取 ISP 路由的本地缓存文件路径
func getCachePath(tableName string) string {
	return fmt.Sprintf("%s/%s.routes", ROUTE_CACHE_DIR, tableName)
}

// fetchAndVerifyRoutes: 从远程获取内容并验证合法性（带重试和本地缓存降级）
// 支持格式 1: route add -net 223.252.221.0/24 gw DESTGW
// 支持格式 2: add address=223.252.214.0/23 comment="" list=List_ChinaTelecom
func fetchAndVerifyRoutes(url string, tableName string) ([]string, error) {
	// 确保缓存目录存在
	os.MkdirAll(ROUTE_CACHE_DIR, 0755)

	var content []byte
	var fromCache bool

	// 带重试下载
	data, err := downloadWithRetry(url)
	if err != nil {
		// 下载失败，尝试使用本地缓存
		cachePath := getCachePath(tableName)
		cachedData, cacheErr := os.ReadFile(cachePath)
		if cacheErr != nil {
			return nil, fmt.Errorf("网络请求失败：%v（且无本地缓存可用）", err)
		}
		content = cachedData
		fromCache = true
		fmt.Printf(" [降级] 远程下载失败，使用本地缓存: %s\n", cachePath)
	} else {
		content = data
	}

	// 解析路由条目
	targets := parseRouteContent(string(content))

	if len(targets) == 0 {
		return nil, fmt.Errorf("解析完成，但未发现任何合法的路由条目")
	}

	// 去重：相同 CIDR 只保留第一次出现
	seen := make(map[string]bool, len(targets))
	uniq := targets[:0]
	for _, t := range targets {
		normalized := normalizeCIDR(t)
		if !seen[normalized] {
			seen[normalized] = true
			uniq = append(uniq, t)
		}
	}

	// 下载成功时更新本地缓存
	if !fromCache {
		cachePath := getCachePath(tableName)
		os.WriteFile(cachePath, content, 0644)
	}

	return uniq, nil
}

// parseRouteContent: 从文本内容中解析路由条目
func parseRouteContent(text string) []string {
	var targets []string
	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		var candidate string

		if strings.Contains(line, "route add -net") {
			// 逻辑 A: Linux 格式
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "-net" && i+1 < len(fields) {
					candidate = fields[i+1]
					break
				}
			}
		} else if strings.Contains(line, "address=") {
			// 逻辑 B: MikroTik 格式
			parts := strings.Split(line, "address=")
			if len(parts) > 1 {
				addrFields := strings.Fields(parts[1])
				if len(addrFields) > 0 {
					candidate = addrFields[0]
				}
			}
		}

		if candidate != "" {
			candidate = strings.Trim(candidate, "\"' ,;")
			if cidrRegex.MatchString(candidate) && !isPrivateIP(candidate) {
				targets = append(targets, candidate)
			}
		}
	}

	return targets
}

// normalizeCIDR: 规范化 CIDR 表示，确保网络地址一致（如 1.2.4.5/24 → 1.2.4.0/24）
func normalizeCIDR(cidr string) string {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return ipNet.String()
}

// ensureRtTable: 倒序分配 ID (252 往下)，注册到 /etc/iproute2/rt_tables
func ensureRtTable(tableName string) error {
	if err := ensureRtTablesFile(); err != nil {
		return err
	}

	content, err := os.ReadFile(RT_TABLES)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	usedIDs := make(map[int]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			id, _ := strconv.Atoi(fields[0])
			usedIDs[id] = true
			if fields[1] == tableName {
				return nil // 已存在
			}
		}
	}

	// 倒序寻找可用 ID (252, 251, 250...)
	newID := 252
	for usedIDs[newID] && newID > 1 {
		newID--
	}

	if newID <= 1 {
		return fmt.Errorf("无可用路由表 ID")
	}

	// 写入文件
	f, err := os.OpenFile(RT_TABLES, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%d\t%s\n", newID, tableName))
	return err
}

// ensureRtTablesFile: 当 /etc/iproute2/rt_tables 缺失或为空时，自动初始化为系统默认模板
func ensureRtTablesFile() error {
	info, err := os.Stat(RT_TABLES)
	if err == nil && info.Size() > 0 {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(RT_TABLES), 0755); err != nil {
		return err
	}

	return os.WriteFile(RT_TABLES, []byte(defaultRtTablesContent), 0644)
}
