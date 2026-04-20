package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	DEFAULT_SYNC_HOURS  = 1   // 默认同步间隔（小时）
	DEFAULT_JITTER_SECS = 600 // 默认随机抖动（秒）
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
	IntervalSecs int      `yaml:"interval_secs"` // 探测间隔（秒）
	DestIPs      []string `yaml:"dest_ips"`      // 探测目的IP列表
	ProbePort    int      `yaml:"probe_port"`    // TCP 探测端口，0 表示 ICMP
	MinAlive     int      `yaml:"min_alive"`     // 判定存活的最低成功数
	TimeoutSecs  int      `yaml:"timeout_secs"`  // 单次探测超时（秒）
}

type Config struct {
	Gateway string       `yaml:"gateway"`
	Targets []string     `yaml:"targets"`
	ISPs    []ISPConfig  `yaml:"isps"`
	Sync    SyncConfig   `yaml:"sync"`
	Detect  DetectConfig `yaml:"detect"`
}

// ================= 全局变量 =================
var cidrRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$`)

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
	if conf.Gateway != "" && len(conf.Targets) > 0 {
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
	}

	// 2. 处理各 ISP (包含私网和公网)
	for _, isp := range conf.ISPs {
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
			targets, err := fetchAndVerifyRoutes(isp.RemoteURL)
			if err != nil {
				logger(" [拒绝] 远程数据校验失败：%v\n", err)
				continue
			}

			// 遍历添加路由
			addedCount := 0
			for _, t := range targets {
				// 1. 添加到 ISP 专用路由表
				applyRoute(t, isp.Gateway, isp.Table, device)

				// 2. 如果配置了 sync_to_main，同时添加到主路由表
				if isp.SyncToMain {
					applyRoute(t, isp.Gateway, "", device)
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

// probeDestIP: 用 TCP 拨测探测目的IP是否可达（从指定 src_ip 出口）
// port 为 0 时退化为 TCP connect 到 80 端口（ICMP 需 root 权限，TCP 更通用）
func probeDestIP(srcIP, destIP string, port, timeoutSecs int) bool {
	if port <= 0 {
		port = 80
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

// probeISP: 从 isp.SrcIP 出口探测 destIPs，返回成功探测数
func probeISP(isp ISPConfig, destIPs []string, port, timeoutSecs int) int {
	alive := 0
	for _, dest := range destIPs {
		if probeDestIP(isp.SrcIP, dest, port, timeoutSecs) {
			alive++
		}
	}
	return alive
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
		if dc.ProbePort <= 0 {
			dc.ProbePort = DEFAULT_PROBE_PORT
		}
		if dc.MinAlive <= 0 {
			dc.MinAlive = DEFAULT_MIN_ALIVE
		}
		if dc.TimeoutSecs <= 0 {
			dc.TimeoutSecs = DEFAULT_PROBE_TIMEOUT
		}
		if len(dc.DestIPs) == 0 {
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

		logger("=== 故障探测开始 (dest: %v) ===\n", dc.DestIPs)

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
			if isp.SrcIP == "" {
				continue // 没有 src_ip 无法绑定出口探测
			}
			aliveCount := probeISP(isp, dc.DestIPs, dc.ProbePort, dc.TimeoutSecs)
			logger("[探测] %s (src:%s gw:%s) 存活探测: %d/%d\n",
				isp.Name, isp.SrcIP, isp.Gateway, aliveCount, len(dc.DestIPs))

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

// fetchAndVerifyRoutes: 从远程获取内容并验证合法性
// 支持格式 1: route add -net 223.252.221.0/24 gw DESTGW
// 支持格式 2: add address=223.252.214.0/23 comment="" list=List_ChinaTelecom
func fetchAndVerifyRoutes(url string) ([]string, error) {
	client := http.Client{Timeout: 25 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("网络请求失败：%v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("服务器返回状态异常：%d", resp.StatusCode)
	}

	var targets []string
	scanner := bufio.NewScanner(resp.Body)

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

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取远程内容时出错：%v", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("解析完成，但未发现任何合法的路由条目")
	}

	return targets, nil
}

// ensureRtTable: 倒序分配 ID (252 往下)，注册到 /etc/iproute2/rt_tables
func ensureRtTable(tableName string) error {
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
