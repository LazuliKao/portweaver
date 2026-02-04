//go:build frpc

package main

// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/xlog"
	golib_log "github.com/fatedier/golib/log"
)

// FRP Client Implementation

// 全局客户端管理
var (
	clients      = make(map[int]*clientWrapper)
	clientsMutex sync.RWMutex
	nextClientID = 1
	multiLogger  *multiWriterLogger
	loggerMutex  sync.Mutex
	loggerInited bool
)

type clientWrapper struct {
	service        *client.Service
	ctx            context.Context
	cancel         context.CancelFunc
	config         *v1.ClientCommonConfig
	proxies        []v1.TypedProxyConfig
	name           string
	status         string
	lastError      string
	logs           []string
	logMutex       sync.Mutex
	useEncryption  bool
	useCompression bool
}

type ringBufferLogger struct {
	wrapper *clientWrapper
}

func (l *ringBufferLogger) Write(p []byte) (n int, err error) {
	l.wrapper.logMutex.Lock()
	defer l.wrapper.logMutex.Unlock()

	line := string(p)
	l.wrapper.logs = append(l.wrapper.logs, line)

	// Keep only last 500 lines
	if len(l.wrapper.logs) > 500 {
		l.wrapper.logs = l.wrapper.logs[len(l.wrapper.logs)-500:]
	}

	return len(p), nil
}

// multiWriterLogger writes log entries to multiple ringBufferLogger instances
type multiWriterLogger struct {
	writers map[int]*ringBufferLogger
	mutex   sync.RWMutex
}

func (m *multiWriterLogger) Write(p []byte) (n int, err error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, writer := range m.writers {
		writer.Write(p)
	}
	return len(p), nil
}

func (m *multiWriterLogger) addWriter(id int, writer *ringBufferLogger) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.writers == nil {
		m.writers = make(map[int]*ringBufferLogger)
	}
	m.writers[id] = writer
}

func (m *multiWriterLogger) removeWriter(id int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.writers, id)
}

//export FrpInit
func FrpInit() {
	// 初始化日志系统（可选，根据需要配置日志文件路径和级别）
	// log.InitLogger("/tmp/frpc.log", "debug", 7, true)
	// test log
	fmt.Println("FRP library initialized.")
}

//export FrpCreateClient
func FrpCreateClient(
	serverAddr *C.char,
	serverPort C.int,
	token *C.char,
	logLevel *C.char,
	clientName *C.char, // optional name for the client
	useEncryption C.int,
	useCompression C.int,
) C.int {
	if serverAddr == nil {
		return -1
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	cfg := v1.ClientCommonConfig{}
	cfg.ServerAddr = C.GoString(serverAddr)
	cfg.ServerPort = int(serverPort)

	if token != nil {
		cfg.Auth.Token = C.GoString(token)
	}

	loginFailExit := false
	cfg.LoginFailExit = &loginFailExit
	cfg.Transport.PoolCount = 1
	cfg.Transport.Protocol = "tcp"

	if logLevel != nil {
		cfg.Log.Level = C.GoString(logLevel)
	} else {
		cfg.Log.Level = "info"
	}

	ctx, cancel := context.WithCancel(context.Background())

	name := ""
	if clientName != nil {
		name = C.GoString(clientName)
	}
	if name == "" {
		// fallback to server address:port if user didn't provide a name
		name = fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	}

	wrapper := &clientWrapper{
		ctx:            ctx,
		cancel:         cancel,
		config:         &cfg,
		proxies:        make([]v1.TypedProxyConfig, 0),
		name:           name,
		status:         "stopped",
		lastError:      "",
		logs:           make([]string, 0),
		logMutex:       sync.Mutex{},
		useEncryption:  useEncryption != 0,
		useCompression: useCompression != 0,
	}

	clientID := nextClientID
	nextClientID++
	clients[clientID] = wrapper

	return C.int(clientID)
}

//export FrpAddTcpProxy
func FrpAddTcpProxy(
	clientID C.int,
	proxyName *C.char,
	localIP *C.char,
	localPort C.int,
	remotePort C.int,
	useEncryption C.int,
	useCompression C.int,
) C.int {
	if proxyName == nil || localIP == nil {
		return -1
	}

	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return -2
	}

	// 创建 TCP 代理配置
	proxyConfig := v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: C.GoString(proxyName),
			Type: "tcp",
			Transport: v1.ProxyTransport{
				UseEncryption:  wrapper.useEncryption,
				UseCompression: wrapper.useCompression,
			},
		},
		RemotePort: int(remotePort),
	}

	// 设置本地地址和端口
	proxyConfig.LocalIP = C.GoString(localIP)
	proxyConfig.LocalPort = int(localPort)

	// 添加到代理列表
	wrapper.proxies = append(wrapper.proxies, v1.TypedProxyConfig{
		Type:            "tcp",
		ProxyConfigurer: &proxyConfig,
	})

	return 0
}

//export FrpAddUdpProxy
func FrpAddUdpProxy(
	clientID C.int,
	proxyName *C.char,
	localIP *C.char,
	localPort C.int,
	remotePort C.int,
	useEncryption C.int,
	useCompression C.int,
) C.int {
	if proxyName == nil || localIP == nil {
		return -1
	}

	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return -2
	}

	// 创建 UDP 代理配置
	proxyConfig := v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: C.GoString(proxyName),
			Type: "udp",
			Transport: v1.ProxyTransport{
				UseEncryption:  wrapper.useEncryption,
				UseCompression: wrapper.useCompression,
			},
		},
		RemotePort: int(remotePort),
	}

	// 设置本地地址和端口
	proxyConfig.LocalIP = C.GoString(localIP)
	proxyConfig.LocalPort = int(localPort)

	// 添加到代理列表
	wrapper.proxies = append(wrapper.proxies, v1.TypedProxyConfig{
		Type:            "udp",
		ProxyConfigurer: &proxyConfig,
	})

	return 0
}

func makeProxyConfigurers(proxies []v1.TypedProxyConfig) []v1.ProxyConfigurer {
	// 转换代理配置为 ProxyConfigurer 类型
	proxyConfigurers := make([]v1.ProxyConfigurer, 0, len(proxies))
	for _, p := range proxies {
		proxyConfigurers = append(proxyConfigurers, p.ProxyConfigurer)
	}
	return proxyConfigurers
}

//export FrpFlushClient
func FrpFlushClient(clientID C.int) C.int {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()
	if !ok {
		return -1
	}
	wrapper.service.UpdateAllConfigurer(makeProxyConfigurers(wrapper.proxies), nil)
	return 0
}

//export FrpStartClient
func FrpStartClient(clientID C.int) C.int {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()
	if !ok {
		return -1
	}
	if wrapper.service != nil {
		return -3
	}

	// Create a ring buffer logger for this client
	logger := &ringBufferLogger{wrapper: wrapper}

	// Initialize global multi-writer logger if not already initialized
	loggerMutex.Lock()
	if !loggerInited {
		multiLogger = &multiWriterLogger{}
		loggerInited = true
		// Initialize FRP logger with default level
		log.InitLogger("", wrapper.config.Log.Level, 7, true)
		// Set multi-writer as output
		log.Logger = log.Logger.WithOptions(golib_log.WithOutput(multiLogger))
	}
	loggerMutex.Unlock()

	// Add this client's logger to the multi-writer
	multiLogger.addWriter(int(clientID), logger)

	// Get log level
	lvl := strings.ToLower(strings.TrimSpace(wrapper.config.Log.Level))

	// Create an xlog.Logger with client-specific prefix (use provided client name)
	name := wrapper.name
	if name == "" {
		name = fmt.Sprintf("client-%d", clientID)
	}
	clientXLog := xlog.New().AppendPrefix(name)

	// Bind the xlog.Logger to the context
	ctxWithLogger := xlog.NewContext(wrapper.ctx, clientXLog)

	// Update wrapper's context to include the logger
	wrapper.ctx = ctxWithLogger

	// If log level is more verbose than info (trace/debug), insert a startup header
	// and preserve the header + the latest 499 log lines.
	if lvl == "trace" || lvl == "debug" {
		ts := time.Now().Format("2006-01-02 15:04:05.000")
		short := "D"
		if lvl == "trace" {
			short = "T"
		}
		msg := fmt.Sprintf("%s [%s] [frpc/init] Log level set to %s\n", ts, short, strings.ToUpper(lvl))

		wrapper.logMutex.Lock()
		if len(wrapper.logs) == 0 {
			wrapper.logs = []string{msg}
		} else {
			// Keep header + newest up to 499 lines
			tailStart := 0
			if len(wrapper.logs) > 499 {
				tailStart = len(wrapper.logs) - 499
			}
			tail := append([]string(nil), wrapper.logs[tailStart:]...)
			newLogs := make([]string, 0, 1+len(tail))
			newLogs = append(newLogs, msg)
			newLogs = append(newLogs, tail...)
			wrapper.logs = newLogs
		}
		wrapper.logMutex.Unlock()
	}

	// 使用新的 API 创建 FRP 客户端服务
	svr, err := client.NewService(client.ServiceOptions{
		Common:      wrapper.config,
		ProxyCfgs:   makeProxyConfigurers(wrapper.proxies),
		VisitorCfgs: nil,
	})
	if err != nil {
		fmt.Printf("Failed to create frp service: %v\n", err)
		return -2
	}

	wrapper.service = svr

	wrapper.logMutex.Lock()
	wrapper.status = "connected"
	wrapper.logMutex.Unlock()

	go func() {
		err := svr.Run(wrapper.ctx)
		wrapper.logMutex.Lock()
		defer wrapper.logMutex.Unlock()
		if err != nil && err != context.Canceled {
			wrapper.status = "error"
			wrapper.lastError = err.Error()
			fmt.Printf("FRP client error: %v\n", err)
		} else if err == context.Canceled {
			wrapper.status = "stopped"
		}
		// No 'else' branch for "connected" here, as it's set above
	}()
	return 0
}

//export FrpStopClient
func FrpStopClient(clientID C.int) C.int {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	wrapper, ok := clients[int(clientID)]
	if !ok {
		return -1
	}

	// 取消上下文以停止服务
	wrapper.cancel()
	wrapper.service = nil

	// Remove this client's logger from multi-writer
	loggerMutex.Lock()
	if multiLogger != nil {
		multiLogger.removeWriter(int(clientID))
	}
	loggerMutex.Unlock()

	return 0
}

//export FrpDestroyClient
func FrpDestroyClient(clientID C.int) C.int {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	wrapper, ok := clients[int(clientID)]
	if !ok {
		return -1
	}

	// 确保服务已停止
	wrapper.cancel()
	wrapper.service = nil

	// Remove this client's logger from multi-writer
	loggerMutex.Lock()
	if multiLogger != nil {
		multiLogger.removeWriter(int(clientID))
	}
	loggerMutex.Unlock()

	// 从全局map中删除
	delete(clients, int(clientID))

	return 0
}

//export FrpGetVersion
func FrpGetVersion() *C.char {
	version_str := version.Full()
	return C.CString(version_str)
}

//export FrpFreeString
func FrpFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export FrpGetStatus
func FrpGetStatus(clientID C.int) *C.char {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return C.CString(`{"status":"unknown","last_error":"client not found"}`)
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	statusJSON := fmt.Sprintf(`{"status":"%s","last_error":"%s"}`, wrapper.status, wrapper.lastError)
	return C.CString(statusJSON)
}

//export FrpGetLogs
func FrpGetLogs(clientID C.int) *C.char {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return C.CString("")
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	var sb strings.Builder
	// Pre-calc approximate capacity to reduce allocations
	for _, l := range wrapper.logs {
		sb.Grow(len(l))
	}
	for _, l := range wrapper.logs {
		sb.WriteString(l)
	}

	return C.CString(sb.String())
}

//export FrpClearLogs
func FrpClearLogs(clientID C.int) {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	wrapper.logs = make([]string, 0)
}

//export FrpGetProxyTrafficStats
func FrpGetProxyTrafficStats(clientID C.int) *C.char {
	// Find the client wrapper
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return C.CString(`{"error":"client_not_found"}`)
	}

	if wrapper.service == nil {
		return C.CString(`{"error":"service_not_running"}`)
	}

	// Get status exporter
	exporter := wrapper.service.StatusExporter()
	if exporter == nil {
		return C.CString(`{"error":"exporter_not_available"}`)
	}

	// Get all proxy names from proxy configurations
	proxyNames := make([]string, 0)
	seenNames := make(map[string]bool)
	for _, cfg := range wrapper.proxies {
		baseCfg := cfg.GetBaseConfig()
		if baseCfg != nil && !seenNames[baseCfg.Name] {
			proxyNames = append(proxyNames, baseCfg.Name)
			seenNames[baseCfg.Name] = true
		}
	}

	if len(proxyNames) == 0 {
		return C.CString(`{"error":"no_proxies"}`)
	}

	// Collect all proxy statuses
	allStatus := make([]*proxy.WorkingStatus, 0, len(proxyNames))
	for _, name := range proxyNames {
		if status, found := exporter.GetProxyStatus(name); found {
			allStatus = append(allStatus, status)
		}
	}
	resultData := make(map[string]interface{})
	// Build result data
	resultData["proxies"] = allStatus
	// Serialize the array
	jsonBytes, err := json.Marshal(resultData)
	if err != nil {
		return C.CString(`{"error":"marshal_failed"}`)
	}

	return C.CString(string(jsonBytes))
}

//export FrpCleanup
func FrpCleanup() {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	// 停止所有客户端
	for _, wrapper := range clients {
		wrapper.cancel()
	}

	// 清空map
	clients = make(map[int]*clientWrapper)

	// Reset logger state
	loggerMutex.Lock()
	multiLogger = nil
	loggerInited = false
	log.InitLogger("", "info", 7, true)
	loggerMutex.Unlock()
}
