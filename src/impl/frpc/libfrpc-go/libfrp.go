package main

// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"context"
	"fmt"
	"sync"
	"unsafe"

	"github.com/fatedier/frp/client"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
	golib_log "github.com/fatedier/golib/log"
)

// 全局客户端管理
var (
	clients      = make(map[int]*clientWrapper)
	clientsMutex sync.RWMutex
	nextClientID = 1
)

type clientWrapper struct {
	service   *client.Service
	ctx       context.Context
	cancel    context.CancelFunc
	config    *v1.ClientCommonConfig
	proxies   []v1.TypedProxyConfig
	status    string
	lastError string
	logs      []string
	logMutex  sync.Mutex
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

func main() {}

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
) C.int {
	if serverAddr == nil {
		return -1
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	// 创建客户端配置
	cfg := v1.ClientCommonConfig{}
	cfg.ServerAddr = C.GoString(serverAddr)
	cfg.ServerPort = int(serverPort)

	if token != nil {
		cfg.Auth.Token = C.GoString(token)
	}

	// 设置默认值
	loginFailExit := false
	cfg.LoginFailExit = &loginFailExit
	cfg.Transport.PoolCount = 1
	cfg.Transport.Protocol = "tcp"
	cfg.Log.Level = "info"

	ctx, cancel := context.WithCancel(context.Background())

	wrapper := &clientWrapper{
		ctx:       ctx,
		cancel:    cancel,
		config:    &cfg,
		proxies:   make([]v1.TypedProxyConfig, 0),
		status:    "stopped",
		lastError: "",
		logs:      make([]string, 0),
		logMutex:  sync.Mutex{},
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
	defer clientsMutex.RUnlock()
	if !ok {
		return -1
	}
	if wrapper.service != nil {
		return -3
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

	logger := &ringBufferLogger{wrapper: wrapper}
	log.Logger = log.Logger.WithOptions(golib_log.WithOutput(logger))

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
			fmt.Printf("FRP client error: %v\\n", err)
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
		return C.CString(`[]`)
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	// Convert logs to JSON array
	logsJSON := "["
	for i, log := range wrapper.logs {
		if i > 0 {
			logsJSON += ","
		}
		// Escape quotes in log lines
		escaped := fmt.Sprintf("%q", log)
		logsJSON += escaped
	}
	logsJSON += "]"

	return C.CString(logsJSON)
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
}
