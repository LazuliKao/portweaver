package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* name;
    char* type;
    char* local_ip;
    int local_port;
    int remote_port;
} ProxyConfig;

typedef void* FrpClient;
*/
import "C"
import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/fatedier/frp/client"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/version"
)

// 全局客户端管理
var (
	clients      = make(map[int]*clientWrapper)
	clientsMutex sync.RWMutex
	nextClientID = 1
)

type clientWrapper struct {
	service *client.Service
	ctx     context.Context
	cancel  context.CancelFunc
	config  *v1.ClientCommonConfig
	proxies []v1.TypedProxyConfig
}

func main() {}

//export FrpInit
func FrpInit() C.int {
	return 0
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
		ctx:     ctx,
		cancel:  cancel,
		config:  &cfg,
		proxies: make([]v1.TypedProxyConfig, 0),
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

//export FrpStartClient
func FrpStartClient(clientID C.int) C.int {
	// log.InitLogger("output.txt", "debug", 7, true)
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return -1
	}

	// 转换代理配置为 ProxyConfigurer 类型
	proxyConfigurers := make([]v1.ProxyConfigurer, 0, len(wrapper.proxies))
	for _, p := range wrapper.proxies {
		proxyConfigurers = append(proxyConfigurers, p.ProxyConfigurer)
	}

	// 使用新的 API 创建 FRP 客户端服务
	svr, err := client.NewService(client.ServiceOptions{
		Common:      wrapper.config,
		ProxyCfgs:   proxyConfigurers,
		VisitorCfgs: nil,
	})
	if err != nil {
		fmt.Printf("Failed to create frp service: %v\n", err)
		return -2
	}

	wrapper.service = svr

	// 在后台启动客户端
	go func() {
		err := svr.Run(wrapper.ctx)
		if err != nil && err != context.Canceled {
			fmt.Printf("FRP client error: %v\n", err)
		}
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

	// 等待服务完全停止
	time.Sleep(100 * time.Millisecond)

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
	time.Sleep(100 * time.Millisecond)

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
