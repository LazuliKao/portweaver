//go:build libfrpc

package main

// void free(void *);
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
	frpconfig "github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/xlog"
)

// FRP Client Implementation

// Global client management
var (
	clients      = make(map[int]*clientWrapper)
	clientsMutex sync.RWMutex
	nextClientID = 1
)

type clientWrapper struct {
	service        *client.Service
	ctx            context.Context
	cancel         context.CancelFunc
	config         *v1.ClientCommonConfig
	configSource   *source.ConfigSource
	aggregator     *source.Aggregator
	proxies        []v1.ProxyConfigurer
	visitors       []v1.VisitorConfigurer
	name           string
	routingID      string
	status         string
	lastError      string
	logs           []string
	logMutex       sync.Mutex
	useEncryption  bool
	useCompression bool
}

type clientRingBufferLogger struct {
	wrapper *clientWrapper
}

func createClient(
	cfg *v1.ClientCommonConfig,
	proxies []v1.ProxyConfigurer,
	visitors []v1.VisitorConfigurer,
	name string,
	useEncryption bool,
	useCompression bool,
) C.int {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	if name == "" {
		name = fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	}
	wrapper := &clientWrapper{
		ctx:            ctx,
		cancel:         cancel,
		config:         cfg,
		configSource:   source.NewConfigSource(),
		proxies:        proxies,
		visitors:       visitors,
		name:           name,
		routingID:      "",
		status:         "stopped",
		lastError:      "",
		logs:           make([]string, 0),
		logMutex:       sync.Mutex{},
		useEncryption:  useEncryption,
		useCompression: useCompression,
	}
	wrapper.aggregator = source.NewAggregator(wrapper.configSource)

	clientID := nextClientID
	nextClientID++
	clients[clientID] = wrapper
	return C.int(clientID)
}

func parseClientConfig(content []byte, format string) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, []v1.VisitorConfigurer, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "toml" && format != "yaml" && format != "json" {
		return nil, nil, nil, fmt.Errorf("unsupported FRPC configuration format %q", format)
	}

	cfg := &v1.ClientConfig{}
	if err := frpconfig.LoadConfigure(content, cfg, true, format); err != nil {
		return nil, nil, nil, err
	}
	if len(cfg.IncludeConfigFiles) != 0 {
		return nil, nil, nil, fmt.Errorf("FRPC includes are not supported")
	}
	if err := cfg.ClientCommonConfig.Complete(); err != nil {
		return nil, nil, nil, err
	}

	proxies := make([]v1.ProxyConfigurer, 0, len(cfg.Proxies))
	for _, proxyCfg := range cfg.Proxies {
		proxies = append(proxies, proxyCfg.ProxyConfigurer)
	}
	visitors := make([]v1.VisitorConfigurer, 0, len(cfg.Visitors))
	for _, visitorCfg := range cfg.Visitors {
		visitors = append(visitors, visitorCfg.VisitorConfigurer)
	}
	proxies, visitors = frpconfig.FilterClientConfigurers(&cfg.ClientCommonConfig, proxies, visitors)
	proxies = frpconfig.CompleteProxyConfigurers(proxies)
	visitors = frpconfig.CompleteVisitorConfigurers(visitors)
	if _, err := validation.ValidateAllClientConfig(&cfg.ClientCommonConfig, proxies, visitors, security.NewUnsafeFeatures(nil)); err != nil {
		return nil, nil, nil, err
	}
	return &cfg.ClientCommonConfig, proxies, visitors, nil
}

func (l *clientRingBufferLogger) Write(p []byte) (n int, err error) {
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

//export FrpcInit
func FrpcInit() {
	fmt.Println("FRP client library initialized.")
}

//export FrpcCreateClient
func FrpcCreateClient(
	serverAddr *C.char,
	serverPort C.int,
	token *C.char,
	logLevel *C.char,
	clientName *C.char,
	useEncryption C.int,
	useCompression C.int,
) C.int {
	if serverAddr == nil {
		return -1
	}

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

	name := ""
	if clientName != nil {
		name = C.GoString(clientName)
	}
	return createClient(&cfg, nil, nil, name, useEncryption != 0, useCompression != 0)
}

//export FrpcCreateClientFromFile
func FrpcCreateClientFromFile(path *C.char, format *C.char, name *C.char) C.int {
	if path == nil || format == nil {
		return -1
	}
	content, err := frpconfig.LoadFileContentWithTemplate(C.GoString(path), frpconfig.GetValues())
	if err != nil {
		fmt.Printf("Failed to load FRPC configuration file: %v\n", err)
		return -1
	}
	cfg, proxies, visitors, err := parseClientConfig(content, C.GoString(format))
	if err != nil {
		fmt.Printf("Failed to parse FRPC configuration file: %v\n", err)
		return -1
	}
	clientName := ""
	if name != nil {
		clientName = C.GoString(name)
	}
	return createClient(cfg, proxies, visitors, clientName, false, false)
}

//export FrpcCreateClientFromContent
func FrpcCreateClientFromContent(content *C.char, format *C.char, name *C.char) C.int {
	if content == nil || format == nil {
		return -1
	}
	rendered, err := frpconfig.RenderWithTemplate([]byte(C.GoString(content)), frpconfig.GetValues())
	if err != nil {
		fmt.Printf("Failed to render FRPC configuration content: %v\n", err)
		return -1
	}
	cfg, proxies, visitors, err := parseClientConfig(rendered, C.GoString(format))
	if err != nil {
		fmt.Printf("Failed to parse FRPC configuration content: %v\n", err)
		return -1
	}
	clientName := ""
	if name != nil {
		clientName = C.GoString(name)
	}
	return createClient(cfg, proxies, visitors, clientName, false, false)
}

//export FrpcValidateConfig
func FrpcValidateConfig(content *C.char, format *C.char) *C.char {
	if content == nil || format == nil {
		return C.CString("content and format are required")
	}
	rendered, err := frpconfig.RenderWithTemplate([]byte(C.GoString(content)), frpconfig.GetValues())
	if err == nil {
		_, _, _, err = parseClientConfig(rendered, C.GoString(format))
	}
	if err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export FrpcAddTcpProxy
func FrpcAddTcpProxy(
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
	name := C.GoString(proxyName)
	for _, existing := range wrapper.proxies {
		if existing.GetBaseConfig().Name == name {
			fmt.Printf("FRPC proxy name %q already exists\n", name)
			return -3
		}
	}

	proxyConfig := v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: name,
			Type: "tcp",
			Transport: v1.ProxyTransport{
				UseEncryption:  wrapper.useEncryption,
				UseCompression: wrapper.useCompression,
			},
		},
		RemotePort: int(remotePort),
	}

	proxyConfig.LocalIP = C.GoString(localIP)
	proxyConfig.LocalPort = int(localPort)

	wrapper.proxies = append(wrapper.proxies, &proxyConfig)

	return 0
}

//export FrpcAddUdpProxy
func FrpcAddUdpProxy(
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
	name := C.GoString(proxyName)
	for _, existing := range wrapper.proxies {
		if existing.GetBaseConfig().Name == name {
			fmt.Printf("FRPC proxy name %q already exists\n", name)
			return -3
		}
	}

	proxyConfig := v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: name,
			Type: "udp",
			Transport: v1.ProxyTransport{
				UseEncryption:  wrapper.useEncryption,
				UseCompression: wrapper.useCompression,
			},
		},
		RemotePort: int(remotePort),
	}

	proxyConfig.LocalIP = C.GoString(localIP)
	proxyConfig.LocalPort = int(localPort)

	wrapper.proxies = append(wrapper.proxies, &proxyConfig)

	return 0
}

func replaceClientConfigSource(wrapper *clientWrapper) error {
	if wrapper.configSource == nil {
		wrapper.configSource = source.NewConfigSource()
	}
	if wrapper.aggregator == nil {
		wrapper.aggregator = source.NewAggregator(wrapper.configSource)
	}
	return wrapper.configSource.ReplaceAll(wrapper.proxies, wrapper.visitors)
}

//export FrpcFlushClient
func FrpcFlushClient(clientID C.int) C.int {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()
	if !ok {
		return -1
	}
	if err := replaceClientConfigSource(wrapper); err != nil {
		fmt.Printf("Failed to refresh frp client config source: %v\n", err)
		return -3
	}
	if wrapper.service == nil {
		return -2
	}
	if err := wrapper.service.UpdateAllConfigurer(wrapper.proxies, wrapper.visitors); err != nil {
		fmt.Printf("Failed to update frp client configurers: %v\n", err)
		return -4
	}
	return 0
}

//export FrpcStartClient
func FrpcStartClient(clientID C.int) C.int {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()
	if !ok {
		return -1
	}
	if wrapper.service != nil {
		return -3
	}

	logger := &clientRingBufferLogger{wrapper: wrapper}

	initSharedLogger(wrapper.config.Log.Level)

	// Generate a routing UUID and inject it as the first (lowest-priority)
	// xlog prefix so every log line from this instance — including lines from
	// FRP's internal child goroutines that inherit this context — contains the
	// unique token "[uuid]". The dispatch writer matches on this token.
	routingID := newRoutingID()
	wrapper.routingID = routingID
	registerInstanceWriter(routingID, logger)

	lvl := strings.ToLower(strings.TrimSpace(wrapper.config.Log.Level))

	name := wrapper.name
	if name == "" {
		name = fmt.Sprintf("client-%d", clientID)
	}
	// Priority 1: routing tag (displayed first, used for dispatch matching)
	// Priority 10: human-readable name (displayed second via AppendPrefix default)
	// Rendered in every log line as: [pw:xxxxxxxxxxxxxxxx] [name] ...
	clientXLog := xlog.New().
		AddPrefix(xlog.LogPrefix{Name: "routing-id", Value: "pw:" + routingID, Priority: 1}).
		AppendPrefix(name)

	ctxWithLogger := xlog.NewContext(wrapper.ctx, clientXLog)
	wrapper.ctx = ctxWithLogger

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
	if err := replaceClientConfigSource(wrapper); err != nil {
		fmt.Printf("Failed to prepare frp client config source: %v\n", err)
		return -2
	}

	svr, err := client.NewService(wrapper.ctx, client.ServiceOptions{
		Common:                 wrapper.config,
		ConfigSourceAggregator: wrapper.aggregator,
	})
	if err != nil {
		fmt.Printf("Failed to create frp service: %v\n", err)
		return -2
	}

	wrapper.service = svr

	go func() {
		defer unregisterInstanceWriter(routingID)

		wrapper.logMutex.Lock()
		wrapper.status = "connected"
		wrapper.logMutex.Unlock()
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
	}()
	return 0
}

//export FrpcStopClient
func FrpcStopClient(clientID C.int) C.int {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	wrapper, ok := clients[int(clientID)]
	if !ok {
		return -1
	}

	if wrapper.cancel != nil {
		wrapper.cancel()
	}

	if wrapper.service != nil {
		wrapper.service = nil
	}

	unregisterInstanceWriter(wrapper.routingID)

	wrapper.logMutex.Lock()
	wrapper.status = "stopped"
	wrapper.logMutex.Unlock()

	return 0
}

//export FrpcDestroyClient
func FrpcDestroyClient(clientID C.int) C.int {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	wrapper, ok := clients[int(clientID)]
	if !ok {
		return -1
	}

	if wrapper.cancel != nil {
		wrapper.cancel()
	}

	if wrapper.service != nil {
		wrapper.service = nil
	}

	unregisterInstanceWriter(wrapper.routingID)
	delete(clients, int(clientID))

	return 0
}

//export FrpcGetVersion
func FrpcGetVersion() *C.char {
	version_str := version.Full()
	return C.CString(version_str)
}

//export FrpcFreeString
func FrpcFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export FrpcGetStatus
func FrpcGetStatus(clientID C.int) *C.char {
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

//export FrpcGetLogs
func FrpcGetLogs(clientID C.int) *C.char {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return C.CString("")
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	var sb strings.Builder
	for _, l := range wrapper.logs {
		sb.Grow(len(l))
	}
	for _, l := range wrapper.logs {
		sb.WriteString(l)
	}

	return C.CString(sb.String())
}

//export FrpcClearLogs
func FrpcClearLogs(clientID C.int) {
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

//export FrpcGetProxyTrafficStats
func FrpcGetProxyTrafficStats(clientID C.int) *C.char {
	clientsMutex.RLock()
	wrapper, ok := clients[int(clientID)]
	clientsMutex.RUnlock()

	if !ok {
		return C.CString(`{"error":"client_not_found"}`)
	}

	if wrapper.service == nil {
		return C.CString(`{"error":"service_not_running"}`)
	}

	exporter := wrapper.service.StatusExporter()
	if exporter == nil {
		return C.CString(`{"error":"exporter_not_available"}`)
	}

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

	allStatus := make([]*proxy.WorkingStatus, 0, len(proxyNames))
	for _, name := range proxyNames {
		if status, found := exporter.GetProxyStatus(name); found {
			allStatus = append(allStatus, status)
		}
	}
	resultData := make(map[string]interface{})
	resultData["proxies"] = allStatus
	jsonBytes, err := json.Marshal(resultData)
	if err != nil {
		return C.CString(`{"error":"marshal_failed"}`)
	}

	return C.CString(string(jsonBytes))
}

//export FrpcCleanup
func FrpcCleanup() {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for _, wrapper := range clients {
		wrapper.cancel()
	}

	clients = make(map[int]*clientWrapper)
	resetSharedLogger()
}
