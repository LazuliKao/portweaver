//go:build libfrps

package main

// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server"

	"github.com/fatedier/frp/server/proxy"
)

// Proxy event types
const (
	ProxyEventAdded   = 1
	ProxyEventRemoved = 2
)

// ProxyEventCallback is the C function signature for proxy event callbacks
// eventType: 1 = proxy added, 2 = proxy removed
// proxyName: name of the proxy
// proxyType: type of the proxy (tcp, udp, http, https, etc.)
// bindPort: the bind port for the proxy
// serverID: the server ID that owns this proxy
type ProxyEventCallback func(eventType C.int, proxyName *C.char, proxyType *C.char, bindPort C.int, serverID C.int)

//export FrpsRegisterProxyEventCallback
func FrpsRegisterProxyEventCallback(callback unsafe.Pointer) {
	proxyCallbackMutex.Lock()
	defer proxyCallbackMutex.Unlock()
	proxyEventCallback = callback
	fmt.Println("FRPS: Proxy event callback registered")
}

var (
	servers      = make(map[int]*serverWrapper)
	serversMutex sync.RWMutex
	nextServerID = 1

	// Callback for proxy events
	proxyEventCallback unsafe.Pointer
	proxyCallbackMutex sync.RWMutex
)

type serverWrapper struct {
	service   *server.Service
	ctx       context.Context
	cancel    context.CancelFunc
	config    *v1.ServerConfig
	name      string
	status    string
	lastError string
	logs      []string
	logMutex  sync.Mutex

	// Proxy monitoring
	proxyMap      map[string]struct{} // Track proxy names
	proxyMapMutex sync.Mutex
	monitorCancel context.CancelFunc // Cancel function for proxy monitor goroutine
}

type serverRingBufferLogger struct {
	wrapper *serverWrapper
}

func (l *serverRingBufferLogger) Write(p []byte) (n int, err error) {
	l.wrapper.logMutex.Lock()
	defer l.wrapper.logMutex.Unlock()

	line := string(p)
	l.wrapper.logs = append(l.wrapper.logs, line)

	if len(l.wrapper.logs) > 500 {
		l.wrapper.logs = l.wrapper.logs[len(l.wrapper.logs)-500:]
	}

	return len(p), nil
}

// startProxyMonitor starts a goroutine that monitors proxy changes
func (w *serverWrapper) startProxyMonitor(serverID int) {
	monitorCtx, monitorCancel := context.WithCancel(w.ctx)
	w.monitorCancel = monitorCancel

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				w.checkProxyChanges(serverID)
			case <-monitorCtx.Done():
				return
			}
		}
	}()
}

// stopProxyMonitor stops the proxy monitor goroutine
func (w *serverWrapper) stopProxyMonitor() {
	if w.monitorCancel != nil {
		w.monitorCancel()
		w.monitorCancel = nil
	}
}

// checkProxyChanges checks for proxy changes and triggers callbacks
func (w *serverWrapper) checkProxyChanges(serverID int) {
	if w.service == nil {
		return
	}

	// Get current proxies from the service using reflection
	// Access the private ctlManager.ctlsByRunID map
	currentProxies := make(map[string]struct{})

	// Get ctlManager field from service
	serviceValue := reflect.ValueOf(w.service).Elem()
	ctlManagerField := serviceValue.FieldByName("ctlManager")
	if !ctlManagerField.IsValid() {
		return
	}

	// Get ctlsByRunID map from ctlManager
	ctlManagerValue := ctlManagerField.Elem()
	ctlsByRunIDField := ctlManagerValue.FieldByName("ctlsByRunID")
	if !ctlsByRunIDField.IsValid() {
		return
	}

	// Iterate over all controls
	ctlsByRunID := ctlsByRunIDField.MapRange()
	for ctlsByRunID.Next() {
		controlValue := ctlsByRunID.Value()
		control := controlValue.Interface().(*server.Control)

		// Get proxies map from control using reflection
		controlElem := reflect.ValueOf(control).Elem()
		proxiesField := controlElem.FieldByName("proxies")
		if !proxiesField.IsValid() {
			continue
		}

		// Iterate over all proxies in this control
		proxiesMap := proxiesField.MapRange()
		for proxiesMap.Next() {
			proxyName := proxiesMap.Key().String()
			pxyValue := proxiesMap.Value()
			pxy, ok := pxyValue.Interface().(proxy.Proxy)
			if !ok {
				continue
			}

			currentProxies[proxyName] = struct{}{}

			// Check if this is a new proxy
			w.proxyMapMutex.Lock()
			_, exists := w.proxyMap[proxyName]
			w.proxyMapMutex.Unlock()

			if !exists {
				// New proxy added
				configurer := pxy.GetConfigurer()
				baseConfig := configurer.GetBaseConfig()
				proxyType := baseConfig.Type

				// Get the bind port based on proxy type
				bindPort := 0
				switch configurer := configurer.(type) {
				case *v1.TCPProxyConfig:
					bindPort = configurer.RemotePort
				case *v1.UDPProxyConfig:
					bindPort = configurer.RemotePort
				case *v1.HTTPProxyConfig:
					bindPort = 80
				case *v1.HTTPSProxyConfig:
					bindPort = 443
				}

				w.proxyMapMutex.Lock()
				w.proxyMap[proxyName] = struct{}{}
				w.proxyMapMutex.Unlock()

				// Trigger callback
				w.triggerProxyCallback(ProxyEventAdded, proxyName, proxyType, bindPort, serverID)
			}
		}
	}

	// Check for removed proxies
	w.proxyMapMutex.Lock()
	for proxyName := range w.proxyMap {
		if _, exists := currentProxies[proxyName]; !exists {
			// Proxy removed
			delete(w.proxyMap, proxyName)

			// Trigger callback - we don't have the proxy info anymore, so use defaults
			w.triggerProxyCallback(ProxyEventRemoved, proxyName, "", 0, serverID)
		}
	}
	w.proxyMapMutex.Unlock()
}

// triggerProxyCallback triggers the proxy event callback
func (w *serverWrapper) triggerProxyCallback(eventType int, proxyName string, proxyType string, bindPort int, serverID int) {
	proxyCallbackMutex.RLock()
	callback := proxyEventCallback
	proxyCallbackMutex.RUnlock()

	if callback != nil {
		// Convert the callback to the appropriate function type
		fn := *(*ProxyEventCallback)(unsafe.Pointer(&callback))

		cProxyName := C.CString(proxyName)
		cProxyType := C.CString(proxyType)
		defer C.free(unsafe.Pointer(cProxyName))
		defer C.free(unsafe.Pointer(cProxyType))

		fn(C.int(eventType), cProxyName, cProxyType, C.int(bindPort), C.int(serverID))
	}
}

//export FrpsInit
func FrpsInit() {
	fmt.Println("FRP server library initialized.")
}

//export FrpsCreateServer
func FrpsCreateServer(configJSON *C.char, serverName *C.char) C.int {
	if configJSON == nil {
		return -1
	}

	serversMutex.Lock()
	defer serversMutex.Unlock()

	configStr := C.GoString(configJSON)
	var cfg v1.ServerConfig

	if err := json.Unmarshal([]byte(configStr), &cfg); err != nil {
		fmt.Printf("Failed to parse server config: %v\n", err)
		return -1
	}

	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	ctx, cancel := context.WithCancel(context.Background())

	name := ""
	if serverName != nil {
		name = C.GoString(serverName)
	}
	if name == "" {
		name = fmt.Sprintf("server-%d", nextServerID)
	}

	wrapper := &serverWrapper{
		ctx:       ctx,
		cancel:    cancel,
		config:    &cfg,
		name:      name,
		status:    "stopped",
		lastError: "",
		logs:      make([]string, 0),
		logMutex:  sync.Mutex{},
		proxyMap:  make(map[string]struct{}),
	}

	serverID := nextServerID
	nextServerID++
	servers[serverID] = wrapper

	return C.int(serverID)
}

//export FrpsStartServer
func FrpsStartServer(serverID C.int) C.int {
	serversMutex.RLock()
	wrapper, ok := servers[int(serverID)]
	serversMutex.RUnlock()
	if !ok {
		return -1
	}
	if wrapper.service != nil {
		return -3
	}

	logger := &serverRingBufferLogger{wrapper: wrapper}
	logKey := fmt.Sprintf("frps-%d", serverID)

	initSharedLogger(wrapper.config.Log.Level)
	addLogWriter(logKey, logger)

	lvl := strings.ToLower(strings.TrimSpace(wrapper.config.Log.Level))

	name := wrapper.name
	if name == "" {
		name = fmt.Sprintf("server-%d", serverID)
	}
	serverXLog := xlog.New().AppendPrefix(name)

	ctxWithLogger := xlog.NewContext(wrapper.ctx, serverXLog)
	wrapper.ctx = ctxWithLogger

	if lvl == "trace" || lvl == "debug" {
		ts := time.Now().Format("2006-01-02 15:04:05.000")
		short := "D"
		if lvl == "trace" {
			short = "T"
		}
		msg := fmt.Sprintf("%s [%s] [frps/init] Log level set to %s\n", ts, short, strings.ToUpper(lvl))

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

	svr, err := server.NewService(wrapper.config)
	if err != nil {
		fmt.Printf("Failed to create frp server service: %v\n", err)
		return -2
	}

	wrapper.service = svr

	go func() {
		wrapper.logMutex.Lock()
		wrapper.status = "running"
		wrapper.logMutex.Unlock()
		svr.Run(wrapper.ctx)
		wrapper.logMutex.Lock()
		defer wrapper.logMutex.Unlock()
		wrapper.status = "stopped"
	}()
	return 0
}

//export FrpsStopServer
func FrpsStopServer(serverID C.int) C.int {
	serversMutex.Lock()
	defer serversMutex.Unlock()

	wrapper, ok := servers[int(serverID)]
	if !ok {
		return -1
	}

	if wrapper.cancel != nil {
		wrapper.cancel()
	}

	if wrapper.service != nil {
		wrapper.service = nil
	}

	logKey := fmt.Sprintf("frps-%d", serverID)
	removeLogWriter(logKey)

	wrapper.logMutex.Lock()
	wrapper.status = "stopped"
	wrapper.logMutex.Unlock()

	return 0
}

//export FrpsDestroyServer
func FrpsDestroyServer(serverID C.int) C.int {
	serversMutex.Lock()
	defer serversMutex.Unlock()

	wrapper, ok := servers[int(serverID)]
	if !ok {
		return -1
	}

	if wrapper.cancel != nil {
		wrapper.cancel()
	}

	if wrapper.service != nil {
		wrapper.service = nil
	}

	logKey := fmt.Sprintf("frps-%d", serverID)
	removeLogWriter(logKey)

	delete(servers, int(serverID))

	return 0
}

//export FrpsGetVersion
func FrpsGetVersion() *C.char {
	version_str := version.Full()
	return C.CString(version_str)
}

//export FrpsFreeString
func FrpsFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export FrpsGetStatus
func FrpsGetStatus(serverID C.int) *C.char {
	serversMutex.RLock()
	wrapper, ok := servers[int(serverID)]
	serversMutex.RUnlock()

	if !ok {
		return C.CString(`{"status":"unknown","last_error":"server not found"}`)
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	statusJSON := fmt.Sprintf(`{"status":"%s","last_error":"%s"}`, wrapper.status, wrapper.lastError)
	return C.CString(statusJSON)
}

//export FrpsGetLogs
func FrpsGetLogs(serverID C.int) *C.char {
	serversMutex.RLock()
	wrapper, ok := servers[int(serverID)]
	serversMutex.RUnlock()

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

//export FrpsClearLogs
func FrpsClearLogs(serverID C.int) {
	serversMutex.RLock()
	wrapper, ok := servers[int(serverID)]
	serversMutex.RUnlock()

	if !ok {
		return
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	wrapper.logs = make([]string, 0)
}

//export FrpsCleanup
func FrpsCleanup() {
	serversMutex.Lock()
	defer serversMutex.Unlock()

	for _, wrapper := range servers {
		wrapper.cancel()
	}

	servers = make(map[int]*serverWrapper)
	resetSharedLogger()
}
