//go:build libfrps

package main

// #include <stdlib.h>
// #include <string.h>
// #include <stdbool.h>
//
// typedef struct {
//     const char* server_name;
//     const char* bind_addr;
//     int* bind_port;
//     const char* auth_token;
//     const char* dashboard_addr;
//     int* dashboard_port;
//     const char* dashboard_user;
//     const char* dashboard_pwd;
//     const char* log_level;
//     int* max_pool_count;
//     int* max_ports_per_client;
//     bool* tcp_mux;
//     const char* allow_ports;
// } FrpsConfig;
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server"
)

var (
	servers      = make(map[int]*serverWrapper)
	serversMutex sync.RWMutex
	nextServerID = 1
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

//export FrpsInit
func FrpsInit() {
	fmt.Println("FRP server library initialized.")
}

//export FrpsCreateServer
func FrpsCreateServer(cConfig *C.FrpsConfig) C.int {
	if cConfig == nil {
		return -1
	}

	serversMutex.Lock()
	defer serversMutex.Unlock()

	cfg := v1.ServerConfig{}

	// Basic Config
	if cConfig.bind_addr != nil {
		cfg.BindAddr = C.GoString(cConfig.bind_addr)
	}
	if cConfig.bind_port != nil {
		cfg.BindPort = int(*cConfig.bind_port)
	}

	// Auth Config
	if cConfig.auth_token != nil {
		cfg.Auth.Method = "token"
		cfg.Auth.Token = C.GoString(cConfig.auth_token)
	}

	// Dashboard Config
	if cConfig.dashboard_addr != nil {
		cfg.WebServer.Addr = C.GoString(cConfig.dashboard_addr)
	}
	if cConfig.dashboard_port != nil {
		cfg.WebServer.Port = int(*cConfig.dashboard_port)
	}
	if cConfig.dashboard_user != nil {
		cfg.WebServer.User = C.GoString(cConfig.dashboard_user)
	}
	if cConfig.dashboard_pwd != nil {
		cfg.WebServer.Password = C.GoString(cConfig.dashboard_pwd)
	}

	// Log Config
	if cConfig.log_level != nil {
		cfg.Log.Level = C.GoString(cConfig.log_level)
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	// Force log to stdout/console so we can capture it
	cfg.Log.To = "console"

	// Transport Config
	if cConfig.max_pool_count != nil {
		cfg.Transport.MaxPoolCount = int64(*cConfig.max_pool_count)
	}
	if cConfig.tcp_mux != nil {
		val := bool(*cConfig.tcp_mux)
		cfg.Transport.TCPMux = &val
	}

	// Access Control
	if cConfig.max_ports_per_client != nil {
		cfg.MaxPortsPerClient = int64(*cConfig.max_ports_per_client)
	}

	if cConfig.allow_ports != nil {
		allowPortsStr := C.GoString(cConfig.allow_ports)
		if allowPortsStr != "" {
			// Simple parsing for single ports or ranges if needed
			// v1.ServerConfig AllowPorts is []types.PortsRange
			// For now, let's try to parse simple ranges or single ports
			// This is a simplified implementation
			ranges := []types.PortsRange{}
			parts := strings.Split(allowPortsStr, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.Contains(p, "-") {
					rangeParts := strings.Split(p, "-")
					if len(rangeParts) == 2 {
						start, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
						end, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
						if start > 0 && end > 0 {
							ranges = append(ranges, types.PortsRange{Start: start, End: end})
						}
					}
				} else {
					port, _ := strconv.Atoi(p)
					if port > 0 {
						ranges = append(ranges, types.PortsRange{Start: port, End: port})
					}
				}
			}
			cfg.AllowPorts = ranges
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	name := ""
	if cConfig.server_name != nil {
		name = C.GoString(cConfig.server_name)
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

// ServerStats represents aggregated FRPS server statistics
type ServerStats struct {
	Status      string `json:"status"`
	LastError   string `json:"last_error"`
	ClientCount int    `json:"client_count"`
	ProxyCount  int    `json:"proxy_count"`
	ServerCount int    `json:"server_count"`
}

//export FrpsGetServerStats
func FrpsGetServerStats() *C.char {
	serversMutex.RLock()
	defer serversMutex.RUnlock()

	serverCount := len(servers)
	if serverCount == 0 {
		result := ServerStats{
			Status:      "stopped",
			LastError:   "",
			ClientCount: 0,
			ProxyCount:  0,
			ServerCount: 0,
		}
		jsonBytes, _ := json.Marshal(result)
		return C.CString(string(jsonBytes))
	}

	hasError := false
	hasRunning := false
	var lastError string
	proxyCount := 0

	for _, wrapper := range servers {
		wrapper.logMutex.Lock()
		if wrapper.status == "running" {
			hasRunning = true
		} else if wrapper.status == "error" {
			hasError = true
			if wrapper.lastError != "" && lastError == "" {
				lastError = wrapper.lastError
			}
		}
		wrapper.logMutex.Unlock()

		// Try to get proxy count from server service if available
		if wrapper.service != nil {
			// FRP server doesn't expose this easily, but we can try
			// For now, we'll estimate based on running servers
		}
	}

	// Determine overall status
	var status string
	if hasError {
		status = "error"
	} else if hasRunning {
		status = "running"
	} else {
		status = "stopped"
	}

	result := ServerStats{
		Status:      status,
		LastError:   lastError,
		ClientCount: 0, // Would need dashboard API for actual client count
		ProxyCount:  proxyCount,
		ServerCount: serverCount,
	}

	jsonBytes, _ := json.Marshal(result)
	return C.CString(string(jsonBytes))
}
