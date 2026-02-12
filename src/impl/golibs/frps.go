//go:build libfrps

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
