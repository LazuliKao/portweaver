//go:build frps

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
	"unsafe"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/server"
	golib_log "github.com/fatedier/golib/log"
)

// FRP Server Implementation

// Global server management
var (
	servers          = make(map[int]*serverWrapper)
	serversMutex     sync.RWMutex
	nextServerID     = 1
	frpsMultiLogger  *frpsMultiWriterLogger
	frpsLoggerMutex  sync.Mutex
	frpsLoggerInited bool
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

type frpsRingBufferLogger struct {
	wrapper *serverWrapper
}

func (l *frpsRingBufferLogger) Write(p []byte) (n int, err error) {
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

// frpsMultiWriterLogger writes log entries to multiple frpsRingBufferLogger instances
type frpsMultiWriterLogger struct {
	writers map[int]*frpsRingBufferLogger
	mutex   sync.RWMutex
}

func (m *frpsMultiWriterLogger) Write(p []byte) (n int, err error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, writer := range m.writers {
		writer.Write(p)
	}
	return len(p), nil
}

func (m *frpsMultiWriterLogger) addWriter(id int, writer *frpsRingBufferLogger) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.writers == nil {
		m.writers = make(map[int]*frpsRingBufferLogger)
	}
	m.writers[id] = writer
}

func (m *frpsMultiWriterLogger) removeWriter(id int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.writers, id)
}

//export FrpsInit
func FrpsInit() {
	// Initialize logger system if not already initialized
	frpsLoggerMutex.Lock()
	if !frpsLoggerInited {
		frpsMultiLogger = &frpsMultiWriterLogger{}
		frpsLoggerInited = true
		// Initialize FRP logger with default level
		log.InitLogger("", "info", 7, true)
		// Set multi-writer as output
		log.Logger = log.Logger.WithOptions(golib_log.WithOutput(frpsMultiLogger))
	}
	frpsLoggerMutex.Unlock()
	fmt.Println("FRPS library initialized.")
}

//export FrpsCreateServer
func FrpsCreateServer(configJSON *C.char, serverName *C.char) C.int {
	if configJSON == nil {
		return -1
	}

	serversMutex.Lock()
	defer serversMutex.Unlock()

	// Parse JSON configuration
	configStr := C.GoString(configJSON)
	cfg := v1.ServerConfig{}
	if err := json.Unmarshal([]byte(configStr), &cfg); err != nil {
		fmt.Printf("Failed to parse FRPS config: %v\n", err)
		return -1
	}

	ctx, cancel := context.WithCancel(context.Background())

	name := ""
	if serverName != nil {
		name = C.GoString(serverName)
	}
	if name == "" {
		// fallback to a default name if user didn't provide one
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

	// Create a ring buffer logger for this server
	logger := &frpsRingBufferLogger{wrapper: wrapper}

	// Add this server's logger to the multi-writer
	frpsMultiLogger.addWriter(int(serverID), logger)

	// Create the server service with the correct API
	svr, err := server.NewService(wrapper.config)
	if err != nil {
		fmt.Printf("Failed to create FRPS service: %v\n", err)
		return -2
	}

	wrapper.service = svr

	// Update status
	wrapper.logMutex.Lock()
	wrapper.status = "running"
	wrapper.logMutex.Unlock()

	// Start the server in a goroutine
	go func() {
		svr.Run(wrapper.ctx)
		// When Run() completes, update status
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

	// Cancel the context to stop the server
	wrapper.cancel()
	if wrapper.service != nil {
		wrapper.service.Close()
		wrapper.service = nil
	}

	// Remove this server's logger from multi-writer
	frpsLoggerMutex.Lock()
	if frpsMultiLogger != nil {
		frpsMultiLogger.removeWriter(int(serverID))
	}
	frpsLoggerMutex.Unlock()

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

	// Ensure server is stopped
	wrapper.cancel()
	if wrapper.service != nil {
		wrapper.service.Close()
		wrapper.service = nil
	}

	// Remove this server's logger from multi-writer
	frpsLoggerMutex.Lock()
	if frpsMultiLogger != nil {
		frpsMultiLogger.removeWriter(int(serverID))
	}
	frpsLoggerMutex.Unlock()

	// Remove from global map
	delete(servers, int(serverID))

	return 0
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

	statusJSON := fmt.Sprintf(`{"status":"%s","last_error":"%s","name":"%s"}`, wrapper.status, wrapper.lastError, wrapper.name)
	return C.CString(statusJSON)
}

//export FrpsIsRunning
func FrpsIsRunning(serverID C.int) C.int {
	serversMutex.RLock()
	wrapper, ok := servers[int(serverID)]
	serversMutex.RUnlock()

	if !ok {
		return 0 // false as int
	}

	wrapper.logMutex.Lock()
	defer wrapper.logMutex.Unlock()

	if wrapper.status == "running" {
		return 1 // true as int
	}
	return 0 // false as int
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
	// Pre-calc approximate capacity to reduce allocations
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

	// Stop all servers
	for _, wrapper := range servers {
		if wrapper.cancel != nil {
			wrapper.cancel()
		}
		if wrapper.service != nil {
			wrapper.service.Close()
		}
	}

	// Clear map
	servers = make(map[int]*serverWrapper)

	// Reset logger state
	frpsLoggerMutex.Lock()
	frpsMultiLogger = nil
	frpsLoggerInited = false
	log.InitLogger("", "info", 7, true)
	frpsLoggerMutex.Unlock()
}
