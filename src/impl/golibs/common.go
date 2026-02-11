package main

import (
	"sync"

	"github.com/fatedier/frp/pkg/util/log"
	golib_log "github.com/fatedier/golib/log"
)

var (
	sharedMultiLogger *sharedMultiWriterLogger
	sharedLoggerMutex sync.Mutex
	sharedLoggerInit  bool
)

type logWriter interface {
	Write(p []byte) (n int, err error)
}

type sharedMultiWriterLogger struct {
	writers map[string]logWriter
	mutex   sync.RWMutex
}

func (m *sharedMultiWriterLogger) Write(p []byte) (n int, err error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, writer := range m.writers {
		writer.Write(p)
	}
	return len(p), nil
}

func (m *sharedMultiWriterLogger) addWriter(key string, writer logWriter) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.writers == nil {
		m.writers = make(map[string]logWriter)
	}
	m.writers[key] = writer
}

func (m *sharedMultiWriterLogger) removeWriter(key string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.writers, key)
}

func initSharedLogger(logLevel string) {
	sharedLoggerMutex.Lock()
	defer sharedLoggerMutex.Unlock()

	if !sharedLoggerInit {
		sharedMultiLogger = &sharedMultiWriterLogger{}
		sharedLoggerInit = true
		log.InitLogger("", logLevel, 7, true)
		log.Logger = log.Logger.WithOptions(golib_log.WithOutput(sharedMultiLogger))
	}
}

func addLogWriter(key string, writer logWriter) {
	if sharedMultiLogger != nil {
		sharedMultiLogger.addWriter(key, writer)
	}
}

func removeLogWriter(key string) {
	if sharedMultiLogger != nil {
		sharedMultiLogger.removeWriter(key)
	}
}

func resetSharedLogger() {
	sharedLoggerMutex.Lock()
	defer sharedLoggerMutex.Unlock()

	sharedMultiLogger = nil
	sharedLoggerInit = false
	log.InitLogger("", "info", 7, true)
}

