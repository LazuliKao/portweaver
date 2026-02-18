//go:build libfrpc || libfrps

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/fatedier/frp/pkg/util/log"
	golib_log "github.com/fatedier/golib/log"
)

type logWriter interface {
	Write(p []byte) (n int, err error)
}

// newRoutingID returns 8 random bytes encoded as 16 lowercase hex characters.
// This is the bare ID; the xlog prefix value is set to "pw:" + routingID so
// that every FRP log line contains the fixed marker "[pw:xxxxxxxxxxxxxxxx]".
// The "pw:" namespace ensures the tag is unique to PortWeaver and trivially
// machine-parseable: find "[pw:", read 16 chars, expect "]".
func newRoutingID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// routingToken returns the exact bracketed xlog token for a given routing ID:
//
//	[pw:xxxxxxxxxxxxxxxx]
//
// This is what appears in every FRP log line for instances that use the ID as
// their first xlog prefix. The token is used both for dispatch matching and
// for stripping from stored log lines.
func routingToken(routingID string) []byte {
	return []byte("[pw:" + routingID + "]")
}

// prefixDispatchWriter routes each log write to the writer whose routing token
// "[pw:id]" appears in the message, then strips the token before storing so
// that the ring buffer only contains human-readable output.
//
// Every FRP log line emitted within an instance's context subtree contains the
// token because the routing ID is registered as the lowest-priority xlog
// prefix (Priority 1) and inherited by all child goroutines via context.
// Writes that carry no known token are discarded (cross-instance safety).
type prefixDispatchWriter struct {
	mu      sync.RWMutex
	writers map[string]logWriter // routingID → writer
	tokens  map[string][]byte    // routingID → cached token bytes
}

func (d *prefixDispatchWriter) Write(p []byte) (int, error) {
	// Fast path: check for "[pw:" prefix before acquiring lock
	pwIdx := bytes.Index(p, []byte("[pw:"))
	if pwIdx == -1 {
		// No token at all, treat as global log
		fmt.Println(string(p))
		return len(p), nil
	}

	// Extract routing ID directly from the message (16 hex chars after "[pw:")
	// Format: [pw:xxxxxxxxxxxxxxxx]
	if pwIdx+20 >= len(p) || p[pwIdx+20] != ']' {
		// Malformed token
		fmt.Println(string(p))
		return len(p), nil
	}
	routingID := string(p[pwIdx+4 : pwIdx+20])

	d.mu.RLock()
	w, ok := d.writers[routingID]
	tok := d.tokens[routingID]
	d.mu.RUnlock()

	if !ok {
		// Unknown routing ID
		fmt.Println(string(p))
		return len(p), nil
	}

	// Strip "[pw:id] " (token + trailing space) from the line
	stripLen := len(tok)
	if pwIdx+stripLen < len(p) && p[pwIdx+stripLen] == ' ' {
		stripLen++ // consume the trailing space too
	}

	// Optimize: reuse buffer when possible, avoid allocation for small messages
	var clean []byte
	if len(p) <= 512 { // Small message optimization
		var buf [512]byte
		clean = buf[:0]
		clean = append(clean, p[:pwIdx]...)
		clean = append(clean, p[pwIdx+stripLen:]...)
	} else {
		clean = make([]byte, 0, len(p)-stripLen)
		clean = append(clean, p[:pwIdx]...)
		clean = append(clean, p[pwIdx+stripLen:]...)
	}

	w.Write(clean)
	return len(p), nil
}

func (d *prefixDispatchWriter) register(routingID string, w logWriter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.writers == nil {
		d.writers = make(map[string]logWriter)
		d.tokens = make(map[string][]byte)
	}
	d.writers[routingID] = w
	d.tokens[routingID] = routingToken(routingID) // Cache the token
}

func (d *prefixDispatchWriter) unregister(routingID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.writers, routingID)
	delete(d.tokens, routingID)
}

var (
	dispatchWriter    *prefixDispatchWriter
	sharedLoggerMutex sync.Mutex
	sharedLoggerInit  bool
)

// initSharedLogger installs the prefix-dispatching writer into the global FRP
// log.Logger once. Subsequent calls are no-ops (level is fixed at first call).
func initSharedLogger(logLevel string) {
	sharedLoggerMutex.Lock()
	defer sharedLoggerMutex.Unlock()

	if !sharedLoggerInit {
		dispatchWriter = &prefixDispatchWriter{
			writers: make(map[string]logWriter),
			tokens:  make(map[string][]byte),
		}
		sharedLoggerInit = true
		log.InitLogger("", logLevel, 7, true)
		log.Logger = log.Logger.WithOptions(golib_log.WithOutput(dispatchWriter))
	}
}

// registerInstanceWriter maps a routing UUID to a writer.
// Must be called before svr.Run() so that the first log lines are captured.
func registerInstanceWriter(routingID string, w logWriter) {
	if dispatchWriter != nil {
		dispatchWriter.register(routingID, w)
	}
}

// unregisterInstanceWriter removes the writer for the given routing UUID.
func unregisterInstanceWriter(routingID string) {
	if dispatchWriter != nil {
		dispatchWriter.unregister(routingID)
	}
}

func resetSharedLogger() {
	sharedLoggerMutex.Lock()
	defer sharedLoggerMutex.Unlock()

	dispatchWriter = nil
	sharedLoggerInit = false
	log.InitLogger("", "info", 7, true)
}
