package server

import (
	"testing"
	"time"

	"github.com/uwaserver/uwas/internal/config"
	"github.com/uwaserver/uwas/internal/logger"
)

// F3100: the HTTP/3 listener ignored global.timeouts.max_header_bytes and
// idle, so a configured 431 limit only held on TCP.
func TestHTTP3HonoursConfiguredLimits(t *testing.T) {
	cfg := &config.Config{Global: config.GlobalConfig{WorkerCount: "1", LogLevel: "error", LogFormat: "text",
		HTTPSListen: "127.0.0.1:0", HTTP3Enabled: true}}
	cfg.Global.Timeouts.MaxHeaderBytes = 4096
	cfg.Global.Timeouts.Idle.Duration = 7 * time.Second
	s := New(cfg, logger.New("error", "text"))
	if err := s.startHTTP3(); err != nil {
		t.Fatal(err)
	}
	defer s.h3srv.Close()
	if s.h3srv.MaxHeaderBytes != 4096 || s.h3srv.IdleTimeout != 7*time.Second {
		t.Errorf("h3 limits: MaxHeaderBytes=%d IdleTimeout=%v", s.h3srv.MaxHeaderBytes, s.h3srv.IdleTimeout)
	}
}
