package metrics

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	server := NewServer(9090)
	require.NotNil(t, server, "NewServer returned nil")

	if server.port != 9090 {
		t.Errorf("NewServer port = %d, want 9090", server.port)
	}
}

func TestServerStartStop(t *testing.T) {
	server := NewServer(0) // Use random port

	// Start server
	if err := server.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Stop server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestStartFunction(t *testing.T) {
	server, err := Start(0) // Use random port
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	if server == nil {
		require.Fail(t, "Start() returned nil server")
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Clean up
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestRecordConnectionStart(_ *testing.T) {
	// Reset metrics
	ActiveConnections.Set(0)

	RecordConnectionStart("client1")
	RecordConnectionStart("client2")

	// We can't easily check the actual metric value without
	// using the prometheus registry, but we can verify no panics
}

func TestRecordConnectionEnd(_ *testing.T) {
	duration := 5 * time.Second
	RecordConnectionEnd(duration)
	// Verify no panics
}

func TestRecordStreamOpen(_ *testing.T) {
	RecordStreamOpen("tcp")
	RecordStreamOpen("udp")
	RecordStreamOpen("control")
	// Verify no panics
}

func TestRecordStreamClose(_ *testing.T) {
	RecordStreamClose("tcp")
	RecordStreamClose("udp")
	// Verify no panics
}

func TestRecordStreamError(_ *testing.T) {
	RecordStreamError("tcp")
	RecordStreamError("udp")
	// Verify no panics
}

func TestRecordBytesTransferred(_ *testing.T) {
	RecordBytesTransferred("tcp", "sent", 1024)
	RecordBytesTransferred("tcp", "received", 2048)
	RecordBytesTransferred("udp", "sent", 512)
	// Verify no panics
}

func TestRecordAuthAttempt(_ *testing.T) {
	RecordAuthAttempt(true)
	RecordAuthAttempt(false)
	// Verify no panics
}

func TestRecordStreamLatency(_ *testing.T) {
	duration := 100 * time.Millisecond
	RecordStreamLatency("tcp", "open", duration)
	RecordStreamLatency("udp", "close", duration)
	RecordStreamLatency("tcp", "data_transfer", duration)
	// Verify no panics
}

func TestRecordStreamReconnect(_ *testing.T) {
	RecordStreamReconnect("tcp")
	RecordStreamReconnect("udp")
	// Verify no panics
}

func TestSetUDPSessionCount(_ *testing.T) {
	SetUDPSessionCount(10)
	SetUDPSessionCount(0)
	SetUDPSessionCount(100)
	// Verify no panics
}

func TestMetricsEndpoint(t *testing.T) {
	// Start metrics server on random port
	server, err := Start(0)
	if err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Record some metrics
	RecordConnectionStart("test-client")
	RecordStreamOpen("tcp")
	RecordBytesTransferred("tcp", "sent", 1024)
	RecordAuthAttempt(true)

	// Note: We can't easily fetch metrics without knowing the actual port
	// since we used port 0 (random). This test mainly verifies the server
	// starts and the metric recording functions don't panic.
}

func TestMetricsHTTPResponse(t *testing.T) {
	// Start server on a known port
	testPort := 19090
	server, err := Start(testPort)
	if err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Record some test metrics
	RecordConnectionStart("test-client")
	RecordStreamOpen("tcp")

	// Try to fetch metrics
	resp, err := http.Get("http://localhost:19090/metrics")
	if err != nil {
		t.Skipf("Could not fetch metrics (port may be in use): %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Metrics endpoint status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Content-Type = %s, want text/plain", contentType)
	}
}

func TestConcurrentMetricRecording(_ *testing.T) {
	// Test concurrent access to metrics
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			clientID := "client-" + string(rune('0'+id))
			RecordConnectionStart(clientID)
			RecordStreamOpen("tcp")
			RecordBytesTransferred("tcp", "sent", 1024)
			RecordStreamClose("tcp")
			RecordConnectionEnd(time.Second)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we got here without panics, concurrent access works
}

func TestStopWithoutStart(t *testing.T) {
	server := NewServer(9091)
	// Stopping without starting should not panic
	err := server.Stop()
	if err != nil {
		t.Logf("Stop() returned error (expected): %v", err)
	}
}

func TestMultipleStops(t *testing.T) {
	server, err := Start(0)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Stop once
	if err := server.Stop(); err != nil {
		t.Errorf("First Stop() failed: %v", err)
	}

	// Stop again - should not panic
	err = server.Stop()
	if err != nil {
		t.Logf("Second Stop() returned error (expected): %v", err)
	}
}
