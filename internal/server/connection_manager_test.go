package server

import (
	"fmt"
	"strings"
	"testing"


	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require")

func TestNewConnectionManager(t *testing.T) {
	cm := NewConnectionManager(10, 100)
	require.NotNil(t, cm, "NewConnectionManager returned nil")

	if cm.maxConnectionsPerClient != 10 {
		t.Errorf("maxConnectionsPerClient = %d, want 10", cm.maxConnectionsPerClient)
	}

	if cm.maxTotalConnections != 100 {
		t.Errorf("maxTotalConnections = %d, want 100", cm.maxTotalConnections)
	}

	total, clients := cm.GetStats()
	if total != 0 || clients != 0 {
		t.Errorf("GetStats() = (%d, %d), want (0, 0)", total, clients)
	}
}

func TestCanAccept_NoLimits(t *testing.T) {
	cm := NewConnectionManager(0, 0) // No limits

	// Should accept unlimited connections
	for i := 0; i < 1000; i++ {
		if err := cm.CanAccept("client1"); err != nil {
			t.Errorf("CanAccept() with no limits returned error: %v", err)
		}
		cm.AddConnection("client1")
	}

	if count := cm.GetConnectionCount("client1"); count != 1000 {
		t.Errorf("GetConnectionCount() = %d, want 1000", count)
	}
}

func TestCanAccept_PerClientLimit(t *testing.T) {
	cm := NewConnectionManager(5, 0) // 5 per client, no total limit

	// Add 5 connections for client1 - should succeed
	for i := 0; i < 5; i++ {
		if err := cm.CanAccept("client1"); err != nil {
			t.Fatalf("CanAccept() connection %d failed: %v", i, err)
		}
		cm.AddConnection("client1")
	}

	// Try to add 6th connection - should fail
	err := cm.CanAccept("client1")
	if err == nil {
		assert.Fail(t, "CanAccept() should have failed at per-client limit")
	}
	if !strings.Contains(err.Error(), "client connection limit") {
		t.Errorf("Error message should mention client limit, got: %v", err)
	}

	// Different client should still be able to connect
	if err := cm.CanAccept("client2"); err != nil {
		t.Errorf("CanAccept() for different client failed: %v", err)
	}
}

func TestCanAccept_TotalLimit(t *testing.T) {
	cm := NewConnectionManager(0, 10) // No per-client limit, 10 total

	// Add 10 connections from different clients
	for i := 0; i < 10; i++ {
		clientID := fmt.Sprintf("client%d", i)
		if err := cm.CanAccept(clientID); err != nil {
			t.Fatalf("CanAccept() connection %d failed: %v", i, err)
		}
		cm.AddConnection(clientID)
	}

	// Try to add 11th connection - should fail
	err := cm.CanAccept("client11")
	if err == nil {
		assert.Fail(t, "CanAccept() should have failed at total limit")
	}
	if !strings.Contains(err.Error(), "server connection limit") {
		t.Errorf("Error message should mention server limit, got: %v", err)
	}
}

func TestAddRemoveConnection(t *testing.T) {
	cm := NewConnectionManager(0, 0)

	// Add connections
	cm.AddConnection("client1")
	cm.AddConnection("client1")
	cm.AddConnection("client2")

	if count := cm.GetConnectionCount("client1"); count != 2 {
		t.Errorf("GetConnectionCount(client1) = %d, want 2", count)
	}

	if count := cm.GetConnectionCount("client2"); count != 1 {
		t.Errorf("GetConnectionCount(client2) = %d, want 1", count)
	}

	total, clients := cm.GetStats()
	if total != 3 || clients != 2 {
		t.Errorf("GetStats() = (%d, %d), want (3, 2)", total, clients)
	}

	// Remove connections
	cm.RemoveConnection("client1")
	if count := cm.GetConnectionCount("client1"); count != 1 {
		t.Errorf("GetConnectionCount(client1) after remove = %d, want 1", count)
	}

	cm.RemoveConnection("client1")
	if count := cm.GetConnectionCount("client1"); count != 0 {
		t.Errorf("GetConnectionCount(client1) after second remove = %d, want 0", count)
	}

	// Client1 should be removed from map
	total, clients = cm.GetStats()
	if total != 1 || clients != 1 {
		t.Errorf("GetStats() after removes = (%d, %d), want (1, 1)", total, clients)
	}

	// Removing non-existent connection should not panic
	cm.RemoveConnection("client3")
}

func TestConcurrentAccess(t *testing.T) {
	cm := NewConnectionManager(100, 1000)
	done := make(chan bool)

	// Simulate concurrent connection additions
	for i := 0; i < 10; i++ {
		go func(id int) {
			clientID := fmt.Sprintf("client%d", id%3) // 3 different clients
			for j := 0; j < 100; j++ {
				if err := cm.CanAccept(clientID); err == nil {
					cm.AddConnection(clientID)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify counts are consistent
	total, _ := cm.GetStats()
	calculatedTotal := 0
	for i := 0; i < 3; i++ {
		clientID := fmt.Sprintf("client%d", i)
		calculatedTotal += cm.GetConnectionCount(clientID)
	}

	if total != calculatedTotal {
		t.Errorf("Total count mismatch: GetStats()=%d, calculated=%d", total, calculatedTotal)
	}
}

func TestBothLimitsEnforced(t *testing.T) {
	cm := NewConnectionManager(3, 5) // 3 per client, 5 total

	// Add 3 connections for client1
	for i := 0; i < 3; i++ {
		if err := cm.CanAccept("client1"); err != nil {
			t.Fatalf("CanAccept() client1 connection %d failed: %v", i, err)
		}
		cm.AddConnection("client1")
	}

	// Add 2 connections for client2
	for i := 0; i < 2; i++ {
		if err := cm.CanAccept("client2"); err != nil {
			t.Fatalf("CanAccept() client2 connection %d failed: %v", i, err)
		}
		cm.AddConnection("client2")
	}

	// Total limit (5) should be reached
	err := cm.CanAccept("client3")
	if err == nil {
		assert.Fail(t, "CanAccept() should have failed at total limit")
	}

	// Client1 should also be at per-client limit
	err = cm.CanAccept("client1")
	if err == nil {
		assert.Fail(t, "CanAccept() should have failed at per-client limit for client1")
	}

	// Client2 should also be blocked by total limit (even though under per-client limit)
	err = cm.CanAccept("client2")
	if err == nil {
		assert.Fail(t, "CanAccept() should have failed at total limit for client2")
	}
}
