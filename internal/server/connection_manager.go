// Package server provides server-side connection management and resource limiting.
package server

import (
	"fmt"
	"sync"
)

// ConnectionManager tracks active connections and enforces resource limits
type ConnectionManager struct {
	mu                      sync.RWMutex
	connections             map[string]int // client_id -> connection count
	totalConnections        int
	maxConnectionsPerClient int
	maxTotalConnections     int
}

// NewConnectionManager creates a new connection manager with specified limits
func NewConnectionManager(maxPerClient, maxTotal int) *ConnectionManager {
	return &ConnectionManager{
		connections:             make(map[string]int),
		maxConnectionsPerClient: maxPerClient,
		maxTotalConnections:     maxTotal,
	}
}

// CanAccept checks if a new connection from the given client can be accepted
func (cm *ConnectionManager) CanAccept(clientID string) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Check total connection limit (0 = unlimited)
	if cm.maxTotalConnections > 0 && cm.totalConnections >= cm.maxTotalConnections {
		return fmt.Errorf("server connection limit reached (%d connections)", cm.maxTotalConnections)
	}

	// Check per-client connection limit (0 = unlimited)
	if cm.maxConnectionsPerClient > 0 {
		clientConns := cm.connections[clientID]
		if clientConns >= cm.maxConnectionsPerClient {
			return fmt.Errorf("client connection limit reached (%d connections for %s)", cm.maxConnectionsPerClient, clientID)
		}
	}

	return nil
}

// AddConnection registers a new connection for the given client
func (cm *ConnectionManager) AddConnection(clientID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.connections[clientID]++
	cm.totalConnections++
}

// RemoveConnection unregisters a connection for the given client
func (cm *ConnectionManager) RemoveConnection(clientID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if count, exists := cm.connections[clientID]; exists {
		if count <= 1 {
			delete(cm.connections, clientID)
		} else {
			cm.connections[clientID]--
		}
		cm.totalConnections--
	}
}

// GetConnectionCount returns the current connection count for a specific client
func (cm *ConnectionManager) GetConnectionCount(clientID string) int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.connections[clientID]
}

// GetTotalConnectionCount returns the total number of active connections
func (cm *ConnectionManager) GetTotalConnectionCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.totalConnections
}

// GetStats returns connection statistics
func (cm *ConnectionManager) GetStats() (totalConns, uniqueClients int) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.totalConnections, len(cm.connections)
}
