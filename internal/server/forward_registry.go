// Package server provides server-side connection management and resource limiting.
package server

import (
	"fmt"
	"sync"

	"github.com/piwi3910/tunnelor/internal/config"
)

// ForwardInfo represents a configured reverse tunnel forward
type ForwardInfo struct {
	ID       string // Unique identifier for this forward
	Local    string // Public address to listen on (e.g., "0.0.0.0:8080")
	Remote   string // Address the client should connect to (e.g., "localhost:3000")
	Proto    string // Protocol: "tcp" or "udp"
	ClientID string // Which client should handle this forward
}

// ForwardRegistry tracks configured reverse tunnel forwards
type ForwardRegistry struct {
	forwards map[string]*ForwardInfo // key: forward ID
	mu       sync.RWMutex
}

// NewForwardRegistry creates a new forward registry
func NewForwardRegistry() *ForwardRegistry {
	return &ForwardRegistry{
		forwards: make(map[string]*ForwardInfo),
	}
}

// AddForward adds a forward to the registry
func (fr *ForwardRegistry) AddForward(fwd *ForwardInfo) error {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	if _, exists := fr.forwards[fwd.ID]; exists {
		return fmt.Errorf("forward with ID %s already exists", fwd.ID)
	}

	fr.forwards[fwd.ID] = fwd
	return nil
}

// RemoveForward removes a forward from the registry
func (fr *ForwardRegistry) RemoveForward(id string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	delete(fr.forwards, id)
}

// GetForward retrieves a forward by ID
func (fr *ForwardRegistry) GetForward(id string) (*ForwardInfo, bool) {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	fwd, exists := fr.forwards[id]
	return fwd, exists
}

// GetForwardsByClient returns all forwards for a specific client
func (fr *ForwardRegistry) GetForwardsByClient(clientID string) []*ForwardInfo {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	var result []*ForwardInfo
	for _, fwd := range fr.forwards {
		if fwd.ClientID == clientID {
			result = append(result, fwd)
		}
	}
	return result
}

// GetAllForwards returns all configured forwards
func (fr *ForwardRegistry) GetAllForwards() []*ForwardInfo {
	fr.mu.RLock()
	defer fr.mu.RUnlock()

	result := make([]*ForwardInfo, 0, len(fr.forwards))
	for _, fwd := range fr.forwards {
		result = append(result, fwd)
	}
	return result
}

// LoadFromConfig loads forwards from server configuration
func (fr *ForwardRegistry) LoadFromConfig(forwards []config.ServerForwardConfig) error {
	for i, fwdCfg := range forwards {
		fwd := &ForwardInfo{
			ID:       fmt.Sprintf("fwd-%d", i),
			Local:    fwdCfg.Local,
			Remote:   fwdCfg.Remote,
			Proto:    fwdCfg.Proto,
			ClientID: fwdCfg.ClientID,
		}

		if err := fr.AddForward(fwd); err != nil {
			return fmt.Errorf("failed to add forward %d: %w", i, err)
		}
	}
	return nil
}

// Count returns the number of forwards in the registry
func (fr *ForwardRegistry) Count() int {
	fr.mu.RLock()
	defer fr.mu.RUnlock()
	return len(fr.forwards)
}
