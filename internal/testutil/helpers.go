// Package testutil provides common test utilities and helpers for Tunnelor tests.
package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TableTest represents a single table-driven test case
type TableTest struct {
	Input   interface{}
	Want    interface{}
	Name    string
	ErrMsg  string
	WantErr bool
}

// RunTableTests executes a slice of table tests with a test function
func RunTableTests(t *testing.T, tests []TableTest, testFunc func(t *testing.T, tt TableTest)) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			testFunc(t, tt)
		})
	}
}

// AssertError checks if an error matches expected conditions
func AssertError(t *testing.T, err error, wantErr bool, errMsg string) {
	t.Helper()
	if wantErr {
		require.Error(t, err, "Expected an error but got nil")
		if errMsg != "" {
			assert.Contains(t, err.Error(), errMsg, "Error message should contain expected text")
		}
	} else {
		assert.NoError(t, err, "Expected no error but got: %v", err)
	}
}

// AssertEqual is a helper for deep equality checks with better error messages
func AssertEqual(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected, actual, msgAndArgs...)
}

// RequireNoError is a helper that stops the test immediately on error
func RequireNoError(t *testing.T, err error, msgAndArgs ...interface{}) {
	t.Helper()
	require.NoError(t, err, msgAndArgs...)
}

// RequireNotNil is a helper that stops the test immediately if value is nil
func RequireNotNil(t *testing.T, object interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	require.NotNil(t, object, msgAndArgs...)
}

// ValidationTest represents a table test for validation functions
type ValidationTest struct {
	Input     interface{}
	Name      string
	ErrString string
	WantErr   bool
}

// RunValidationTests executes validation table tests
func RunValidationTests(t *testing.T, tests []ValidationTest, validatorFunc func(interface{}) error) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			err := validatorFunc(tt.Input)
			AssertError(t, err, tt.WantErr, tt.ErrString)
		})
	}
}
