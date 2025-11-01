package quic

import "errors"

// Common QUIC errors
var (
	ErrConnectionClosed   = errors.New("connection closed")
	ErrStreamClosed       = errors.New("stream closed")
	ErrStreamNotFound     = errors.New("stream not found")
	ErrTimeout            = errors.New("operation timeout")
	ErrInvalidConfig      = errors.New("invalid configuration")
	ErrTLSConfig          = errors.New("TLS configuration error")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrMaxStreamsExceeded = errors.New("maximum streams exceeded")
)

// ErrorCode represents QUIC application error codes
type ErrorCode uint64

const (
	// ErrorCodeNoError indicates no error
	ErrorCodeNoError ErrorCode = 0x0

	// ErrorCodeProtocolViolation indicates a protocol violation
	ErrorCodeProtocolViolation ErrorCode = 0x1

	// ErrorCodeInternalError indicates an internal error
	ErrorCodeInternalError ErrorCode = 0x2

	// ErrorCodeConnectionRefused indicates connection was refused
	ErrorCodeConnectionRefused ErrorCode = 0x3

	// ErrorCodeFlowControlError indicates a flow control error
	ErrorCodeFlowControlError ErrorCode = 0x4

	// ErrorCodeStreamLimitError indicates stream limit was exceeded
	ErrorCodeStreamLimitError ErrorCode = 0x5

	// ErrorCodeStreamStateError indicates an invalid stream state
	ErrorCodeStreamStateError ErrorCode = 0x6

	// ErrorCodeAuthenticationFailed indicates authentication failed
	ErrorCodeAuthenticationFailed ErrorCode = 0x10
)

// String returns the string representation of the error code
func (ec ErrorCode) String() string {
	switch ec {
	case ErrorCodeNoError:
		return "NO_ERROR"
	case ErrorCodeProtocolViolation:
		return "PROTOCOL_VIOLATION"
	case ErrorCodeInternalError:
		return "INTERNAL_ERROR"
	case ErrorCodeConnectionRefused:
		return "CONNECTION_REFUSED"
	case ErrorCodeFlowControlError:
		return "FLOW_CONTROL_ERROR"
	case ErrorCodeStreamLimitError:
		return "STREAM_LIMIT_ERROR"
	case ErrorCodeStreamStateError:
		return "STREAM_STATE_ERROR"
	case ErrorCodeAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	default:
		return "UNKNOWN"
	}
}
