package enclave

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/mock"
	"net"
	"testing"
	"time"
)

// MockConn is a mock implementation of net.Conn
type MockConn struct {
	mock.Mock
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Other required net.Conn interface methods...
// You'll need to implement these but they won't be used in our tests
func (m *MockConn) LocalAddr() net.Addr                { return nil }
func (m *MockConn) RemoteAddr() net.Addr               { return nil }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHandleError(t *testing.T) {
	testCases := []struct {
		name       string
		message    string
		status     int
		writeError error
		closeError error
	}{
		{
			name:       "500 error handling",
			message:    "internal server error",
			status:     500,
			writeError: nil,
			closeError: nil,
		},
		{
			name:       "403 error handling",
			message:    "forbidden access",
			status:     403,
			writeError: nil,
			closeError: nil,
		},
		{
			name:       "Write error handling",
			message:    "test message",
			status:     500,
			writeError: fmt.Errorf("write error"),
			closeError: nil,
		},
		{
			name:       "Close error handling",
			message:    "test message",
			status:     500,
			writeError: nil,
			closeError: fmt.Errorf("close error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockConn := new(MockConn)

			// Setup expected response
			expectedResponse, _ := json.Marshal(signerTypes.EnclaveResult{
				Status: tc.status,
				Body: signerTypes.SignedTransaction{
					Error: tc.message,
				},
			})

			// Setup expectations
			mockConn.On("Write", expectedResponse).Return(len(expectedResponse), tc.writeError)
			mockConn.On("Close").Return(tc.closeError)

			// Execute function
			HandleError(mockConn, tc.message, tc.status)

			// Verify all expectations were met
			mockConn.AssertExpectations(t)
		})
	}
}
