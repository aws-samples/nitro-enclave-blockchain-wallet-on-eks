package keymanagement

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	"fmt"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

// Mock DDB Provider
type MockDDBProvider struct {
	mock.Mock
}

func (m *MockDDBProvider) PutItem(ctx context.Context, params *ddb.PutItemInput, optFns ...func(*ddb.Options)) (*ddb.PutItemOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ddb.PutItemOutput), args.Error(1)
}

func TestEncryptAndSaveKey(t *testing.T) {
	tests := []struct {
		name          string
		keyARN        string
		secretTable   string
		plainKey      signerTypes.PlainKey
		address       string
		kmsError      error
		ddbError      error
		expectedError bool
	}{
		{
			name:          "successful encryption and storage",
			keyARN:        "arn:aws:kms:region:account:key/test",
			secretTable:   "test-table",
			plainKey:      signerTypes.PlainKey{ /* fill with test data */ },
			address:       "0x123",
			kmsError:      nil,
			ddbError:      nil,
			expectedError: false,
		},
		{
			name:          "dynamodb storage fails",
			keyARN:        "arn:aws:kms:region:account:key/test",
			secretTable:   "test-table",
			plainKey:      signerTypes.PlainKey{ /* fill with test data */ },
			address:       "0x123",
			kmsError:      nil,
			ddbError:      fmt.Errorf("DynamoDB put failed"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockKMS := new(MockKMSProvider)
			mockDDB := new(MockDDBProvider)

			// Setup KMS mock expectations
			if tt.kmsError == nil {
				mockKMS.On("Encrypt", mock.Anything, mock.Anything, mock.Anything).Return(
					&kms.EncryptOutput{
						CiphertextBlob: []byte("encrypted-data"),
					},
					nil,
				)
			} else {
				mockKMS.On("Encrypt", mock.Anything, mock.Anything, mock.Anything).Return(
					nil,
					tt.kmsError,
				)
			}

			// Setup DDB mock expectations
			if tt.ddbError == nil {
				mockDDB.On("PutItem", mock.Anything, mock.Anything).Return(
					&ddb.PutItemOutput{},
					nil,
				)
			} else {
				mockDDB.On("PutItem", mock.Anything, mock.Anything).Return(
					nil,
					tt.ddbError,
				)
			}

			// Execute test
			secretID, err := EncryptAndSaveKey(
				mockKMS,
				mockDDB,
				tt.keyARN,
				tt.secretTable,
				tt.plainKey,
				tt.address,
			)

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Empty(t, secretID)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, secretID)
			}

			// Verify mock expectations
			mockKMS.AssertExpectations(t)
			mockDDB.AssertExpectations(t)
		})
	}
}
