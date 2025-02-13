package keymanagement

import (
	"aws/ethereum-signer/internal/types"
	"encoding/base64"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/net/context"
	"os"
	"testing"
)

const CiphertextForRecipientB64 = "MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAg898CKVBqrNfD8U7ZohZms68btEvMiu/aHunx0qvk2oEwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQAvKYW8jMsvWf3A7zHMmRa9Ko7/lWnOa9lBcamoabqSPAjUe2Hp1bR/iIFrc/1fmdBGpixO3YeUlKVagzO8sksDFTPMYfLJAFWXosxrKjicWT79zEAxWAzZtj6OTr5MBK+kzlEaiR25Lihts4QGVi3l94e7w4LcPLHrXJp+xSEIqv5ttAN65uCTCPiKV9KOJqQJnIv6AM0n4CADmkK9OH2rGfwTErpGAfLVmQzU4jNzYYlucnPYGeGB5FnyGVCybU6F8dhce7pzvg4fTW4VMjSxMSCEzZUYkWINF3GP7hQW2OJCtOdOT/4LypL4G+ts9v6pLDqsN2aWu6Guxkhx4TJTMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEO+jHoApImXndcYDXJCwxbWggASBoBb7hNObeGBPstJaCKBerxcJX+qsGyiajD4927XBu+zmD7DloS10QznG/w71FgxW7N1donMmmWi33KzqHZ1rOJawPm7jYDoanX3+Kp9kYiemO2iYp+Eujr4yjEsLlcZyWmLMP0EOjd7phL16duEnYG9SYk6KmZlwnm4DO95q/bvFp1tKYaANT3uTaUPP7uYc55rEqp8bCd0QX3ZHSD5A0n0AAAAAAAAAAAAA"
const PrivateKeyB64 = "MIIEpAIBAAKCAQEAxGk1BnKDygnEWPxS2HONDCsdSUPtLwZwJ78tX1BkNOyEXt5FuBJpGtpUBAEunJmybgBfieT3o/j3VXWM88r1o9huVTcXIlPQUEymPMZ/uCR4CYy4WpFT3L9R7iO922zscc/EtdP87HaFTWELETZmlHDirNAcX+k5gpb3FA9BnHDYSCTjoIM9VEcetU/mC8bbU08J5eQMiNR5j+tBVaTtYD4sFF/Yv+QnlO3HRr040etCIzOD+2qkwuKDmBldu8HkatMidzghsidpyIpeSM7c2bJb+gmqqI262eIPgtKvrYbJa2SfJ5QPXuOQ8rkk1lm+POHyNLiTQD1EwlLf7SMoSwIDAQABAoIBAHT4iwG59U6/nlW4f8Y0ms2iZ6CYeYrF9MlXC7h18hequ/KbwT2siTfayqpP4eiViDQGuN8wo2LeBL66cSVHvB7F6H+LfZWOAMOxwlbziGCsJ2jYi3o0jpMqxapjUtB5AB+PswDurPROaXj50FOB6HmC+RweHKfqB7wEGEW0CEkXxzKQxliXjyH56s2O+YV7CEGOaPm2FDh4hDvo5/tdvBIyntFOgAHZ0snPcbaDJ6t/mzwfyb2U8haNQt1HIlhJ0RYrKg8Ma2sXOMiJzwkk4USE3czmkOc08CGGSROzxJwFAheECQx6az/Xgl4iopdtpNLeN/mRBayjL3VyoJkMt0ECgYEAzStKBGsKWJwxpWGoa3lXCMkpSsgvBIRSYhbBvowb3VXpjEIrmoCnojQKcD8GS3Rtfd9qAw8tc6RWdWHNOAFyM29yH/yHF7usAHZr9cXq9rtko4pQYLOH3nhFW8K+bbhf/1mroz/C/AqFObSDU4h4mFZql3FsUDxkb4FF6RP4rDsCgYEA9RJwel/EAnKhM/YtDbBNmVc+qt++Tmfi3AGOjBzI6Yao1f/YskLlwOyKvkvUy8Py0JWf1Ae656lDJhwZwAOCYkKfLMimPVmFBx7B6kuwlAC/Ywah1cIjhne9WWSPxpilJGxhjE5uGeMMnRK0OA7YbD/VRlOGZ/9KFME2zDC4gzECgYEAlqGVsjC0Y+IpQPa2JFHt6HFoc5MNkg9kPMfgbvmG67XLxkI+qSyT5q62izp6cKOGT8fbmWtnP2QEZiHr/ZZyNfk4nOtWc8JBwgUvtj4dCBEFDlzaLmUg9+DtazVLglq/gEZhkXWavlkq/vbdBFNJ1u57S7zmfPIZ+xO6NCmJhUkCgYAM9vPCVYyeAIhsokpR3hDM2uOy0HFV3oMO1no/CUrLp9cIsyc4jvdulFTmqkZQnUYcKL4yzlHh7X9i5buq/8SHBDU9fkPlHPY/oS3rAiQOQFffmjs3frS4aV83+mzsuaiK27zxWjjS38MMEDA+gvKKD3pt5P9IQyYdIPeQJ8erEQKBgQDLxwCIMA/upR8cJ2vKCCPZiyG18MHVqClHJ3GOKeAlALUD7qZcPrIy1XPEmSy+BR2ZWqN9C8sg02S47I0CkuRuoas+VzmS9/zbnmn6SPjc1OS9IArPkHXbGY0b6HbYqC6WkzsZnxoVQyTzgzb+XOkFjToNn+q++7NSWKBboZAexQ=="

// Mock implementations for testing
type MockAttestationProvider struct {
	mock.Mock
}

func (m *MockAttestationProvider) GetAttestationDoc(nonce []byte, userData []byte, publicKey []byte) ([]byte, error) {
	args := m.Called(nonce, userData, publicKey)
	return args.Get(0).([]byte), args.Error(1)
}

type MockKMSProvider struct {
	mock.Mock
}

func (m *MockKMSProvider) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	args := m.Called(ctx, params, optFns)
	return args.Get(0).(*kms.EncryptOutput), args.Error(1)
}

func (m *MockKMSProvider) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	args := m.Called(ctx, params, optFns)
	return args.Get(0).(*kms.DecryptOutput), args.Error(1)
}

// Test implementation
func TestDecryptCiphertextWithAttestation(t *testing.T) {
	type testCase struct {
		name           string
		ciphertext     string
		setupMocks     func(*MockAttestationProvider, *MockKMSProvider)
		env            map[string]string
		expectedError  string
		expectedResult types.PlainKey
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString([]byte("base64EncodedTestData"))
	ciphertextForRecipient, _ := base64.StdEncoding.DecodeString(CiphertextForRecipientB64)

	testCases := []testCase{
		{
			name:       "successful decryption",
			ciphertext: ciphertextB64,

			setupMocks: func(ma *MockAttestationProvider, mk *MockKMSProvider) {
				// Setup attestation mock
				ma.On("GetAttestationDoc",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					//	todo attestation doc should be enclosed in kms request -> intercept??
				).Return([]byte("mock-attestation-doc"), nil)

				// Setup KMS mock
				mk.On("Decrypt",
					mock.Anything, // context
					mock.MatchedBy(func(input *kms.DecryptInput) bool {
						// Add validation logic if needed
						return true
					}),
					mock.Anything,
				).Return(&kms.DecryptOutput{
					// todo return CFR with matching priv/pub key
					CiphertextForRecipient: ciphertextForRecipient,
				}, nil)
			},
			env: map[string]string{
				"RSA_PRIVATE_KEY": PrivateKeyB64,
			},
			expectedResult: types.PlainKey{
				Secret: "9779d2b8f0bc495b1691ce1a2baf800453e18a58d4eea8bf1fe996a0ab291dba",
				EthKey: "25e82557e8d2d154503f8e371a36b27b067c5c60793737e76313de1a431e8099"},
		},
		{
			name:       "attestation error",
			ciphertext: "base64EncodedTestData",
			setupMocks: func(ma *MockAttestationProvider, mk *MockKMSProvider) {
				ma.On("GetAttestationDoc",
					mock.Anything,
					mock.Anything,
					mock.Anything,
				).Return([]byte{}, errors.New("attestation failed"))
			},
			expectedError: "attestation failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mocks
			mockAttestation := &MockAttestationProvider{}
			mockKMS := &MockKMSProvider{}

			// Setup mocks
			tc.setupMocks(mockAttestation, mockKMS)

			// Setup environment
			for k, v := range tc.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			// Test options
			opts := &AdvancedDecOpts{
				EphemeralRSAKey: false,
			}

			// Call function
			result, err := DecryptCiphertextWithAttestation(
				tc.ciphertext,
				opts,
				mockAttestation,
				mockKMS,
			)

			resultParsed, _ := ParsePlaintext(result)
			// Verify results
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, resultParsed)
			}

			// Verify all mock expectations were met
			mockAttestation.AssertExpectations(t)
			mockKMS.AssertExpectations(t)
		})
	}
}
