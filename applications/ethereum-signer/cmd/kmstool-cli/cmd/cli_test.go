package cmd

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestDecryptCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		input   string
		golden  string
		wantErr bool
	}{
		{
			// golden path
			// todo extend mocking to cli - just ensuring correct parameter combination right now
			name: "basic_decrypt",
			args: []string{
				"decrypt",
				"--region", "us-west-2",
				"--ciphertext", "SGVsbG8gV29ybGQ=", // base64 encoded
				"--proxy-port", "8000",
				"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
				"--aws-secret-access-key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"--aws-session-token", "SESSION_TOKEN",
			},
			env: map[string]string{
				"RSA_PRIVATE_KEY": "test-key",
			},
			wantErr: true,
			golden:  "testdata/basic_decrypt_missing_nsm.golden",
		},
		{
			name: "missing_region",
			args: []string{
				"decrypt",
				"--key-id", "test-key-id",
				"--ciphertext", "SGVsbG8gV29ybGQ=",
			},
			wantErr: true,
			golden:  "testdata/missing_region.golden",
		},
		{
			name: "invalid_encryption_algorithm",
			args: []string{
				"decrypt",
				"--region", "us-west-2",
				"--proxy-port", "8000",
				"--aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
				"--aws-secret-access-key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"--aws-session-token", "SESSION_TOKEN",
				"--ciphertext", "SGVsbG8gV29ybGQ=", // base64 encoded
				"--ephemeral-key", "false",
			},
			wantErr: true,
			golden:  "testdata/basic_decrypt_ephemeral-key.golden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//
			rootCmd := NewRootCmd()

			// Setup environment
			for k, v := range tt.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			// Capture stdout and err out
			oldStdout := os.Stdout
			oldStderr := os.Stderr

			rOut, wOut, _ := os.Pipe()
			rErr, wErr, _ := os.Pipe()

			os.Stdout = wOut
			os.Stderr = wErr

			// Execute command
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Restore stdout
			wOut.Close()
			wErr.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			// Read captured output
			var stdoutBuf, stderrBuf bytes.Buffer
			io.Copy(&stdoutBuf, rOut)
			io.Copy(&stderrBuf, rErr)
			output := stdoutBuf.String()
			errorOutput := stderrBuf.String()

			// Combine output if needed
			combinedOutput := output
			if errorOutput != "" {
				combinedOutput = output + errorOutput
			}

			// Handle error cases
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Update golden files if flag is set
			if *update {
				if err := os.MkdirAll(filepath.Dir(tt.golden), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(tt.golden, []byte(combinedOutput), 0644); err != nil {
					t.Fatal(err)
				}
			}

			// Compare with golden file
			expected, err := os.ReadFile(tt.golden)
			if err != nil {
				t.Fatal(err)
			}

			if combinedOutput != string(expected) {
				t.Errorf("output differs from golden file:\ngot:\n%s\nwant:\n%s",
					combinedOutput, string(expected))
			}
		})
	}
}
