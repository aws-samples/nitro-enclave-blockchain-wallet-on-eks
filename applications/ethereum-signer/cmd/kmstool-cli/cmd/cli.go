package cmd

import (
	"aws/ethereum-signer/internal/attestation"
	aws2 "aws/ethereum-signer/internal/aws"
	"aws/ethereum-signer/internal/keymanagement"
	signerTypes "aws/ethereum-signer/internal/types"
	"encoding/base64"
	"fmt"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"

	// global flags
	verbose bool
)

type DecryptConfig struct {
	region              string
	proxyPort           int
	awsAccessKeyID      string
	awsSecretAccessKey  string
	awsSessionToken     string
	ciphertext          string
	keyID               string
	encryptionAlgorithm string
	encryptionContext   map[string]string
	ephemeralKeySwitch  bool
}

var decryptCfg DecryptConfig

func NewRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "kmstool-cli",
		Short:   "AWS KMS decryption tool written in Go(lang)",
		Version: Version,
		Run: func(cmd *cobra.Command, args []string) {
			err := cmd.Help()
			if err != nil {
				return
			}
		},
	}

	rootCmd.SetVersionTemplate(`Version: {{.Version}}
Build Time: ` + BuildTime)

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt ciphertext using AWS KMS",
		RunE:  runDecrypt,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// validate required flags
			if decryptCfg.region == "" {
				return fmt.Errorf("--region is required")
			}
			if decryptCfg.ciphertext == "" {
				return fmt.Errorf("--ciphertext is required")
			}
			if decryptCfg.keyID != "" && decryptCfg.encryptionAlgorithm == "" {
				return fmt.Errorf("--encryption-algorithm is required when --key-id is set")
			}

			if decryptCfg.encryptionAlgorithm != "" {
				_, err := supportedEncryptionAlgorithms(decryptCfg.encryptionAlgorithm)
				if err != nil {
					return fmt.Errorf("invalid encryption algorithm: %v", err)
				}
			}

			if decryptCfg.awsSessionToken == "" || decryptCfg.awsAccessKeyID == "" || decryptCfg.awsSecretAccessKey == "" {
				return fmt.Errorf("AWS credentials are required, --aws-access-key-id, --aws-secret-access-key, --aws-session-token have to be set")
			}

			// validate base64 ciphertext
			_, err := base64.StdEncoding.DecodeString(decryptCfg.ciphertext)
			if err != nil {
				return fmt.Errorf("invalid base64 ciphertext: %v", err)
			}

			return nil
		},
	}

	// add flags to decrypt command
	decryptCmd.Flags().StringVar(&decryptCfg.region, "region", "", "AWS region to use for KMS")
	decryptCmd.Flags().IntVar(&decryptCfg.proxyPort, "proxy-port", 8000, "Connect to KMS proxy on PORT")
	decryptCmd.Flags().StringVar(&decryptCfg.awsAccessKeyID, "aws-access-key-id", "", "AWS access key ID")
	decryptCmd.Flags().StringVar(&decryptCfg.awsSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key")
	decryptCmd.Flags().StringVar(&decryptCfg.awsSessionToken, "aws-session-token", "", "Session token associated with the access key ID")
	decryptCmd.Flags().StringVar(&decryptCfg.ciphertext, "ciphertext", "", "Base64-encoded ciphertext that need to decrypt")
	decryptCmd.Flags().StringVar(&decryptCfg.keyID, "key-id", "", "Decrypt key id (for symmetric keys)")
	decryptCmd.Flags().StringVar(&decryptCfg.encryptionAlgorithm, "encryption-algorithm", "SYMMETRIC_DEFAULT", "Encryption algorithm for ciphertext, defaults to SYMMETRIC_DEFAULT (only option for symmetric keys")
	decryptCmd.Flags().StringToStringVar(&decryptCfg.encryptionContext, "encryption-context", nil, "Encryption context key-value pairs")
	decryptCmd.Flags().BoolVar(&decryptCfg.ephemeralKeySwitch, "ephemeral-key", true,
		"If true, the RSA key used in the Recipient field is regenerated with every run. "+
			"If switch is set to false, key will be sourced from RSA_PRIVATE_KEY env variable. "+
			"If variable is empty, key will just be generated once and stored in RSA_PRIVATE_KEY. "+
			"RSA key is used by KMS in the CiphertextForRecipient structure which is a RecipientInfo structure, "+
			"as described in RFC5652 Section 6")

	rootCmd.AddCommand(decryptCmd)

	return rootCmd
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	if verbose {
		fmt.Printf("Decrypting with the following configuration:\n")
		fmt.Printf("Region: %s\n", decryptCfg.region)
		fmt.Printf("Proxy Port: %d\n", decryptCfg.proxyPort)
		fmt.Printf("AWS Access Key ID: %s\n", maskString(decryptCfg.awsAccessKeyID))
		fmt.Printf("AWS Secret Access Key: %s\n", maskString(decryptCfg.awsSecretAccessKey))
		fmt.Printf("AWS Session Token: %s\n", maskString(decryptCfg.awsSessionToken))
		fmt.Printf("Ciphertext: %s\n", decryptCfg.ciphertext)
		fmt.Printf("Key ID: %s\n", decryptCfg.keyID)
		fmt.Printf("Encryption Algorithm: %s\n", decryptCfg.encryptionAlgorithm)
		fmt.Printf("Encryption Context: %v\n", decryptCfg.encryptionContext)
		fmt.Printf("Ephemeral Key: %v\n", decryptCfg.ephemeralKeySwitch)
	}

	// credentials
	credentials := signerTypes.AWSCredentials{
		AccessKeyID:     decryptCfg.awsAccessKeyID,
		SecretAccessKey: decryptCfg.awsSecretAccessKey,
		Token:           decryptCfg.awsSessionToken,
	}

	// advanced decrypt options
	encALgo, err := supportedEncryptionAlgorithms(decryptCfg.encryptionAlgorithm)
	if err != nil {
		return fmt.Errorf("invalid encryption algorithm: %v", err)
	}
	advDecOpts := keymanagement.AdvancedDecOpts{
		EncryptionAlgorithm: encALgo,
		EncryptionContext:   decryptCfg.encryptionContext,
		KeyId:               decryptCfg.keyID,
		EphemeralRSAKey:     decryptCfg.ephemeralKeySwitch,
	}

	kmsProvider, err := keymanagement.NewAWSKMSProvider(credentials, decryptCfg.region, aws2.VSOCK, 3, uint32(decryptCfg.proxyPort))
	if err != nil {
		return fmt.Errorf("failed to create kms provider: %v", err)
	}
	plaintextB64, err := keymanagement.DecryptCiphertextWithAttestation(decryptCfg.ciphertext, &advDecOpts, &attestation.NitroAttestationProvider{}, kmsProvider)
	if err != nil {
		return fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	fmt.Printf("%v", plaintextB64)

	return nil
}

// supported encryption algorithms
func supportedEncryptionAlgorithms(encryptionAlgorithm string) (kmstypes.EncryptionAlgorithmSpec, error) {
	switch encryptionAlgorithm {
	case "SYMMETRIC_DEFAULT":
		return kmstypes.EncryptionAlgorithmSpecSymmetricDefault, nil
	case "RSAES_OAEP_SHA_1":
		return kmstypes.EncryptionAlgorithmSpecRsaesOaepSha1, nil
	case "RSAES_OAEP_SHA_256":
		return kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256, nil
	default:
		return "", fmt.Errorf("only SYMMETRIC_DEFAULT, RSAES_OAEP_SHA_1 and RSAES_OAEP_SHA_256 are supported. Please see https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/docs/kms-apis/Decrypt.md#encryptionalgorithm for more information: %s", encryptionAlgorithm)
	}
}

// helper function to mask sensitive information
func maskString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:4] + "****"
}
