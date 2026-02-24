/*
Copyright 2026 Yudhisitra Arief Wibowo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/spf13/cobra"
)

type PCRAllowList struct {
	Sha256 []string `yaml:"sha256" json:"sha256"`
}

// Mapping of each PCR index to its sha256 allowlist
type PCRMap map[int]PCRAllowList

type ZKPStatement struct {
	MinimalFirmwareVersion uint64   `yaml:"minimal_firmware_version" json:"minimal_firmware_version"`
	SecureBootEnabled      bool     `yaml:"secure_boot_enabled" json:"secure_boot_enabled"`
	KernelAllowList        []string `yaml:"kernel_allowlist" json:"kernel_allowlist"`
	PCRs                   PCRMap   `yaml:"pcrs" json:"pcrs"`
}

type TpmCmdFlags struct {
	// Common Flags
	PolicyFilePath string

	// TPM
	DevicePath               string `yaml:"device_path"`
	Nonce                    string `yaml:"nonce"`
	QuoteOutputPath          string `yaml:"quote_output"`
	QuoteSignatureOutputPath string `yaml:"quote_signature_output"`

	// ZKP
	ProofOutputPath string       `yaml:"proof_output"`
	Statement       ZKPStatement `yaml:"zkp_statement"`
}

var tpmCmdFlags TpmCmdFlags = TpmCmdFlags{
	Statement: ZKPStatement{},
}

type ProveOutput struct {
	Proof        []byte       `json:"proof"`
	AKPublicKeyX []byte       `json:"ak_public_key_x"` // Longfellow prove does not require the AK certificate, public key is enough
	AKPublicKeyY []byte       `json:"ak_public_key_y"`
	Statement    ZKPStatement `json:"zkp_statement"`
}

var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Commands related to TPM operations",
	Long:  "This command group contains subcommands for performing various TPM operations.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := parseYaml(cmd); err != nil {
			return err
		}
		return nil
	},
}

var tpmProveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Create a TPM quote zero knowledge proof",
	Long:  "Create a TPM quote zero knowledge proof for the current platform state.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(tpmCmdFlags.Statement.KernelAllowList) > 5 {
			return fmt.Errorf("kernel allow list cannot contain more than 5 entries")
		}

		if _, err := os.Stat(tpmCmdFlags.DevicePath); os.IsNotExist(err) {
			return fmt.Errorf("TPM device not found at %q: %w", tpmCmdFlags.DevicePath, err)
		}

		pcrCount, err := getPCRCount(tpmCmdFlags.DevicePath)
		if err != nil {
			return fmt.Errorf("getting PCR count: %w", err)
		}

		for pcrIndex := range tpmCmdFlags.Statement.PCRs {
			if uint16(pcrIndex) >= pcrCount {
				return fmt.Errorf("PCR index %d is out of bounds (max: %d)", pcrIndex, pcrCount-1)
			}

			if len(tpmCmdFlags.Statement.PCRs[pcrIndex].Sha256) > 5 {
				return fmt.Errorf("PCR %d allow list cannot contain more than 5 entries", pcrIndex)
			}
		}

		if tpmCmdFlags.Nonce == "" {
			nonce, err := generateSecureNonce()
			if err != nil {
				return fmt.Errorf("generating secure nonce: %w", err)
			} else {
				fmt.Printf("Using nonce: %s\n", nonce)
			}
			tpmCmdFlags.Nonce = nonce
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		tpm, err := openTPM(tpmCmdFlags.DevicePath)
		if err != nil {
			return fmt.Errorf("opening TPM: %w", err)
		}
		defer tpm.Close()

		akHandle, akName, err := createAttestationKey(tpm)
		if err != nil {
			return fmt.Errorf("creating attestation key: %w", err)
		}
		defer func() {
			_, _ = tpm2.FlushContext{FlushHandle: akHandle}.Execute(tpm)
		}()

		// Get quote from TPM
		quote, err := createTPMQuote(tpm, akHandle, akName)
		if err != nil {
			return fmt.Errorf("creating TPM quote: %w", err)
		}

		if tpmCmdFlags.QuoteOutputPath != "" {
			if err := os.WriteFile(tpmCmdFlags.QuoteOutputPath, quote.Quoted.Bytes(), 0644); err != nil {
				return fmt.Errorf("writing quote to file: %w", err)
			}
			fmt.Printf("Quote written to %s\n", tpmCmdFlags.QuoteOutputPath)
		}

		// Get signature from quote
		signature, err := quote.Signature.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("parsing quote signature: %w", err)
		}

		if tpmCmdFlags.QuoteSignatureOutputPath != "" {
			if err := os.WriteFile(tpmCmdFlags.QuoteSignatureOutputPath, signature.SignatureR.Buffer, 0644); err != nil {
				return fmt.Errorf("writing quote signature to file: %w", err)
			}
			fmt.Printf("Quote signature written to %s\n", tpmCmdFlags.QuoteSignatureOutputPath)
		}

		// Execute circuit and generate proof file
		proveOutput, err := generateProve(tpm, quote, tpmCmdFlags.Statement, akHandle)
		if err != nil {
			return fmt.Errorf("executing ZKP circuit: %w", err)
		}

		if tpmCmdFlags.ProofOutputPath != "" {
			outputBytes, err := json.Marshal(proveOutput)
			if err != nil {
				return fmt.Errorf("marshaling prove output: %w", err)
			}
			if err := os.WriteFile(tpmCmdFlags.ProofOutputPath, outputBytes, 0644); err != nil {
				return fmt.Errorf("writing prove output to file: %w", err)
			}
			fmt.Printf("Prove output written to %s\n", tpmCmdFlags.ProofOutputPath)
		}

		return nil
	},
}

var tpmVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a TPM quote zero knowledge proof",
	Long:  "Verify a TPM quote zero knowledge proof against the current platform state.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func generateProve(tpm transport.TPM, quote *tpm2.QuoteResponse, statement ZKPStatement, akHandle tpm2.TPMHandle) (ProveOutput, error) {
	readPublicResponse, err := tpm2.ReadPublic{ObjectHandle: akHandle}.Execute(tpm)
	if err != nil {
		return ProveOutput{}, fmt.Errorf("reading AK public area: %w", err)
	}

	content, err := readPublicResponse.OutPublic.Contents()
	if err != nil {
		return ProveOutput{}, fmt.Errorf("extracting AK public key: %w", err)
	}

	akPublicKey, err := content.Unique.ECC()
	if err != nil {
		return ProveOutput{}, fmt.Errorf("parsing AK public key: %w", err)
	}

	return ProveOutput{
		Statement:    statement,
		AKPublicKeyX: akPublicKey.X.Buffer,
		AKPublicKeyY: akPublicKey.Y.Buffer,
	}, nil
}

func getPCRCount(devicePath string) (uint16, error) {
	tpm, err := openTPM(devicePath)
	if err != nil {
		return 0, err
	}
	defer tpm.Close()

	pcrs, err := assignedPCRSelection(tpm)
	if err != nil {
		return 0, fmt.Errorf("parsing PCR capabilities: %w", err)
	}

	return uint16(len(pcrs.PCRSelections)), nil
}

func assignedPCRSelection(tpm transport.TPM) (*tpm2.TPMLPCRSelection, error) {
	capRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("getting PCR capabilities: %w", err)
	}
	pcrs, err := capRsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("parsing PCR capabilities: %w", err)
	}
	if len(pcrs.PCRSelections) == 0 {
		return nil, fmt.Errorf("TPM reported no PCR banks")
	}
	return pcrs, nil
}

func createTPMQuote(tpm transport.TPM, akHandle tpm2.TPMHandle, akName tpm2.TPM2BName) (*tpm2.QuoteResponse, error) {
	pcrSelection, err := assignedPCRSelection(tpm)
	if err != nil {
		return nil, err
	}

	pcrRsp, err := tpm2.PCRRead{PCRSelectionIn: *pcrSelection}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}

	quoteRsp, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: akHandle,
			Name:   akName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: []byte(tpmCmdFlags.Nonce)},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA},
		PCRSelect:      pcrRsp.PCRSelectionOut,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("quoting PCRs: %w", err)
	}

	return quoteRsp, nil
}

func openTPM(devicePath string) (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open(devicePath)
	if err != nil {
		return nil, fmt.Errorf("opening TPM device %s: %w", devicePath, err)
	}
	return tpm, nil
}

func generateSecureNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	return hex.EncodeToString(nonce), nil
}

func createAttestationKey(tpm transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				KeyBits:  2048,
				Exponent: 0,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
		),
	}

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{},
		InPublic:    tpm2.New2B(template),
	}.Execute(tpm)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("creating attestation key: %w", err)
	}
	return createRsp.ObjectHandle, createRsp.Name, nil
}

func parseYaml(cmd *cobra.Command) error {
	if tpmCmdFlags.PolicyFilePath == "" {
		return nil
	}

	policyContent, err := os.ReadFile(tpmCmdFlags.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("reading policy file %q: %w", tpmCmdFlags.PolicyFilePath, err)
	}

	cliValues := tpmCmdFlags
	merged := tpmCmdFlags
	if err := yaml.Unmarshal(policyContent, &merged); err != nil {
		return fmt.Errorf("parsing policy file %q: %w", tpmCmdFlags.PolicyFilePath, err)
	}

	if cmd.Flags().Changed("device") {
		merged.DevicePath = cliValues.DevicePath
	}
	if cmd.Flags().Changed("min-firmware-version") {
		merged.Statement.MinimalFirmwareVersion = cliValues.Statement.MinimalFirmwareVersion
	}
	if cmd.Flags().Changed("secure-boot") {
		merged.Statement.SecureBootEnabled = cliValues.Statement.SecureBootEnabled
	}
	if cmd.Flags().Changed("kernel-allowlist") {
		merged.Statement.KernelAllowList = cliValues.Statement.KernelAllowList
	}

	merged.PolicyFilePath = cliValues.PolicyFilePath
	tpmCmdFlags = merged
	return nil
}

func init() {
	RootCmd.AddCommand(tpmCmd)
	tpmCmd.AddCommand(tpmProveCmd)
	tpmCmd.AddCommand(tpmVerifyCmd)

	// Common Flags
	tpmCmd.PersistentFlags().StringVar(&tpmCmdFlags.PolicyFilePath, "policy", "", "Path to the policy file (YAML)")

	// TPM Flags
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.DevicePath, "device", "d", "/dev/tpm0", "Path to the TPM device (e.g., /dev/tpm0)")
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.Nonce, "nonce", "n", "", "Nonce for the quote (default to random string)")
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.QuoteOutputPath, "quote-output", "q", "quote.bin", "Output file for the TPM quote")
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.QuoteSignatureOutputPath, "signature-output", "s", "quote.sig", "Output file for the TPM quote signature")

	// ZKP Flags
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.ProofOutputPath, "proof-output", "p", "proof.bin", "Output file for the ZKP proof")

	// ZKP Constraints
	tpmCmd.PersistentFlags().Uint64Var(&tpmCmdFlags.Statement.MinimalFirmwareVersion, "min-firmware-version", 0, "Minimal firmware version constraint (inclusive this value)")
	tpmCmd.PersistentFlags().BoolVar(&tpmCmdFlags.Statement.SecureBootEnabled, "secure-boot", false, "Secure boot enabled constraint (default to no requirement)")
	tpmCmd.PersistentFlags().StringSliceVar(&tpmCmdFlags.Statement.KernelAllowList, "kernel-allowlist", []string{"all"}, "Kernel allow list constraint (default to allow all kernels, maximum size is 5)")
}
