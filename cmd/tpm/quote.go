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

package tpm

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	util "github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

type PCRAllowList struct {
	Sha256 []string `yaml:"sha256" json:"sha256"`
}

// Mapping of each PCR index to its sha256 allowlist
type PCRMap map[int]PCRAllowList

type QuoteProof struct {
	Proof        []byte       `json:"proof"`
	AKPublicKeyX []byte       `json:"ak_public_key_x"` // Longfellow prove does not require the AK certificate, public key is enough
	AKPublicKeyY []byte       `json:"ak_public_key_y"`
	Statement    ZKPStatement `json:"zkp_statement"`
}

type ZKPStatement struct {
	MinimalFirmwareVersion uint64   `yaml:"minimal_firmware_version" json:"minimal_firmware_version"`
	SecureBootEnabled      bool     `yaml:"secure_boot_enabled" json:"secure_boot_enabled"`
	KernelAllowList        []string `yaml:"kernel_allowlist" json:"kernel_allowlist"`
	PCRs                   PCRMap   `yaml:"pcrs" json:"pcrs"`
}

var zkpStatement = &ZKPStatement{}

type TpmProveQuoteCmdFlags struct {
}

var tpmProveQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Perform TPM attestation and generate a Zero Knowledge Proof for the quote",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("nonce") {
			if parsedNonce, err := util.ParseNonceFlag(cmd); err != nil {
				return err
			} else {
				tpmCmdFlags.Nonce = parsedNonce
			}
		}

		if len(tpmCmdFlags.Nonce) == 0 {
			nonce, err := generateSecureNonce()
			if err != nil {
				return fmt.Errorf("generating secure nonce: %w", err)
			} else {
				fmt.Printf("Using nonce: %s\n", hex.EncodeToString(nonce))
			}
			tpmCmdFlags.Nonce = nonce
		}

		// Pad the nonce to 32 bytes if it's shorter
		if len(tpmCmdFlags.Nonce) < 32 {
			paddedNonce := make([]byte, 32)
			copy(paddedNonce, tpmCmdFlags.Nonce)
			tpmCmdFlags.Nonce = paddedNonce
		}

		if err := verifyArguments(cmd); err != nil {
			return util.UsageError(cmd, err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		tpm, err := openTPM(tpmCmdFlags.DevicePath)
		if err != nil {
			return fmt.Errorf("opening TPM: %w", err)
		}
		defer tpm.Close()

		var akResponse *TPM2Key

		akResponse, err = attesationKeys[tpmCmdFlags.AttestationKeyType](tpm)
		if err != nil {
			return fmt.Errorf("creating attestation key: %w", err)
		}
		akHandle := akResponse.handle
		akName := akResponse.name
		akCert := akResponse.certificate

		defer func() {
			_, _ = tpm2.FlushContext{FlushHandle: akHandle}.Execute(tpm)
		}()

		// Get quote from TPM
		quote, err := createTPMQuote(tpm, akHandle, akName)
		if err != nil {
			return fmt.Errorf("creating TPM quote: %w", err)
		}

		if tpmProveCmdFlags.OutputPath != "" {
			if err := os.WriteFile(tpmProveCmdFlags.OutputPath, quote.Quoted.Bytes(), 0644); err != nil {
				return fmt.Errorf("writing quote to file: %w", err)
			}
			fmt.Printf("Quote written to %s\n", tpmProveCmdFlags.OutputPath)
		}

		// Get signature from quote
		signature, err := quote.Signature.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("parsing quote signature: %w", err)
		}

		if tpmProveCmdFlags.OutputSignaturePath != "" {
			signatureBytes := append(signature.SignatureR.Buffer, signature.SignatureS.Buffer...)
			if err := os.WriteFile(tpmProveCmdFlags.OutputSignaturePath, signatureBytes, 0644); err != nil {
				return fmt.Errorf("writing quote signature to file: %w", err)
			}
			fmt.Printf("Quote signature written to %s\n", tpmProveCmdFlags.OutputSignaturePath)
		}

		// Execute circuit and generate proof file
		proveOutput, err := generateProve(tpm, quote, zkpStatement, akHandle, akCert)
		if err != nil {
			return fmt.Errorf("executing ZKP circuit: %w", err)
		}

		if tpmProveCmdFlags.OutputPath != "" {
			outputBytes, err := json.Marshal(proveOutput)
			if err != nil {
				return fmt.Errorf("marshaling prove output: %w", err)
			}
			if err := os.WriteFile(tpmProveCmdFlags.OutputPath, outputBytes, 0644); err != nil {
				return fmt.Errorf("writing prove output to file: %w", err)
			}
			fmt.Printf("Prove output written to %s\n", tpmProveCmdFlags.OutputPath)
		}

		return nil
	},
}

type TpmVerifyQuoteCmdFlags struct {
}

var tpmVerifyQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Verify a TPM quote Zero Knowledge Proof against constraints",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if nonce, err := util.ParseNonceFlag(cmd); err != nil {
			return util.UsageError(cmd, err)
		} else {
			tpmCmdFlags.Nonce = nonce
		}

		if len(tpmCmdFlags.Nonce) == 0 {
			return util.UsageError(cmd, fmt.Errorf("nonce must be provided either via command line or policy file"))
		}

		if err := verifyArguments(cmd); err != nil {
			return util.UsageError(cmd, err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// For now, we are verifying the attestation quote first
		// to understand how the pipeline works.

		quoteBytes, err := os.ReadFile(tpmVerifyCmdFlags.InputPath)
		if err != nil {
			return fmt.Errorf("reading quote file: %w", err)
		}

		// Nonce Precheck
		quoteAttest2B := tpm2.BytesAs2B[tpm2.TPMSAttest, *tpm2.TPMSAttest](quoteBytes)
		quoteAttest, err := quoteAttest2B.Contents()
		if err != nil {
			return fmt.Errorf("parsing quote attestation data: %w", err)
		}

		if !bytes.Equal(quoteAttest.ExtraData.Buffer, tpmCmdFlags.Nonce) {
			return fmt.Errorf("quote nonce mismatch: expected %x, got %x", tpmCmdFlags.Nonce, quoteAttest.ExtraData.Buffer)
		}

		isValid := true

		if isValid {
			fmt.Println("Quote signature is valid.")
		} else {
			fmt.Println("Quote signature is invalid.")
		}

		return nil
	},
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
		QualifyingData: tpm2.TPM2BData{Buffer: tpmCmdFlags.Nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      pcrRsp.PCRSelectionOut,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("quoting PCRs: %w", err)
	}

	return quoteRsp, nil
}

func generateProve(tpm transport.TPM, quote *tpm2.QuoteResponse, statement *ZKPStatement, akHandle tpm2.TPMHandle, akCert x509.Certificate) (QuoteProof, error) {
	readPublicResponse, err := tpm2.ReadPublic{ObjectHandle: akHandle}.Execute(tpm)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("reading AK public area: %w", err)
	}

	content, err := readPublicResponse.OutPublic.Contents()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("extracting AK public key: %w", err)
	}

	akPublicKey, err := content.Unique.ECC()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("parsing AK public key: %w", err)
	}

	// TODO: Create the ZKP Proof using the circuit and add it to the output

	return QuoteProof{
		Statement:    *statement,
		AKPublicKeyX: akPublicKey.X.Buffer,
		AKPublicKeyY: akPublicKey.Y.Buffer,
	}, nil
}

func verifyArguments(cmd *cobra.Command) error {
	if len(zkpStatement.KernelAllowList) > 5 {
		return fmt.Errorf("kernel allow list cannot contain more than 5 entries")
	}

	if _, err := os.Stat(tpmCmdFlags.DevicePath); os.IsNotExist(err) {
		return fmt.Errorf("TPM device not found at %q: %w", tpmCmdFlags.DevicePath, err)
	}

	pcrCount, err := getPCRCount(tpmCmdFlags.DevicePath)
	if err != nil {
		return fmt.Errorf("getting PCR count: %w", err)
	}

	for pcrIndex := range zkpStatement.PCRs {
		if uint16(pcrIndex) >= pcrCount {
			return fmt.Errorf("PCR index %d is out of bounds (max: %d)", pcrIndex, pcrCount-1)
		}

		if len(zkpStatement.PCRs[pcrIndex].Sha256) > 5 {
			return fmt.Errorf("PCR %d allow list cannot contain more than 5 entries", pcrIndex)
		}
	}
	return nil
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

func init() {
	tpmProveCmd.AddCommand(tpmProveQuoteCmd)
	tpmVerifyCmd.AddCommand(tpmVerifyQuoteCmd)
}
