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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
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

type TPM2Key struct {
	handle      tpm2.TPMHandle
	name        tpm2.TPM2BName
	certificate x509.Certificate
	public      tpm2.TPMTPublic
}

// Mapping attestation key to the function to get their certificate
var attesationKeys = map[string]func(transport.TPM) (*TPM2Key, error){
	"gce": getGCEAttestationKey,
}

// Taken from go-tpm-tools library
const (
	GceAKCertNVIndex     uint32 = 0x01c10002
	GceAKTemplateNVIndex uint32 = 0x01c10003
)

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
	Nonce                    []byte `yaml:"nonce"`
	QuoteOutputPath          string `yaml:"quote_output"`
	QuoteSignatureOutputPath string `yaml:"quote_signature_output"`
	AttestationKeyType       string `yaml:"attestation_key_type"`

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
	AKPublicKeyY []byte       `json:"ak_public_key_y"` // Quoestion: Do we want to use AK or EK here?
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
	Use:          "prove",
	Short:        "Create a TPM quote zero knowledge proof",
	Long:         "Create a TPM quote zero knowledge proof for the current platform state.",
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := parseNonceFlag(cmd); err != nil {
			return err
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

		if err := verifyArguments(cmd); err != nil {
			return usageError(cmd, err)
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

		switch tpmCmdFlags.AttestationKeyType {
		case "gce":
			akResponse, err = getGCEAttestationKey(tpm)
		default:
			return fmt.Errorf("unknown attestation key type: %s", tpmCmdFlags.AttestationKeyType)
		}
		if err != nil {
			return fmt.Errorf("creating attestation key: %w", err)
		}
		akHandle := akResponse.handle
		akName := akResponse.name
		akCert := akResponse.certificate

		if err := writeCertificatePEM(akCert, "ak_cert.pem"); err != nil {
			return fmt.Errorf("writing AK certificate to PEM: %w", err)
		}
		fmt.Println("AK certificate written to ak_cert.pem")

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
			signatureBytes := append(signature.SignatureR.Buffer, signature.SignatureS.Buffer...)
			if err := os.WriteFile(tpmCmdFlags.QuoteSignatureOutputPath, signatureBytes, 0644); err != nil {
				return fmt.Errorf("writing quote signature to file: %w", err)
			}
			fmt.Printf("Quote signature written to %s\n", tpmCmdFlags.QuoteSignatureOutputPath)
		}

		// Execute circuit and generate proof file
		proveOutput, err := generateProve(tpm, quote, tpmCmdFlags.Statement, akHandle, akCert)
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
	Use:          "verify",
	Short:        "Verify a TPM quote zero knowledge proof",
	Long:         "Verify a TPM quote zero knowledge proof against the current platform state.",
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := parseNonceFlag(cmd); err != nil {
			return usageError(cmd, err)
		}

		if len(tpmCmdFlags.Nonce) == 0 {
			return usageError(cmd, fmt.Errorf("nonce must be provided either via command line or policy file"))
		}

		if err := verifyArguments(cmd); err != nil {
			return usageError(cmd, err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// For now, we are verifying the attestation quote first
		// to understand how the pipeline works.

		quoteBytes, err := os.ReadFile(tpmCmdFlags.QuoteOutputPath)
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

		signatureBytes, err := os.ReadFile(tpmCmdFlags.QuoteSignatureOutputPath)
		if err != nil {
			return fmt.Errorf("reading quote signature file: %w", err)
		}
		signatureR := new(big.Int).SetBytes(signatureBytes[:len(signatureBytes)/2])
		signatureS := new(big.Int).SetBytes(signatureBytes[len(signatureBytes)/2:])

		proofBytes, err := os.ReadFile(tpmCmdFlags.ProofOutputPath)
		if err != nil {
			return fmt.Errorf("reading proof file: %w", err)
		}

		var proveOutput ProveOutput
		if err := json.Unmarshal(proofBytes, &proveOutput); err != nil {
			return fmt.Errorf("parsing proof file: %w", err)
		}

		// Regenerate the attestation public key
		pubKey := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(proveOutput.AKPublicKeyX),
			Y:     new(big.Int).SetBytes(proveOutput.AKPublicKeyY),
		}

		digest := sha256.Sum256(quoteBytes)
		isValid := ecdsa.Verify(&pubKey, digest[:], signatureR, signatureS)

		if isValid {
			fmt.Println("Quote signature is valid.")
		} else {
			fmt.Println("Quote signature is invalid.")
		}

		return nil
	},
}

func usageError(cmd *cobra.Command, err error) error {
	_ = cmd.Usage()
	return err
}

func writeCertificatePEM(cert x509.Certificate, outputPath string) error {
	if len(cert.Raw) == 0 {
		return fmt.Errorf("AK certificate is empty")
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if pemData == nil {
		return fmt.Errorf("encoding certificate to PEM")
	}

	if err := os.WriteFile(outputPath, pemData, 0644); err != nil {
		return fmt.Errorf("writing file %q: %w", outputPath, err)
	}

	return nil
}

func generateProve(tpm transport.TPM, quote *tpm2.QuoteResponse, statement ZKPStatement, akHandle tpm2.TPMHandle, akCert x509.Certificate) (ProveOutput, error) {
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

	// TODO: Create the ZKP Proof using the circuit and add it to the output

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
		QualifyingData: tpm2.TPM2BData{Buffer: tpmCmdFlags.Nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
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

func generateSecureNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func createAttestationKey(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
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
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
				KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
				Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			},
		),
	}

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("creating attestation key: %w", err)
	}
	return createRsp, nil
}

func getGCEAttestationKey(tpm transport.TPM) (*TPM2Key, error) {
	akTemplateBytes, err := readNVIndexData(tpm, GceAKTemplateNVIndex)
	if err != nil {
		return nil, fmt.Errorf("reading GCE AK template from NV index: %w", err)
	}

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](akTemplateBytes),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("creating GCE attestation key from NV template: %w", err)
	}

	outPublic, err := createRsp.OutPublic.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}.Execute(tpm)
		return nil, fmt.Errorf("parsing GCE AK public area: %w", err)
	}

	key := &TPM2Key{
		handle: createRsp.ObjectHandle,
		name:   createRsp.Name,
		public: *outPublic,
	}

	certBytes, err := readNVIndexData(tpm, GceAKCertNVIndex)
	if err == nil {
		x509Cert, certErr := x509.ParseCertificate(certBytes)
		if certErr != nil {
			_, _ = tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}.Execute(tpm)
			return nil, fmt.Errorf("failed to parse GCE AK certificate from NV memory: %w", certErr)
		}
		key.certificate = *x509Cert
	}

	return key, nil
}

func readNVIndexData(tpm transport.TPM, index uint32) ([]byte, error) {
	readPubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	capRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	props, err := capRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	if len(props.TPMProperty) == 0 {
		return nil, fmt.Errorf("TPM did not return NV buffer max property")
	}

	blockSize := int(props.TPMProperty[0].Value)
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid NV buffer max value: %d", blockSize)
	}

	outBuff := make([]byte, 0, int(nvPublic.DataSize))
	for len(outBuff) < int(nvPublic.DataSize) {
		readSize := blockSize
		if remaining := int(nvPublic.DataSize) - len(outBuff); readSize > remaining {
			readSize = remaining
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.HandleName(tpm2.TPMRHOwner),
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: uint16(len(outBuff)),
		}.Execute(tpm)
		if err != nil {
			return nil, err
		}

		outBuff = append(outBuff, readRsp.Data.Buffer...)
	}

	return outBuff, nil
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

func parseNonceFlag(cmd *cobra.Command) error {
	nonceHex, err := cmd.Flags().GetString("nonce")
	if err != nil {
		return fmt.Errorf("reading nonce flag: %w", err)
	}

	if nonceHex == "" {
		return nil
	}

	parsedNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	tpmCmdFlags.Nonce = parsedNonce

	// Enforce that the length of nonce does not exceed 32 bytes because we use SHA256 digest which is 32 bytes
	// See TPM 2.0 Library Specification Part 2 Section 10.4.3
	if len(tpmCmdFlags.Nonce) > 32 {
		return fmt.Errorf("nonce cannot exceed 32 bytes (got %d bytes)", len(tpmCmdFlags.Nonce))
	}

	return nil
}

func verifyArguments(cmd *cobra.Command) error {
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
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.QuoteOutputPath, "quote-output", "q", "quote.bin", "Output file for the TPM quote")
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.QuoteSignatureOutputPath, "signature-output", "s", "quote.sig", "Output file for the TPM quote signature")
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.AttestationKeyType, "attestation-key-type", "t", "gce", "Type of attestation key to use (default: gce)")

	tpmCmd.PersistentFlags().StringP("nonce", "n", "", "Nonce for the quote (hex string; default is random nonce for prove)")

	// ZKP Flags
	tpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.ProofOutputPath, "proof-output", "p", "proof.json", "Output file for the ZKP proof")

	// ZKP Constraints
	tpmCmd.PersistentFlags().Uint64Var(&tpmCmdFlags.Statement.MinimalFirmwareVersion, "min-firmware-version", 0, "Minimal firmware version constraint (inclusive this value)")
	tpmCmd.PersistentFlags().BoolVar(&tpmCmdFlags.Statement.SecureBootEnabled, "secure-boot", false, "Secure boot enabled constraint (default to no requirement)")
	tpmCmd.PersistentFlags().StringSliceVar(&tpmCmdFlags.Statement.KernelAllowList, "kernel-allowlist", []string{"all"}, "Kernel allow list constraint (default to allow all kernels, maximum size is 5)")
}
