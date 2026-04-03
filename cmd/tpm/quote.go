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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/itsmeyaw/asta/cmd/libtpm2"
	util "github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

const (
	// TPMS_ATTEST structure offsets (from longfellow-zk/lib/circuits/tpm2_quote/tpm2_quote_constants.h)
	tpm2PCRDigestOffset = 125
	tpm2PCRDigestLen    = 32
)

type ZKPStatement struct {
	MinimalFirmwareVersion uint64 `yaml:"minimal_firmware_version" json:"minimal_firmware_version"`
	Nonce                  []byte `json:"nonce"`                    // Freshness nonce
	ExpectedPCRHash        []byte `json:"expected_pcr_hash"`        // PCR digest from quote (32 bytes)
	MinFirmwareVersionBE   []byte `json:"min_firmware_version_be"`  // Big-endian encoding (8 bytes)
}

// DebugProveInputs contains internal prover values, only included in debug mode
type DebugProveInputs struct {
	QuotedBytes  []byte `json:"quoted_bytes"`    // Raw TPMS_ATTEST bytes
	SignatureR   []byte `json:"signature_r"`     // ECDSA signature R component
	SignatureS   []byte `json:"signature_s"`     // ECDSA signature S component
	AKPublicKeyX []byte `json:"ak_public_key_x"` // AK public key X coordinate
	AKPublicKeyY []byte `json:"ak_public_key_y"` // AK public key Y coordinate
}

type QuoteProof struct {
	Proof       []byte            `json:"proof"`
	Statement   ZKPStatement      `json:"zkp_statement"`
	DebugInputs *DebugProveInputs `json:"debug_inputs,omitempty"` // Only present in debug mode
}

var zkpStatement = &ZKPStatement{}

type TpmProveQuoteCmdFlags struct {
	OutputQuotePath       string
	OutputCertificatePath string
	OutputSignaturePath   string
	PCRRegisters          []int
	InputQuotePath        string
	InputSignaturePath    string
	InputCertificatePath  string
	Debug                 bool
}

var tpmProveQuoteCmdFlags = &TpmProveQuoteCmdFlags{}

var tpmProveQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Perform TPM attestation and generate a Zero Knowledge Proof for the quote",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		preExtracted := tpmProveQuoteCmdFlags.InputQuotePath != ""

		if preExtracted {
			if tpmProveQuoteCmdFlags.InputSignaturePath == "" || tpmProveQuoteCmdFlags.InputCertificatePath == "" {
				return util.UsageError(cmd, fmt.Errorf("--quote-input, --signature-input, and --certificate-input must all be provided together"))
			}

			if !cmd.Flags().Changed("nonce") {
				return util.UsageError(cmd, fmt.Errorf("--nonce is required when using pre-extracted quote inputs"))
			}

			parsedNonce, err := util.ParseNonceFlag(cmd)
			if err != nil {
				return err
			}
			if len(parsedNonce) == 0 {
				return util.UsageError(cmd, fmt.Errorf("--nonce is required when using pre-extracted quote inputs"))
			}
			tpmCmdFlags.Nonce = parsedNonce

			if len(tpmCmdFlags.Nonce) < 32 {
				paddedNonce := make([]byte, 32)
				copy(paddedNonce, tpmCmdFlags.Nonce)
				tpmCmdFlags.Nonce = paddedNonce
			}

			if err := verifyZKPStatement(); err != nil {
				return util.UsageError(cmd, err)
			}

			return nil
		}

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

		if err := verifyGenericArguments(cmd); err != nil {
			return util.UsageError(cmd, err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var proveOutput QuoteProof
		var err error

		if tpmProveQuoteCmdFlags.InputQuotePath != "" {
			proveOutput, err = proveFromPreExtracted()
		} else {
			proveOutput, err = proveFromTPM()
		}
		if err != nil {
			return err
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
		if err := cmd.MarkFlagRequired("nonce"); err != nil {
			return err
		}

		nonce, err := util.ParseNonceFlag(cmd)
		if err != nil {
			return util.UsageError(cmd, err)
		}
		if len(nonce) == 0 {
			return util.UsageError(cmd, fmt.Errorf("nonce must be provided"))
		}
		tpmCmdFlags.Nonce = nonce

		// Pad nonce to 32 bytes to match prove behavior
		if len(tpmCmdFlags.Nonce) < 32 {
			paddedNonce := make([]byte, 32)
			copy(paddedNonce, tpmCmdFlags.Nonce)
			tpmCmdFlags.Nonce = paddedNonce
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		proofFileBytes, err := os.ReadFile(tpmVerifyCmdFlags.InputPath)
		if err != nil {
			return fmt.Errorf("reading proof file: %w", err)
		}

		var quoteProof QuoteProof
		if err := json.Unmarshal(proofFileBytes, &quoteProof); err != nil {
			return fmt.Errorf("parsing proof file: %w", err)
		}

		// Verify nonce freshness against user-provided nonce
		if !bytes.Equal(quoteProof.Statement.Nonce, tpmCmdFlags.Nonce) {
			return fmt.Errorf("nonce mismatch: proof contains a different nonce than provided")
		}

		// Validate statement fields
		if len(quoteProof.Statement.Nonce) != 32 {
			return fmt.Errorf("nonce must be 32 bytes, got %d", len(quoteProof.Statement.Nonce))
		}
		if len(quoteProof.Statement.ExpectedPCRHash) != 32 {
			return fmt.Errorf("expected PCR hash must be 32 bytes, got %d", len(quoteProof.Statement.ExpectedPCRHash))
		}
		if len(quoteProof.Statement.MinFirmwareVersionBE) != 8 {
			return fmt.Errorf("min firmware version BE must be 8 bytes, got %d", len(quoteProof.Statement.MinFirmwareVersionBE))
		}

		// Verify consistency: MinFirmwareVersionBE should match MinimalFirmwareVersion
		var expectedMinFW [8]byte
		binary.BigEndian.PutUint64(expectedMinFW[:], quoteProof.Statement.MinimalFirmwareVersion)
		if !bytes.Equal(quoteProof.Statement.MinFirmwareVersionBE, expectedMinFW[:]) {
			return fmt.Errorf("min_firmware_version_be does not match minimal_firmware_version")
		}

		// Prepare fixed-size arrays for the verifier
		var minFirmwareVersion [8]byte
		copy(minFirmwareVersion[:], quoteProof.Statement.MinFirmwareVersionBE)

		var pcrHash [32]byte
		copy(pcrHash[:], quoteProof.Statement.ExpectedPCRHash)

		// Generate circuit
		circuit, err := libtpm2.GenerateCircuit()
		if err != nil {
			return fmt.Errorf("generating ZKP circuit: %w", err)
		}

		// Run ZKP verifier
		if err := libtpm2.RunVerifier(
			false, // useV7 must match the value used during proving
			circuit,
			quoteProof.Statement.Nonce,
			minFirmwareVersion,
			pcrHash,
			quoteProof.Proof,
		); err != nil {
			return fmt.Errorf("ZKP verification failed: %w", err)
		}

		fmt.Println("ZKP verification passed.")
		return nil
	},
}

func proveFromPreExtracted() (QuoteProof, error) {
	quotedBytes, err := os.ReadFile(tpmProveQuoteCmdFlags.InputQuotePath)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("reading quote file: %w", err)
	}

	sigBytes, err := os.ReadFile(tpmProveQuoteCmdFlags.InputSignaturePath)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("reading signature file: %w", err)
	}
	if len(sigBytes) != 64 {
		return QuoteProof{}, fmt.Errorf("signature file must be exactly 64 bytes (R||S for P-256, got %d bytes)", len(sigBytes))
	}

	var sigR, sigS [32]byte
	copy(sigR[:], sigBytes[:32])
	copy(sigS[:], sigBytes[32:64])

	certBytes, err := os.ReadFile(tpmProveQuoteCmdFlags.InputCertificatePath)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("reading certificate file: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("parsing certificate: %w", err)
	}
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return QuoteProof{}, fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	ecdhKey, err := ecdsaPubKey.ECDH()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("converting certificate public key: %w", err)
	}
	// Uncompressed point encoding: 0x04 || X || Y, each coordinate is (len-1)/2 bytes
	pubKeyBytes := ecdhKey.Bytes()
	coordLen := (len(pubKeyBytes) - 1) / 2

	return generateProveFromRawData(
		quotedBytes,
		sigR,
		sigS,
		pubKeyBytes[1:1+coordLen],
		pubKeyBytes[1+coordLen:],
		zkpStatement,
		tpmCmdFlags.Nonce,
	)
}

func proveFromTPM() (QuoteProof, error) {
	tpm, err := openTPM(tpmCmdFlags.DevicePath)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()

	akResponse, err := attesationKeys[tpmCmdFlags.AttestationKeyType](tpm)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("creating attestation key: %w", err)
	}
	akHandle := akResponse.handle
	akName := akResponse.name
	akCert := akResponse.certificate

	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: akHandle}.Execute(tpm)
	}()

	quote, err := createTPMQuote(tpm, akHandle, akName, tpmProveQuoteCmdFlags.PCRRegisters)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("creating TPM quote: %w", err)
	}

	if tpmProveQuoteCmdFlags.OutputQuotePath != "" {
		if err := os.WriteFile(tpmProveQuoteCmdFlags.OutputQuotePath, quote.Quoted.Bytes(), 0644); err != nil {
			return QuoteProof{}, fmt.Errorf("writing quote to file: %w", err)
		}
		fmt.Printf("Quote written to %s\n", tpmProveQuoteCmdFlags.OutputQuotePath)
	}

	signature, err := quote.Signature.Signature.ECDSA()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("parsing quote signature: %w", err)
	}

	if tpmProveQuoteCmdFlags.OutputSignaturePath != "" {
		signatureBytes := append(signature.SignatureR.Buffer, signature.SignatureS.Buffer...)
		if err := os.WriteFile(tpmProveQuoteCmdFlags.OutputSignaturePath, signatureBytes, 0644); err != nil {
			return QuoteProof{}, fmt.Errorf("writing quote signature to file: %w", err)
		}
		fmt.Printf("Quote signature written to %s\n", tpmProveQuoteCmdFlags.OutputSignaturePath)
	}

	if tpmProveQuoteCmdFlags.OutputCertificatePath != "" {
		if err := os.WriteFile(tpmProveQuoteCmdFlags.OutputCertificatePath, akCert.Raw, 0644); err != nil {
			return QuoteProof{}, fmt.Errorf("writing AK certificate to file: %w", err)
		}
		fmt.Printf("AK certificate written to %s\n", tpmProveQuoteCmdFlags.OutputCertificatePath)
	}

	return generateProve(tpm, quote, zkpStatement, akHandle, akCert)
}

func createTPMQuote(tpm transport.TPM, akHandle tpm2.TPMHandle, akName tpm2.TPM2BName, selectedPCRRegisters []int) (*tpm2.QuoteResponse, error) {
	pcrSelection, err := pcrSelectionForRegisters(tpm, selectedPCRRegisters)
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

func pcrSelectionForRegisters(tpm transport.TPM, selectedPCRRegisters []int) (*tpm2.TPMLPCRSelection, error) {
	assignedSelection, err := assignedPCRSelection(tpm)
	if err != nil {
		return nil, err
	}

	if len(selectedPCRRegisters) == 0 {
		return assignedSelection, nil
	}

	uniqueRegisters := make(map[int]struct{}, len(selectedPCRRegisters))
	for _, pcrRegister := range selectedPCRRegisters {
		if pcrRegister < 0 {
			return nil, fmt.Errorf("PCR register must be >= 0 (got %d)", pcrRegister)
		}
		uniqueRegisters[pcrRegister] = struct{}{}
	}

	orderedRegisters := make([]int, 0, len(uniqueRegisters))
	for pcrRegister := range uniqueRegisters {
		orderedRegisters = append(orderedRegisters, pcrRegister)
	}
	sort.Ints(orderedRegisters)

	filteredSelections := make([]tpm2.TPMSPCRSelection, 0, len(assignedSelection.PCRSelections))
	for _, bankSelection := range assignedSelection.PCRSelections {
		filteredPCRBytes := make([]byte, len(bankSelection.PCRSelect))
		for _, pcrRegister := range orderedRegisters {
			byteIndex := pcrRegister / 8
			bitPosition := uint(pcrRegister % 8)
			if byteIndex < len(filteredPCRBytes) {
				filteredPCRBytes[byteIndex] |= 1 << bitPosition
			}
		}

		hasAnyPCR := false
		for i := range filteredPCRBytes {
			filteredPCRBytes[i] &= bankSelection.PCRSelect[i]
			if filteredPCRBytes[i] != 0 {
				hasAnyPCR = true
			}
		}

		if hasAnyPCR {
			filteredSelections = append(filteredSelections, tpm2.TPMSPCRSelection{
				Hash:      bankSelection.Hash,
				PCRSelect: filteredPCRBytes,
			})
		}
	}

	if len(filteredSelections) == 0 {
		return nil, fmt.Errorf("none of the selected PCR registers are available: %v", orderedRegisters)
	}

	return &tpm2.TPMLPCRSelection{PCRSelections: filteredSelections}, nil
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

	// Extract ECDSA signature (r, s) from quote
	ecdsaSig, err := quote.Signature.Signature.ECDSA()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("extracting ECDSA signature: %w", err)
	}

	var sigR, sigS [32]byte
	copy(sigR[:], padLeft(ecdsaSig.SignatureR.Buffer, 32))
	copy(sigS[:], padLeft(ecdsaSig.SignatureS.Buffer, 32))

	return generateProveFromRawData(
		quote.Quoted.Bytes(),
		sigR,
		sigS,
		akPublicKey.X.Buffer,
		akPublicKey.Y.Buffer,
		statement,
		tpmCmdFlags.Nonce,
	)
}

func generateProveFromRawData(
	quotedBytes []byte,
	sigR [32]byte,
	sigS [32]byte,
	akPubKeyX []byte,
	akPubKeyY []byte,
	statement *ZKPStatement,
	nonce []byte,
) (QuoteProof, error) {
	// Encode firmware version as 8-byte big-endian
	var minFirmwareVersion [8]byte
	binary.BigEndian.PutUint64(minFirmwareVersion[:], statement.MinimalFirmwareVersion)

	// Extract PCR digest from the quote (at fixed offset 125, 32 bytes)
	if len(quotedBytes) < tpm2PCRDigestOffset+tpm2PCRDigestLen {
		return QuoteProof{}, fmt.Errorf("quote too short to contain PCR digest (need %d bytes, got %d)",
			tpm2PCRDigestOffset+tpm2PCRDigestLen, len(quotedBytes))
	}
	var expectedPCRHash [32]byte
	copy(expectedPCRHash[:], quotedBytes[tpm2PCRDigestOffset:tpm2PCRDigestOffset+tpm2PCRDigestLen])

	// Convert AK public key coordinates to decimal strings for the C library
	pkX := new(big.Int).SetBytes(akPubKeyX).String()
	pkY := new(big.Int).SetBytes(akPubKeyY).String()

	// Generate circuit
	circuit, err := libtpm2.GenerateCircuit()
	if err != nil {
		return QuoteProof{}, fmt.Errorf("generating ZKP circuit: %w", err)
	}

	// Run the ZKP prover
	result, err := libtpm2.RunProver(
		false, // usev7
		circuit,
		sigR,
		sigS,
		nonce,
		minFirmwareVersion,
		expectedPCRHash,
		pkX,
		pkY,
		quotedBytes,
	)
	if err != nil {
		return QuoteProof{}, fmt.Errorf("running ZKP prover: %w", err)
	}

	// Populate statement with computed values
	stmt := ZKPStatement{
		MinimalFirmwareVersion: statement.MinimalFirmwareVersion,
		Nonce:                  nonce,
		ExpectedPCRHash:        expectedPCRHash[:],
		MinFirmwareVersionBE:   minFirmwareVersion[:],
	}

	// Build proof output
	proof := QuoteProof{
		Proof:     result.Proof,
		Statement: stmt,
	}

	// Include debug inputs if debug mode is enabled
	if tpmProveQuoteCmdFlags.Debug {
		proof.DebugInputs = &DebugProveInputs{
			QuotedBytes:  quotedBytes,
			SignatureR:   sigR[:],
			SignatureS:   sigS[:],
			AKPublicKeyX: akPubKeyX,
			AKPublicKeyY: akPubKeyY,
		}
	}

	return proof, nil
}

// padLeft pads a byte slice with leading zeros to reach the target length.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func verifyZKPStatement() error {
	// No additional validation needed - firmware version is a uint64
	return nil
}

func verifyGenericArguments(cmd *cobra.Command) error {
	if err := verifyZKPStatement(); err != nil {
		return err
	}

	if _, err := os.Stat(tpmCmdFlags.DevicePath); os.IsNotExist(err) {
		return fmt.Errorf("TPM device not found at %q: %w", tpmCmdFlags.DevicePath, err)
	}

	pcrCount, err := getPCRCount(tpmCmdFlags.DevicePath)
	if err != nil {
		return fmt.Errorf("getting PCR count: %w", err)
	}

	for _, pcrRegister := range tpmProveQuoteCmdFlags.PCRRegisters {
		if pcrRegister < 0 {
			return fmt.Errorf("PCR register must be >= 0 (got %d)", pcrRegister)
		}
		if uint16(pcrRegister) >= pcrCount {
			return fmt.Errorf("selected PCR register %d is out of bounds (max: %d)", pcrRegister, pcrCount-1)
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

	maxPCRCount := 0
	for _, selection := range pcrs.PCRSelections {
		if bankPCRCount := len(selection.PCRSelect) * 8; bankPCRCount > maxPCRCount {
			maxPCRCount = bankPCRCount
		}
	}

	if maxPCRCount == 0 {
		return 0, fmt.Errorf("TPM reported no selectable PCR registers")
	}

	return uint16(maxPCRCount), nil
}

func init() {
	tpmProveCmd.AddCommand(tpmProveQuoteCmd)
	tpmProveQuoteCmd.Flags().StringVarP(&tpmProveQuoteCmdFlags.OutputQuotePath, "quote-output", "q", "quote.bin", "Output file for the TPM attestation quote")
	tpmProveQuoteCmd.Flags().StringVarP(&tpmProveQuoteCmdFlags.OutputSignaturePath, "signature-output", "s", "quote.sig", "Output file for the TPM quote signature")
	tpmProveQuoteCmd.Flags().StringVarP(&tpmProveQuoteCmdFlags.OutputCertificatePath, "certificate-output", "c", "quote.crt", "Output file for the TPM attestation key certificate")
	tpmProveQuoteCmd.Flags().IntSliceVarP(&tpmProveQuoteCmdFlags.PCRRegisters, "pcr-registers", "p", nil, "Comma-separated PCR register indices to include in quote (default: all available)")
	tpmProveQuoteCmd.Flags().String("nonce", "", "Hex-encoded nonce (max 32 bytes; auto-generated if not provided)")
	tpmProveQuoteCmd.Flags().StringVar(&tpmProveQuoteCmdFlags.InputQuotePath, "quote-input", "", "Path to pre-extracted TPM quote file (TPMS_ATTEST bytes)")
	tpmProveQuoteCmd.Flags().StringVar(&tpmProveQuoteCmdFlags.InputSignaturePath, "signature-input", "", "Path to pre-extracted quote signature file (64 bytes: R||S)")
	tpmProveQuoteCmd.Flags().StringVar(&tpmProveQuoteCmdFlags.InputCertificatePath, "certificate-input", "", "Path to pre-extracted AK certificate file (DER-encoded X.509)")
	tpmProveQuoteCmd.Flags().BoolVar(&tpmProveQuoteCmdFlags.Debug, "debug", false, "Include debug inputs (quoted bytes, signature, AK public key) in proof output")

	tpmVerifyCmd.AddCommand(tpmVerifyQuoteCmd)
	tpmVerifyQuoteCmd.Flags().String("nonce", "", "Hex-encoded nonce used in quote freshness validation (max 32 bytes)")
}
