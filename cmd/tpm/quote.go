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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/itsmeyaw/herta/cmd/attest"
	"github.com/itsmeyaw/herta/cmd/libtpm2"
	"github.com/spf13/cobra"
)

const (
	tpm2PCRDigestOffset = 125
	tpm2PCRDigestLen    = 32
)

type requirements struct {
	Nonce                  string `json:"nonce"`
	MinimalFirmwareVersion uint64 `json:"minimum_firmware_version"`
	ExpectedPCRHash        string `json:"expected_pcr_hash"`
}

type statement struct {
	Nonce            []byte `json:"nonce"`
	MinFirmware      []byte `json:"min_firmware"`
	PCRHash          []byte `json:"pcr_hash"`
	IssuerSPKI       []byte `json:"issuer_spki"`
	VerificationTime []byte `json:"verification_time"`
	SerialBlocklist  []byte `json:"serial_blocklist"`
	ActiveSerials    int    `json:"active_serials"`
}

type proofEnvelope struct {
	Profile     string    `json:"profile"`
	SpecVersion int       `json:"spec_version"`
	CircuitID   []byte    `json:"circuit_id"`
	Statement   statement `json:"statement"`
	Proof       []byte    `json:"proof"`
}

var proveQuoteFlags struct {
	quote, signature, certificate, circuit, policy, output string
}

var verifyQuoteFlags struct{ input, circuit, policy string }

var tpmProveQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Generate a policy-bound TPM quote proof",
	RunE:  func(*cobra.Command, []string) error { return proveQuote() },
}

var tpmVerifyQuoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Verify a policy-bound TPM quote proof",
	RunE:  func(*cobra.Command, []string) error { return verifyQuote() },
}

var tpmCircuitGenerateCmd = &cobra.Command{
	Use:   "generate <output>",
	Short: "Generate a TPM ZK circuit",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		circuit, err := libtpm2.GenerateCircuit()
		if err != nil {
			return fmt.Errorf("generating circuit: %w", err)
		}
		return os.WriteFile(args[0], circuit, 0644)
	},
}

var tpmCircuitCmd = &cobra.Command{Use: "circuit", Short: "TPM ZK circuit operations"}

func circuitFor(path string) ([]byte, error) {
	if path == "" {
		return libtpm2.GenerateCircuit()
	}
	circuit, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading circuit file: %w", err)
	}
	if len(circuit) == 0 {
		return nil, fmt.Errorf("circuit file is empty: %s", path)
	}
	return circuit, nil
}

func proveQuote() error {
	if proveQuoteFlags.quote == "" || proveQuoteFlags.signature == "" || proveQuoteFlags.certificate == "" {
		return fmt.Errorf("policy-bound TPM proving requires --quote, --signature, and --certificate")
	}
	policy, requirements, err := load(proveQuoteFlags.policy)
	if err != nil {
		return err
	}
	quote, err := os.ReadFile(proveQuoteFlags.quote)
	if err != nil {
		return fmt.Errorf("reading quote: %w", err)
	}
	signature, err := os.ReadFile(proveQuoteFlags.signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}
	if len(signature) != 64 {
		return fmt.Errorf("signature must be 64 bytes, got %d", len(signature))
	}
	certificateDER, err := os.ReadFile(proveQuoteFlags.certificate)
	if err != nil {
		return fmt.Errorf("reading AK certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return fmt.Errorf("parsing AK certificate: %w", err)
	}
	trust, err := attest.ValidateTrust(policy, certificate, libtpm2.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	statement, err := makeStatement(requirements, trust)
	if err != nil {
		return err
	}
	statement.Version = policy.SpecVersion
	if len(quote) < tpm2PCRDigestOffset+tpm2PCRDigestLen || !bytes.Equal(quote[tpm2PCRDigestOffset:tpm2PCRDigestOffset+tpm2PCRDigestLen], statement.PCRHash[:]) {
		return fmt.Errorf("quote PCR digest does not match policy")
	}
	circuit, err := circuitFor(proveQuoteFlags.circuit)
	if err != nil {
		return err
	}
	var r, s [32]byte
	copy(r[:], signature[:32])
	copy(s[:], signature[32:])
	proof, err := libtpm2.Prove(circuit, statement, quote, r, s, certificateDER)
	if err != nil {
		return err
	}
	id, err := libtpm2.CircuitID(circuit, policy.SpecVersion)
	if err != nil {
		return err
	}
	output, err := json.Marshal(proofEnvelope{policy.Profile, policy.SpecVersion, id[:], proofStatement(statement), proof})
	if err != nil {
		return fmt.Errorf("encoding proof: %w", err)
	}
	if err := os.WriteFile(proveQuoteFlags.output, output, 0600); err != nil {
		return fmt.Errorf("writing proof: %w", err)
	}
	return nil
}

func verifyQuote() error {
	policy, requirements, err := load(verifyQuoteFlags.policy)
	if err != nil {
		return err
	}
	trust, err := attest.ValidateCollateral(policy, libtpm2.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	statement, err := makeStatement(requirements, trust)
	if err != nil {
		return err
	}
	statement.Version = policy.SpecVersion
	data, err := os.ReadFile(verifyQuoteFlags.input)
	if err != nil {
		return fmt.Errorf("reading proof: %w", err)
	}
	var envelope proofEnvelope
	if err := attest.DecodeJSON(data, &envelope); err != nil {
		return fmt.Errorf("parsing proof: %w", err)
	}
	if envelope.Profile != policy.Profile || envelope.SpecVersion != policy.SpecVersion || !sameStatement(envelope.Statement, proofStatement(statement)) {
		return fmt.Errorf("proof statement does not match verifier policy and collateral")
	}
	circuit, err := circuitFor(verifyQuoteFlags.circuit)
	if err != nil {
		return err
	}
	id, err := libtpm2.CircuitID(circuit, policy.SpecVersion)
	if err != nil || !bytes.Equal(envelope.CircuitID, id[:]) {
		return fmt.Errorf("proof circuit ID does not match verifier circuit")
	}
	return libtpm2.Verify(circuit, statement, envelope.Proof)
}

func load(path string) (attest.Policy, requirements, error) {
	policy, err := attest.LoadPolicy(path)
	if err != nil {
		return attest.Policy{}, requirements{}, err
	}
	if policy.Profile != "longfellow-tpm2-gcp-ak-v1" {
		return attest.Policy{}, requirements{}, fmt.Errorf("policy profile must be longfellow-tpm2-gcp-ak-v1")
	}
	var req requirements
	if err := attest.DecodeJSON(policy.Requirements, &req); err != nil {
		return attest.Policy{}, requirements{}, fmt.Errorf("parsing TPM requirements: %w", err)
	}
	return policy, req, nil
}

func makeStatement(requirements requirements, trust attest.Trust) (libtpm2.Statement, error) {
	nonce, err := hex.DecodeString(requirements.Nonce)
	if err != nil || len(nonce) == 0 || len(nonce) > 32 {
		return libtpm2.Statement{}, fmt.Errorf("TPM policy nonce must contain 1 to 32 hex bytes")
	}
	pcr, err := hex.DecodeString(requirements.ExpectedPCRHash)
	if err != nil || len(pcr) != 32 {
		return libtpm2.Statement{}, fmt.Errorf("TPM policy expected_pcr_hash must contain 32 hex bytes")
	}
	var firmware [8]byte
	binary.BigEndian.PutUint64(firmware[:], requirements.MinimalFirmwareVersion)
	var pcrHash [32]byte
	copy(pcrHash[:], pcr)
	return libtpm2.Statement{Version: 6, Nonce: nonce, MinFirmware: firmware, PCRHash: pcrHash, IssuerSPKI: trust.IssuerSPKI, VerificationTime: trust.VerificationTime, SerialBlocklist: trust.SerialBlocklist, ActiveSerials: trust.ActiveBlocklistSize}, nil
}

func proofStatement(s libtpm2.Statement) statement {
	return statement{s.Nonce, s.MinFirmware[:], s.PCRHash[:], s.IssuerSPKI, s.VerificationTime, s.SerialBlocklist, s.ActiveSerials}
}

func sameStatement(left, right statement) bool {
	return bytes.Equal(left.Nonce, right.Nonce) && bytes.Equal(left.MinFirmware, right.MinFirmware) && bytes.Equal(left.PCRHash, right.PCRHash) && bytes.Equal(left.IssuerSPKI, right.IssuerSPKI) && bytes.Equal(left.VerificationTime, right.VerificationTime) && bytes.Equal(left.SerialBlocklist, right.SerialBlocklist) && left.ActiveSerials == right.ActiveSerials
}

func init() {
	tpmProveCmd.AddCommand(tpmProveQuoteCmd)
	tpmProveQuoteCmd.Flags().StringVar(&proveQuoteFlags.quote, "quote", "", "TPMS_ATTEST quote input")
	tpmProveQuoteCmd.Flags().StringVar(&proveQuoteFlags.signature, "signature", "", "64-byte R||S quote signature")
	tpmProveQuoteCmd.Flags().StringVar(&proveQuoteFlags.certificate, "certificate", "", "DER AK certificate")
	tpmProveQuoteCmd.Flags().StringVar(&proveQuoteFlags.policy, "policy", "", "Policy JSON")
	tpmProveQuoteCmd.Flags().StringVar(&proveQuoteFlags.circuit, "circuit", "", "Circuit file")
	tpmProveQuoteCmd.Flags().StringVarP(&proveQuoteFlags.output, "output", "o", "proof.json", "Proof output")
	_ = tpmProveQuoteCmd.MarkFlagRequired("quote")
	_ = tpmProveQuoteCmd.MarkFlagRequired("signature")
	_ = tpmProveQuoteCmd.MarkFlagRequired("certificate")
	_ = tpmProveQuoteCmd.MarkFlagRequired("policy")

	tpmVerifyCmd.AddCommand(tpmVerifyQuoteCmd)
	tpmVerifyQuoteCmd.Flags().StringVarP(&verifyQuoteFlags.input, "input", "i", "", "Proof input")
	tpmVerifyQuoteCmd.Flags().StringVar(&verifyQuoteFlags.policy, "policy", "", "Policy JSON")
	tpmVerifyQuoteCmd.Flags().StringVar(&verifyQuoteFlags.circuit, "circuit", "", "Circuit file")
	_ = tpmVerifyQuoteCmd.MarkFlagRequired("input")
	_ = tpmVerifyQuoteCmd.MarkFlagRequired("policy")

	TpmCmd.AddCommand(tpmCircuitCmd)
	tpmCircuitCmd.AddCommand(tpmCircuitGenerateCmd)
}
