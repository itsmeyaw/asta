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

package tdx

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/itsmeyaw/herta/cmd/attest"
	"github.com/itsmeyaw/herta/cmd/libtdx"
	"github.com/spf13/cobra"
)

const profile = "intel-tdx-quote-v4-pck-issuer-v3"

type requirements struct {
	MinTCBSVN       string   `json:"minimum_tcb_svn"`
	MRSEAM          string   `json:"mr_seam"`
	MRSignerSEAM    string   `json:"mr_signer_seam"`
	SEAMAttributes  string   `json:"seam_attributes"`
	TDAttributes    string   `json:"td_attributes"`
	MRTD            string   `json:"mr_td"`
	MROwnerConfigID string   `json:"mr_owner_config_id"`
	MROwner         string   `json:"mr_owner"`
	MROwnerConfig   string   `json:"mr_owner_config"`
	RTMR0           string   `json:"rtmr0"`
	RTMR1           string   `json:"rtmr1"`
	RTMR2Candidates []string `json:"rtmr2_candidates"`
	RTMR3Candidates []string `json:"rtmr3_candidates"`
	Nonce           string   `json:"nonce"`
	MinPCESVN       string   `json:"minimum_pce_svn"`
	MinCPUSVN       string   `json:"minimum_cpu_svn"`
}

type statement struct {
	Version          int          `json:"version"`
	Requirements     requirements `json:"requirements"`
	IssuerSPKI       []byte       `json:"issuer_spki"`
	VerificationTime []byte       `json:"verification_time"`
	SerialBlocklist  []byte       `json:"serial_blocklist"`
	ActiveSerials    int          `json:"active_serials"`
}

type proofEnvelope struct {
	Profile     string    `json:"profile"`
	SpecVersion int       `json:"spec_version"`
	CircuitID   []byte    `json:"circuit_id"`
	Statement   statement `json:"statement"`
	Proof       []byte    `json:"proof"`
}

var proveQuoteFlags struct {
	quote, policy, circuit, output string
	check                          bool
}

var verifyQuoteFlags struct {
	input, policy, circuit string
}

var (
	TdxCmd    = &cobra.Command{Use: "tdx", Short: "Intel TDX quote proofs"}
	proveCmd  = &cobra.Command{Use: "prove", Short: "Generate a TDX quote proof"}
	verifyCmd = &cobra.Command{Use: "verify", Short: "Verify a TDX quote proof"}
)

var proveQuoteCmd = &cobra.Command{Use: "quote", Short: "Prove a TDX quote", RunE: func(*cobra.Command, []string) error { return proveQuote() }}

var verifyQuoteCmd = &cobra.Command{Use: "quote", Short: "Verify a TDX quote proof", RunE: func(*cobra.Command, []string) error { return verifyQuote() }}

var generateCmd = &cobra.Command{Use: "generate <output>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
	c, err := libtdx.GenerateCircuit(6)
	if err != nil {
		return err
	}
	return os.WriteFile(args[0], c, 0600)
}}
var circuitCmd = &cobra.Command{Use: "circuit", Short: "TDX circuit operations"}

func init() {
	TdxCmd.AddCommand(proveCmd, verifyCmd, circuitCmd)
	proveCmd.AddCommand(proveQuoteCmd)
	verifyCmd.AddCommand(verifyQuoteCmd)
	circuitCmd.AddCommand(generateCmd)
	proveQuoteCmd.Flags().StringVar(&proveQuoteFlags.quote, "quote", "", "TDX quote input")
	proveQuoteCmd.Flags().StringVar(&proveQuoteFlags.policy, "policy", "", "Policy JSON")
	proveQuoteCmd.Flags().StringVar(&proveQuoteFlags.circuit, "circuit", "", "Circuit file")
	proveQuoteCmd.Flags().StringVarP(&proveQuoteFlags.output, "output", "o", "proof.json", "Proof output")
	proveQuoteCmd.Flags().BoolVar(&proveQuoteFlags.check, "check-requirements", false, "Check the quote before proving")
	_ = proveQuoteCmd.MarkFlagRequired("quote")
	_ = proveQuoteCmd.MarkFlagRequired("policy")
	verifyQuoteCmd.Flags().StringVarP(&verifyQuoteFlags.input, "input", "i", "", "Proof input")
	verifyQuoteCmd.Flags().StringVar(&verifyQuoteFlags.policy, "policy", "", "Policy JSON")
	verifyQuoteCmd.Flags().StringVar(&verifyQuoteFlags.circuit, "circuit", "", "Circuit file")
	_ = verifyQuoteCmd.MarkFlagRequired("input")
	_ = verifyQuoteCmd.MarkFlagRequired("policy")
}

func proveQuote() error {
	policy, req, err := load(proveQuoteFlags.policy)
	if err != nil {
		return err
	}
	quote, err := os.ReadFile(proveQuoteFlags.quote)
	if err != nil {
		return fmt.Errorf("reading quote: %w", err)
	}
	leaf, err := pckCertificate(quote)
	if err != nil {
		return err
	}
	trust, err := attest.ValidateTrust(policy, leaf, libtdx.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	st, err := makeStatement(policy, req, trust)
	if err != nil {
		return err
	}
	if proveQuoteFlags.check {
		if err := checkQuote(quote, st); err != nil {
			return err
		}
	}
	circuit, err := circuitFor(proveQuoteFlags.circuit, policy.SpecVersion)
	if err != nil {
		return err
	}
	proof, err := libtdx.Prove(circuit, toLib(st), quote)
	if err != nil {
		return err
	}
	id, err := libtdx.CircuitID(circuit, policy.SpecVersion)
	if err != nil {
		return err
	}
	data, err := json.Marshal(proofEnvelope{policy.Profile, policy.SpecVersion, id[:], st, proof})
	if err != nil {
		return err
	}
	return os.WriteFile(proveQuoteFlags.output, data, 0600)
}

func verifyQuote() error {
	policy, req, err := load(verifyQuoteFlags.policy)
	if err != nil {
		return err
	}
	trust, err := attest.ValidateCollateral(policy, libtdx.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	expected, err := makeStatement(policy, req, trust)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(verifyQuoteFlags.input)
	if err != nil {
		return err
	}
	var proof proofEnvelope
	if err := attest.DecodeJSON(data, &proof); err != nil {
		return fmt.Errorf("parsing proof: %w", err)
	}
	if proof.Profile != policy.Profile || proof.SpecVersion != policy.SpecVersion || !sameStatement(proof.Statement, expected) {
		return fmt.Errorf("proof statement does not match verifier policy and collateral")
	}
	circuit, err := circuitFor(verifyQuoteFlags.circuit, policy.SpecVersion)
	if err != nil {
		return err
	}
	id, err := libtdx.CircuitID(circuit, policy.SpecVersion)
	if err != nil || !bytes.Equal(id[:], proof.CircuitID) {
		return fmt.Errorf("proof circuit ID does not match verifier circuit")
	}
	return libtdx.Verify(circuit, toLib(expected), proof.Proof)
}

func load(path string) (attest.Policy, requirements, error) {
	p, err := attest.LoadPolicy(path)
	if err != nil {
		return p, requirements{}, err
	}
	if p.Profile != profile {
		return p, requirements{}, fmt.Errorf("policy profile must be %s", profile)
	}
	var r requirements
	if err := attest.DecodeJSON(p.Requirements, &r); err != nil {
		return p, r, fmt.Errorf("parsing TDX requirements: %w", err)
	}
	return p, r, nil
}

func circuitFor(path string, version int) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	return libtdx.GenerateCircuit(version)
}

func fixed(value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("expected %d hex bytes", size)
	}
	return b, nil
}

func makeStatement(p attest.Policy, r requirements, trust attest.Trust) (statement, error) {
	fields := []struct {
		value string
		size  int
	}{{r.MinTCBSVN, 16}, {r.MRSEAM, 48}, {r.MRSignerSEAM, 48}, {r.SEAMAttributes, 8}, {r.TDAttributes, 8}, {r.MRTD, 48}, {r.MROwnerConfigID, 48}, {r.MROwner, 48}, {r.MROwnerConfig, 48}, {r.RTMR0, 48}, {r.RTMR1, 48}, {r.Nonce, 32}, {r.MinPCESVN, 1}, {r.MinCPUSVN, 16}}
	for _, f := range fields {
		if _, err := fixed(f.value, f.size); err != nil {
			return statement{}, err
		}
	}
	if len(r.RTMR2Candidates) != 1 || len(r.RTMR3Candidates) != 1 {
		return statement{}, fmt.Errorf("TDX profile requires one RTMR2 and RTMR3 candidate")
	}
	if _, err := fixed(r.RTMR2Candidates[0], 48); err != nil {
		return statement{}, err
	}
	if _, err := fixed(r.RTMR3Candidates[0], 48); err != nil {
		return statement{}, err
	}
	return statement{p.SpecVersion, r, trust.IssuerSPKI, trust.VerificationTime, trust.SerialBlocklist, trust.ActiveBlocklistSize}, nil
}

func toLib(s statement) libtdx.Statement {
	r := s.Requirements
	var out libtdx.Statement
	out.Version = s.Version
	copy(out.MinTCBSVN[:], must(r.MinTCBSVN))
	copy(out.MRSEAM[:], must(r.MRSEAM))
	copy(out.MRSignerSEAM[:], must(r.MRSignerSEAM))
	copy(out.SEAMAttributes[:], must(r.SEAMAttributes))
	copy(out.TDAttributes[:], must(r.TDAttributes))
	copy(out.MRTD[:], must(r.MRTD))
	copy(out.MROwnerConfigID[:], must(r.MROwnerConfigID))
	copy(out.MROwner[:], must(r.MROwner))
	copy(out.MROwnerConfig[:], must(r.MROwnerConfig))
	copy(out.RTMR0[:], must(r.RTMR0))
	copy(out.RTMR1[:], must(r.RTMR1))
	out.RTMR2Candidates = [][48]byte{{}}
	copy(out.RTMR2Candidates[0][:], must(r.RTMR2Candidates[0]))
	out.RTMR3Candidates = [][48]byte{{}}
	copy(out.RTMR3Candidates[0][:], must(r.RTMR3Candidates[0]))
	out.Nonce = must(r.Nonce)
	copy(out.MinPCESVN[:], must(r.MinPCESVN))
	copy(out.MinCPUSVN[:], must(r.MinCPUSVN))
	out.IssuerSPKI = s.IssuerSPKI
	out.VerificationTime = s.VerificationTime
	out.SerialBlocklist = s.SerialBlocklist
	out.ActiveSerials = s.ActiveSerials
	return out
}
func must(v string) []byte { b, _ := hex.DecodeString(v); return b }
func sameStatement(a, b statement) bool {
	ar, _ := json.Marshal(a.Requirements)
	br, _ := json.Marshal(b.Requirements)
	return a.Version == b.Version && bytes.Equal(ar, br) && bytes.Equal(a.IssuerSPKI, b.IssuerSPKI) && bytes.Equal(a.VerificationTime, b.VerificationTime) && bytes.Equal(a.SerialBlocklist, b.SerialBlocklist) && a.ActiveSerials == b.ActiveSerials
}

func checkQuote(q []byte, s statement) error {
	if _, err := parseQuote(q); err != nil {
		return err
	}
	r := s.Requirements
	for i, minimum := range must(r.MinTCBSVN) {
		if q[48+i] < minimum {
			return fmt.Errorf("TDX quote TCB SVN is below policy")
		}
	}
	if !bytes.Equal(q[64:112], must(r.MRSEAM)) || !bytes.Equal(q[112:160], must(r.MRSignerSEAM)) || !bytes.Equal(q[160:168], must(r.SEAMAttributes)) || !bytes.Equal(q[168:176], must(r.TDAttributes)) || !bytes.Equal(q[184:232], must(r.MRTD)) || !bytes.Equal(q[232:280], must(r.MROwnerConfigID)) || !bytes.Equal(q[280:328], must(r.MROwner)) || !bytes.Equal(q[328:376], must(r.MROwnerConfig)) || !bytes.Equal(q[376:424], must(r.RTMR0)) || !bytes.Equal(q[424:472], must(r.RTMR1)) || !bytes.Equal(q[472:520], must(r.RTMR2Candidates[0])) || !bytes.Equal(q[520:568], must(r.RTMR3Candidates[0])) || !bytes.Equal(q[568:600], must(r.Nonce)) {
		return fmt.Errorf("TDX quote does not satisfy required measurements or nonce")
	}
	return nil
}

func pckCertificate(q []byte) (*x509.Certificate, error) {
	chainData, err := pckChainData(q)
	if err != nil {
		return nil, err
	}
	leaf, _, err := parsePCKLeaf(chainData)
	return leaf, err
}

func pckChainData(raw []byte) ([]byte, error) {
	parsed, err := tdxabi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing TDX quote: %w", err)
	}
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("Longfellow TDX proofs support Quote v4 only")
	}
	chainData := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	if len(chainData) == 0 {
		return nil, fmt.Errorf("TDX quote has no PCK certificate data")
	}
	return chainData, nil
}

func parsePCKLeaf(chainData []byte) (*x509.Certificate, []byte, error) {
	leaf, remaining := pem.Decode(chainData)
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("TDX quote must contain a PEM PCK certificate")
	}
	leafCert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PCK certificate: %w", err)
	}
	if _, err := pcs.PckCertificateExtensions(leafCert); err != nil {
		return nil, nil, fmt.Errorf("validating PCK certificate extensions: %w", err)
	}
	return leafCert, remaining, nil
}

func parseQuote(raw []byte) (*pckChain, error) {
	chainData, err := pckChainData(raw)
	if err != nil {
		return nil, err
	}
	leafCert, remaining, err := parsePCKLeaf(chainData)
	if err != nil {
		return nil, err
	}
	issuer, remaining := pem.Decode(remaining)
	root, remaining := pem.Decode(remaining)
	if issuer == nil || root == nil || len(bytes.Trim(remaining, "\x00 \t\r\n")) != 0 || issuer.Type != "CERTIFICATE" || root.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("TDX quote must contain exactly three PEM PCK certificates")
	}
	issuerCert, err := x509.ParseCertificate(issuer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PCK issuer certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PCK root certificate: %w", err)
	}
	return &pckChain{leafCert, issuerCert, rootCert}, nil
}

type pckChain struct {
	PCKCertificate          *x509.Certificate
	IntermediateCertificate *x509.Certificate
	RootCertificate         *x509.Certificate
}

// ExtractPCKChain parses the fixed Quote v4 PCK chain used by this profile.
func ExtractPCKChain(raw []byte) (leaf, issuer, root *x509.Certificate, err error) {
	chain, err := parseQuote(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	return chain.PCKCertificate, chain.IntermediateCertificate, chain.RootCertificate, nil
}
