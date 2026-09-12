package sevsnp

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/itsmeyaw/asta/cmd/attest"
	"github.com/itsmeyaw/asta/cmd/libsevsnp"
	"github.com/spf13/cobra"
)

const profile = "longfellow-sev-snp-milan-vcek-v4"

type requirements struct {
	MinGuestSVN, Policy, FamilyID, ImageID, MinCurrentTCB, PlatformInfo, Nonce, Measurement, HostData, IDKeyDigest, AuthorKeyDigest, ReportID, ReportIDMA, MinCommittedTCB, MinLaunchTCB string
	VMPL                                                                                                                                                                                 uint32 `json:"vmpl"`
	MinBootloaderSVN, MinTEESVN, MinSNPSVN, MinMicrocodeSVN                                                                                                                              byte
}
type statement struct {
	Version                                       int          `json:"version"`
	Requirements                                  requirements `json:"requirements"`
	IssuerSPKI, VerificationTime, SerialBlocklist []byte
	ActiveSerials                                 int
}
type envelope struct {
	Profile     string    `json:"profile"`
	SpecVersion int       `json:"spec_version"`
	CircuitID   []byte    `json:"circuit_id"`
	Statement   statement `json:"statement"`
	Proof       []byte    `json:"proof"`
}

var flags struct {
	report, vcek, input, policy, circuit, output string
	check                                        bool
}
var SevSnpCmd = &cobra.Command{Use: "sev-snp", Short: "AMD Milan SEV-SNP report proofs"}
var proveCmd = &cobra.Command{Use: "prove", Short: "Generate an SEV-SNP report proof"}
var verifyCmd = &cobra.Command{Use: "verify", Short: "Verify an SEV-SNP report proof"}
var circuitCmd = &cobra.Command{Use: "circuit", Short: "SEV-SNP circuit operations"}
var proveReportCmd = &cobra.Command{Use: "report", Short: "Prove an SEV-SNP report", RunE: func(*cobra.Command, []string) error {
	p, r, err := load(flags.policy)
	if err != nil {
		return err
	}
	report, err := os.ReadFile(flags.report)
	if err != nil {
		return fmt.Errorf("reading report: %w", err)
	}
	vcekDER, err := os.ReadFile(flags.vcek)
	if err != nil {
		return fmt.Errorf("reading VCEK: %w", err)
	}
	vcek, err := x509.ParseCertificate(vcekDER)
	if err != nil {
		return fmt.Errorf("parsing VCEK: %w", err)
	}
	trust, err := attest.ValidateTrust(p, vcek, libsevsnp.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	s, err := makeStatement(p, r, trust)
	if err != nil {
		return err
	}
	if flags.check {
		if err := checkReport(report, vcek, s); err != nil {
			return err
		}
	}
	c, err := circuitFor(flags.circuit, p.SpecVersion)
	if err != nil {
		return err
	}
	quote := append(append([]byte(nil), report...), vcekDER...)
	proof, err := libsevsnp.Prove(c, toLib(s), quote)
	if err != nil {
		return err
	}
	id, err := libsevsnp.CircuitID(c, p.SpecVersion)
	if err != nil {
		return err
	}
	data, err := json.Marshal(envelope{p.Profile, p.SpecVersion, id[:], s, proof})
	if err != nil {
		return err
	}
	return os.WriteFile(flags.output, data, 0600)
}}
var verifyReportCmd = &cobra.Command{Use: "report", Short: "Verify an SEV-SNP report proof", RunE: func(*cobra.Command, []string) error {
	p, r, err := load(flags.policy)
	if err != nil {
		return err
	}
	trust, err := attest.ValidateCollateral(p, libsevsnp.SerialBlocklistCapacity)
	if err != nil {
		return err
	}
	want, err := makeStatement(p, r, trust)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(flags.input)
	if err != nil {
		return err
	}
	var proof envelope
	if err := json.Unmarshal(data, &proof); err != nil {
		return fmt.Errorf("parsing proof: %w", err)
	}
	if proof.Profile != p.Profile || proof.SpecVersion != p.SpecVersion || !same(proof.Statement, want) {
		return fmt.Errorf("proof statement does not match verifier policy and collateral")
	}
	c, err := circuitFor(flags.circuit, p.SpecVersion)
	if err != nil {
		return err
	}
	id, err := libsevsnp.CircuitID(c, p.SpecVersion)
	if err != nil || !bytes.Equal(id[:], proof.CircuitID) {
		return fmt.Errorf("proof circuit ID does not match verifier circuit")
	}
	return libsevsnp.Verify(c, toLib(want), proof.Proof)
}}
var generateCmd = &cobra.Command{Use: "generate <output>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
	c, err := libsevsnp.GenerateCircuit(6)
	if err != nil {
		return err
	}
	return os.WriteFile(args[0], c, 0600)
}}

func init() {
	SevSnpCmd.AddCommand(proveCmd, verifyCmd, circuitCmd)
	proveCmd.AddCommand(proveReportCmd)
	verifyCmd.AddCommand(verifyReportCmd)
	circuitCmd.AddCommand(generateCmd)
	proveReportCmd.Flags().StringVar(&flags.report, "report", "", "SEV-SNP report input")
	proveReportCmd.Flags().StringVar(&flags.vcek, "vcek", "", "VCEK certificate input")
	proveReportCmd.Flags().StringVar(&flags.policy, "policy", "", "Policy JSON")
	proveReportCmd.Flags().StringVar(&flags.circuit, "circuit", "", "Circuit file")
	proveReportCmd.Flags().StringVar(&flags.output, "output", "proof.json", "Proof output")
	proveReportCmd.Flags().BoolVar(&flags.check, "check-requirements", false, "Check report before proving")
	_ = proveReportCmd.MarkFlagRequired("report")
	_ = proveReportCmd.MarkFlagRequired("vcek")
	_ = proveReportCmd.MarkFlagRequired("policy")
	verifyReportCmd.Flags().StringVar(&flags.input, "input", "", "Proof input")
	verifyReportCmd.Flags().StringVar(&flags.policy, "policy", "", "Policy JSON")
	verifyReportCmd.Flags().StringVar(&flags.circuit, "circuit", "", "Circuit file")
	_ = verifyReportCmd.MarkFlagRequired("input")
	_ = verifyReportCmd.MarkFlagRequired("policy")
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
	if err := json.Unmarshal(p.Requirements, &r); err != nil {
		return p, r, fmt.Errorf("parsing SEV-SNP requirements: %w", err)
	}
	return p, r, nil
}
func circuitFor(path string, v int) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	return libsevsnp.GenerateCircuit(v)
}
func field(v string, n int) ([]byte, error) {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("expected %d hex bytes", n)
	}
	return b, nil
}
func must(v string) []byte { b, _ := hex.DecodeString(v); return b }
func makeStatement(p attest.Policy, r requirements, t attest.Trust) (statement, error) {
	for _, f := range []struct {
		v string
		n int
	}{{r.MinGuestSVN, 4}, {r.Policy, 8}, {r.FamilyID, 16}, {r.ImageID, 16}, {r.MinCurrentTCB, 8}, {r.PlatformInfo, 8}, {r.Nonce, 64}, {r.Measurement, 48}, {r.HostData, 32}, {r.IDKeyDigest, 48}, {r.AuthorKeyDigest, 48}, {r.ReportID, 32}, {r.ReportIDMA, 32}, {r.MinCommittedTCB, 8}, {r.MinLaunchTCB, 8}} {
		if _, err := field(f.v, f.n); err != nil {
			return statement{}, err
		}
	}
	return statement{p.SpecVersion, r, t.IssuerSPKI, t.VerificationTime, t.SerialBlocklist, t.ActiveBlocklistSize}, nil
}
func toLib(s statement) libsevsnp.Statement {
	r := s.Requirements
	var o libsevsnp.Statement
	o.Version = s.Version
	copy(o.MinGuestSVN[:], must(r.MinGuestSVN))
	copy(o.Policy[:], must(r.Policy))
	copy(o.FamilyID[:], must(r.FamilyID))
	copy(o.ImageID[:], must(r.ImageID))
	o.VMPL = r.VMPL
	copy(o.MinCurrentTCB[:], must(r.MinCurrentTCB))
	copy(o.PlatformInfo[:], must(r.PlatformInfo))
	copy(o.Nonce[:], must(r.Nonce))
	copy(o.Measurement[:], must(r.Measurement))
	copy(o.HostData[:], must(r.HostData))
	copy(o.IDKeyDigest[:], must(r.IDKeyDigest))
	copy(o.AuthorKeyDigest[:], must(r.AuthorKeyDigest))
	copy(o.ReportID[:], must(r.ReportID))
	copy(o.ReportIDMA[:], must(r.ReportIDMA))
	o.MinBootloaderSVN = r.MinBootloaderSVN
	o.MinTEESVN = r.MinTEESVN
	o.MinSNPSVN = r.MinSNPSVN
	o.MinMicrocodeSVN = r.MinMicrocodeSVN
	copy(o.MinCommittedTCB[:], must(r.MinCommittedTCB))
	copy(o.MinLaunchTCB[:], must(r.MinLaunchTCB))
	o.IssuerSPKI = s.IssuerSPKI
	o.VerificationTime = s.VerificationTime
	o.SerialBlocklist = s.SerialBlocklist
	o.ActiveSerials = s.ActiveSerials
	return o
}
func same(a, b statement) bool {
	aj, _ := json.Marshal(a.Requirements)
	bj, _ := json.Marshal(b.Requirements)
	return a.Version == b.Version && bytes.Equal(aj, bj) && bytes.Equal(a.IssuerSPKI, b.IssuerSPKI) && bytes.Equal(a.VerificationTime, b.VerificationTime) && bytes.Equal(a.SerialBlocklist, b.SerialBlocklist) && a.ActiveSerials == b.ActiveSerials
}
func checkReport(report []byte, vcek *x509.Certificate, s statement) error {
	parsed, err := sevabi.ReportToProto(report)
	if err != nil {
		return fmt.Errorf("parsing SEV-SNP report: %w", err)
	}
	extensions, err := kds.VcekCertificateExtensions(vcek)
	if err != nil {
		return fmt.Errorf("validating VCEK certificate extensions: %w", err)
	}
	if !bytes.Equal(extensions.HWID, parsed.GetChipId()) || uint64(extensions.TCBVersion) != parsed.GetReportedTcb() {
		return fmt.Errorf("VCEK certificate does not match report chip ID and TCB")
	}
	if err := sevverify.SnpReportSignature(report, vcek); err != nil {
		return fmt.Errorf("verifying SEV-SNP report signature: %w", err)
	}
	r := s.Requirements
	for i, minimum := range must(r.MinGuestSVN) {
		if report[0x04+i] < minimum {
			return fmt.Errorf("SEV-SNP report guest SVN is below policy")
		}
	}
	for i, minimum := range must(r.MinCurrentTCB) {
		if report[0x38+i] < minimum {
			return fmt.Errorf("SEV-SNP report current TCB is below policy")
		}
	}
	for i, minimum := range must(r.MinCommittedTCB) {
		if report[0x1e0+i] < minimum {
			return fmt.Errorf("SEV-SNP report committed TCB is below policy")
		}
	}
	for i, minimum := range must(r.MinLaunchTCB) {
		if report[0x1f0+i] < minimum {
			return fmt.Errorf("SEV-SNP report launch TCB is below policy")
		}
	}
	if !bytes.Equal(report[0x08:0x10], must(r.Policy)) || !bytes.Equal(report[0x10:0x20], must(r.FamilyID)) || !bytes.Equal(report[0x20:0x30], must(r.ImageID)) || binary.LittleEndian.Uint32(report[0x30:0x34]) != r.VMPL || !bytes.Equal(report[0x40:0x48], must(r.PlatformInfo)) || !bytes.Equal(report[0x50:0x90], must(r.Nonce)) || !bytes.Equal(report[0x90:0xc0], must(r.Measurement)) || !bytes.Equal(report[0xc0:0xe0], must(r.HostData)) || !bytes.Equal(report[0xe0:0x110], must(r.IDKeyDigest)) || !bytes.Equal(report[0x110:0x140], must(r.AuthorKeyDigest)) || !bytes.Equal(report[0x140:0x160], must(r.ReportID)) || !bytes.Equal(report[0x160:0x180], must(r.ReportIDMA)) {
		return fmt.Errorf("SEV-SNP report does not satisfy policy measurements")
	}
	tcb := report[0x180:0x188]
	if tcb[0] < r.MinBootloaderSVN || tcb[1] < r.MinTEESVN || tcb[6] < r.MinSNPSVN || tcb[7] < r.MinMicrocodeSVN {
		return fmt.Errorf("SEV-SNP report reported TCB is below policy")
	}
	return nil
}
