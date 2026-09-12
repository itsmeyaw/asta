package collateral

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/itsmeyaw/asta/cmd/tdx"
	"github.com/spf13/cobra"
)

type manifest struct {
	Platform  string            `json:"platform"`
	Retrieved string            `json:"retrieved"`
	Sources   map[string]string `json:"sources"`
	SHA256    map[string]string `json:"sha256"`
}

var flags struct{ akCert, quote, report, root, output string }

var CollateralCmd = &cobra.Command{Use: "collateral", Short: "Create verifier collateral snapshots"}
var refreshCmd = &cobra.Command{Use: "refresh", Short: "Fetch and validate vendor collateral"}

var refreshTDXCmd = &cobra.Command{Use: "tdx", Short: "Refresh Intel TDX collateral", RunE: func(*cobra.Command, []string) error {
	quote, err := os.ReadFile(flags.quote)
	if err != nil {
		return fmt.Errorf("reading quote: %w", err)
	}
	leaf, issuer, root, err := tdx.ExtractPCKChain(quote)
	if err != nil {
		return err
	}
	trustedRoot, err := readCertificate(flags.root)
	if err != nil {
		return err
	}
	if !bytes.Equal(root.Raw, trustedRoot.Raw) {
		return fmt.Errorf("TDX quote root does not match --trust-root")
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("validating PCK certificate: %w", err)
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("validating PCK issuer: %w", err)
	}
	ca := ""
	switch issuer.Subject.CommonName {
	case "Intel SGX PCK Platform CA":
		ca = "platform"
	case "Intel SGX PCK Processor CA":
		ca = "processor"
	default:
		return fmt.Errorf("unsupported PCK issuer %q", issuer.Subject.CommonName)
	}
	leafURL := pcs.PckCrlURL(ca)
	issuerURL, err := onlyCRLURL(root)
	if err != nil {
		return err
	}
	leafCRL, header, err := fetchWithHeaders(leafURL)
	if err != nil {
		return err
	}
	crlIssuer, crlRoot, err := parseIssuerChain(header.Values("Sgx-Pck-Crl-Issuer-Chain"))
	if err != nil {
		return fmt.Errorf("parsing Intel PCK CRL issuer chain: %w", err)
	}
	if !bytes.Equal(crlIssuer.Raw, issuer.Raw) || !bytes.Equal(crlRoot.Raw, root.Raw) {
		return fmt.Errorf("Intel PCK CRL issuer chain does not match quote chain")
	}
	issuerCRL, err := fetch(issuerURL)
	if err != nil {
		return err
	}
	if err := validateCRL(leafCRL, issuer); err != nil {
		return fmt.Errorf("validating PCK CRL: %w", err)
	}
	if err := validateCRL(issuerCRL, root); err != nil {
		return fmt.Errorf("validating root CRL: %w", err)
	}
	return writeSnapshot(flags.output, "tdx", map[string][]byte{"pck.der": leaf.Raw, "issuer.der": issuer.Raw, "root.der": root.Raw, "leaf.crl": leafCRL, "issuer.crl": issuerCRL}, map[string]string{"leaf_crl": leafURL, "issuer_crl": issuerURL})
}}

var refreshSNPCmd = &cobra.Command{Use: "sev-snp", Short: "Refresh AMD Milan SEV-SNP collateral", RunE: func(*cobra.Command, []string) error {
	reportBytes, err := os.ReadFile(flags.report)
	if err != nil {
		return fmt.Errorf("reading report: %w", err)
	}
	report, err := sevabi.ReportToProto(reportBytes)
	if err != nil {
		return fmt.Errorf("parsing report: %w", err)
	}
	product := "Milan"
	vcekURL := kds.VCEKCertURL(product, report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
	chainURL := kds.ProductCertChainURL(sevabi.VcekReportSigner, product)
	crlURL := kds.CrlLinkByRole(product, "ASK")
	vcekDER, err := fetch(vcekURL)
	if err != nil {
		return err
	}
	chainPEM, err := fetch(chainURL)
	if err != nil {
		return err
	}
	issuerDER, rootDER, err := kds.ParseProductCertChain(chainPEM)
	if err != nil {
		return fmt.Errorf("parsing AMD chain: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	trustedRoot, err := readCertificate(flags.root)
	if err != nil {
		return err
	}
	if !bytes.Equal(root.Raw, trustedRoot.Raw) {
		return fmt.Errorf("AMD KDS root does not match --trust-root")
	}
	vcek, err := x509.ParseCertificate(vcekDER)
	if err != nil {
		return err
	}
	if err := vcek.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("validating VCEK certificate: %w", err)
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("validating ASK certificate: %w", err)
	}
	issuerCRL, err := fetch(crlURL)
	if err != nil {
		return err
	}
	if err := validateCRL(issuerCRL, root); err != nil {
		return fmt.Errorf("validating AMD issuer CRL: %w", err)
	}
	return writeSnapshot(flags.output, "sev-snp", map[string][]byte{"vcek.der": vcekDER, "issuer.der": issuerDER, "root.der": rootDER, "issuer.crl": issuerCRL}, map[string]string{"vcek": vcekURL, "chain": chainURL, "issuer_crl": crlURL})
}}

var refreshGCPCmd = &cobra.Command{Use: "gcp", Short: "Refresh GCP TPM collateral", RunE: func(*cobra.Command, []string) error {
	ak, err := readCertificate(flags.akCert)
	if err != nil {
		return fmt.Errorf("reading AK certificate: %w", err)
	}
	root, err := readCertificate(flags.root)
	if err != nil {
		return err
	}
	if len(ak.IssuingCertificateURL) != 1 {
		return fmt.Errorf("AK certificate must advertise exactly one issuer URL")
	}
	issuerURL, err := googleAIAURL(ak.IssuingCertificateURL[0])
	if err != nil {
		return err
	}
	issuerDER, err := fetch(issuerURL)
	if err != nil {
		return err
	}
	issuer, err := parseCertificate(issuerDER)
	if err != nil {
		return fmt.Errorf("parsing GCP issuer certificate: %w", err)
	}
	if !issuer.IsCA || !root.IsCA {
		return fmt.Errorf("GCP issuer and trusted root must be CA certificates")
	}
	if err := ak.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("validating AK certificate: %w", err)
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("validating GCP issuer certificate: %w", err)
	}
	if _, err := ak.Verify(x509.VerifyOptions{Roots: certPool(root), Intermediates: certPool(issuer), CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("verifying GCP AK chain: %w", err)
	}
	return writeSnapshot(flags.output, "gcp", map[string][]byte{"ak.der": ak.Raw, "issuer.der": issuer.Raw, "root.der": root.Raw}, map[string]string{"issuer": issuerURL})
}}

func init() {
	CollateralCmd.AddCommand(refreshCmd)
	refreshCmd.AddCommand(refreshGCPCmd, refreshTDXCmd, refreshSNPCmd)
	refreshGCPCmd.Flags().StringVar(&flags.akCert, "ak-cert", "", "GCP AK certificate")
	refreshGCPCmd.Flags().StringVar(&flags.root, "trust-root", "", "Pinned Google EK/AK root certificate")
	refreshGCPCmd.Flags().StringVar(&flags.output, "output", "", "New snapshot directory")
	_ = refreshGCPCmd.MarkFlagRequired("ak-cert")
	_ = refreshGCPCmd.MarkFlagRequired("trust-root")
	_ = refreshGCPCmd.MarkFlagRequired("output")
	refreshTDXCmd.Flags().StringVar(&flags.quote, "quote", "", "TDX Quote v4")
	refreshTDXCmd.Flags().StringVar(&flags.root, "trust-root", "", "Pinned Intel root certificate")
	refreshTDXCmd.Flags().StringVar(&flags.output, "output", "", "New snapshot directory")
	_ = refreshTDXCmd.MarkFlagRequired("quote")
	_ = refreshTDXCmd.MarkFlagRequired("trust-root")
	_ = refreshTDXCmd.MarkFlagRequired("output")
	refreshSNPCmd.Flags().StringVar(&flags.report, "report", "", "SEV-SNP report")
	refreshSNPCmd.Flags().StringVar(&flags.root, "trust-root", "", "Pinned AMD ARK certificate")
	refreshSNPCmd.Flags().StringVar(&flags.output, "output", "", "New snapshot directory")
	_ = refreshSNPCmd.MarkFlagRequired("report")
	_ = refreshSNPCmd.MarkFlagRequired("trust-root")
	_ = refreshSNPCmd.MarkFlagRequired("output")
}
func fetch(source string) ([]byte, error) {
	body, _, err := fetchWithHeaders(source)
	return body, err
}
func fetchWithHeaders(source string) ([]byte, http.Header, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, nil, fmt.Errorf("refusing non-HTTPS collateral URL %q", source)
	}
	c := http.Client{Timeout: 30 * time.Second}
	r, err := c.Get(source)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %s: %w", source, err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetching %s: status %s", source, r.Status)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		return nil, nil, err
	}
	return b, r.Header, nil
}
func onlyCRLURL(cert *x509.Certificate) (string, error) {
	if len(cert.CRLDistributionPoints) != 1 {
		return "", fmt.Errorf("certificate %q must have exactly one CRL URL", cert.Subject.CommonName)
	}
	return cert.CRLDistributionPoints[0], nil
}
func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := parseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}
func parseCertificate(raw []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	return x509.ParseCertificate(raw)
}
func parseIssuerChain(values []string) (*x509.Certificate, *x509.Certificate, error) {
	if len(values) != 1 || values[0] == "" {
		return nil, nil, fmt.Errorf("expected one issuer-chain header")
	}
	chain, err := url.QueryUnescape(values[0])
	if err != nil {
		return nil, nil, err
	}
	issuerBlock, rest := pem.Decode([]byte(chain))
	if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("missing issuer certificate")
	}
	rootBlock, rest := pem.Decode(rest)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, nil, fmt.Errorf("missing root certificate")
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return issuer, root, nil
}
func googleAIAURL(source string) (string, error) {
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasSuffix(u.Hostname(), ".storage.googleapis.com") {
		return "", fmt.Errorf("GCP AK issuer URL must be a Google Cloud Storage URL")
	}
	u.Scheme = "https"
	return u.String(), nil
}
func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
func validateCRL(raw []byte, signer *x509.Certificate) error {
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(crl.RawIssuer, signer.RawSubject) {
		return fmt.Errorf("CRL issuer does not match signer")
	}
	if err := crl.CheckSignatureFrom(signer); err != nil {
		return err
	}
	now := time.Now()
	if crl.ThisUpdate.After(now) || crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) {
		return fmt.Errorf("CRL is not currently valid")
	}
	return nil
}
func writeSnapshot(output, platform string, files map[string][]byte, sources map[string]string) error {
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("snapshot directory %q already exists", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	m := manifest{Platform: platform, Retrieved: time.Now().UTC().Format(time.RFC3339), Sources: sources, SHA256: map[string]string{}}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		m.SHA256[name] = hex.EncodeToString(sum[:])
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "manifest.json"), data, 0600)
}
