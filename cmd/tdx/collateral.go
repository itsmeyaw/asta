package tdx

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

var refreshCollateralFlags struct {
	quote, root, output string
}

var collateralCmd = &cobra.Command{Use: "collateral", Short: "TDX verifier collateral operations"}
var refreshCollateralCmd = &cobra.Command{Use: "refresh", Short: "Refresh Intel TDX collateral", RunE: func(*cobra.Command, []string) error {
	quote, err := os.ReadFile(refreshCollateralFlags.quote)
	if err != nil {
		return fmt.Errorf("reading quote: %w", err)
	}
	leaf, issuer, root, err := ExtractPCKChain(quote)
	if err != nil {
		return err
	}
	trustedRoot, err := util.ReadCertificate(refreshCollateralFlags.root)
	if err != nil {
		return fmt.Errorf("reading trusted root: %w", err)
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
	var ca string
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
	leafCRL, headers, err := util.FetchWithHeaders(leafURL)
	if err != nil {
		return err
	}
	crlIssuer, crlRoot, err := parseIssuerChain(headers.Values("Sgx-Pck-Crl-Issuer-Chain"))
	if err != nil {
		return fmt.Errorf("parsing Intel PCK CRL issuer chain: %w", err)
	}
	if !bytes.Equal(crlIssuer.Raw, issuer.Raw) || !bytes.Equal(crlRoot.Raw, root.Raw) {
		return fmt.Errorf("Intel PCK CRL issuer chain does not match quote chain")
	}
	issuerCRL, err := util.Fetch(issuerURL)
	if err != nil {
		return err
	}
	parsedLeafCRL, err := x509.ParseRevocationList(leafCRL)
	if err != nil {
		return fmt.Errorf("parsing PCK CRL: %w", err)
	}
	if err := util.ValidateCRL(parsedLeafCRL, issuer, time.Now()); err != nil {
		return fmt.Errorf("validating PCK CRL: %w", err)
	}
	parsedIssuerCRL, err := x509.ParseRevocationList(issuerCRL)
	if err != nil {
		return fmt.Errorf("parsing root CRL: %w", err)
	}
	if err := util.ValidateCRL(parsedIssuerCRL, root, time.Now()); err != nil {
		return fmt.Errorf("validating root CRL: %w", err)
	}
	return util.WriteSnapshot(refreshCollateralFlags.output, "tdx", map[string][]byte{"pck.der": leaf.Raw, "issuer.der": issuer.Raw, "root.der": root.Raw, "leaf.crl": leafCRL, "issuer.crl": issuerCRL}, map[string]string{"leaf_crl": leafURL, "issuer_crl": issuerURL})
}}

func init() {
	TdxCmd.AddCommand(collateralCmd)
	collateralCmd.AddCommand(refreshCollateralCmd)
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.quote, "quote", "", "TDX Quote v4")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.root, "trust-root", "", "Pinned Intel root certificate")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.output, "output", "", "New snapshot directory")
	_ = refreshCollateralCmd.MarkFlagRequired("quote")
	_ = refreshCollateralCmd.MarkFlagRequired("trust-root")
	_ = refreshCollateralCmd.MarkFlagRequired("output")
}

func onlyCRLURL(cert *x509.Certificate) (string, error) {
	if len(cert.CRLDistributionPoints) != 1 {
		return "", fmt.Errorf("certificate %q must have exactly one CRL URL", cert.Subject.CommonName)
	}
	return cert.CRLDistributionPoints[0], nil
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
