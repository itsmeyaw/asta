package sevsnp

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

var refreshCollateralFlags struct {
	quote, root, output string
}

var collateralCmd = &cobra.Command{Use: "collateral", Short: "SEV-SNP verifier collateral operations"}
var refreshCollateralCmd = &cobra.Command{Use: "refresh", Short: "Refresh AMD Milan SEV-SNP collateral", RunE: func(*cobra.Command, []string) error {
	reportBytes, err := os.ReadFile(refreshCollateralFlags.quote)
	if err != nil {
		return fmt.Errorf("reading quote: %w", err)
	}
	report, err := sevabi.ReportToProto(reportBytes)
	if err != nil {
		return fmt.Errorf("parsing report: %w", err)
	}
	const product = "Milan"
	vcekURL := kds.VCEKCertURL(product, report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
	chainURL := kds.ProductCertChainURL(sevabi.VcekReportSigner, product)
	crlURL := kds.CrlLinkByRole(product, "ASK")
	vcekDER, err := util.Fetch(vcekURL)
	if err != nil {
		return err
	}
	chainPEM, err := util.Fetch(chainURL)
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
	trustedRoot, err := util.ReadCertificate(refreshCollateralFlags.root)
	if err != nil {
		return fmt.Errorf("reading trusted root: %w", err)
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
	issuerCRL, err := util.Fetch(crlURL)
	if err != nil {
		return err
	}
	parsedIssuerCRL, err := x509.ParseRevocationList(issuerCRL)
	if err != nil {
		return fmt.Errorf("parsing AMD issuer CRL: %w", err)
	}
	if err := util.ValidateCRL(parsedIssuerCRL, root, time.Now()); err != nil {
		return fmt.Errorf("validating AMD issuer CRL: %w", err)
	}
	return util.WriteSnapshot(refreshCollateralFlags.output, "sev-snp", map[string][]byte{"vcek.der": vcekDER, "issuer.der": issuerDER, "root.der": rootDER, "issuer.crl": issuerCRL}, map[string]string{"vcek": vcekURL, "chain": chainURL, "issuer_crl": crlURL})
}}

func init() {
	SevSnpCmd.AddCommand(collateralCmd)
	collateralCmd.AddCommand(refreshCollateralCmd)
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.quote, "quote", "", "SEV-SNP quote")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.root, "trust-root", "", "Pinned AMD ARK certificate")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.output, "output", "", "New snapshot directory")
	_ = refreshCollateralCmd.MarkFlagRequired("quote")
	_ = refreshCollateralCmd.MarkFlagRequired("trust-root")
	_ = refreshCollateralCmd.MarkFlagRequired("output")
}
