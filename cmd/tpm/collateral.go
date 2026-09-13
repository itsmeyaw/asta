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
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

var refreshCollateralFlags struct {
	akCert, root, output string
}

var (
	collateralCmd        = &cobra.Command{Use: "collateral", Short: "TPM verifier collateral operations"}
	refreshCollateralCmd = &cobra.Command{Use: "refresh", Short: "Refresh GCP TPM collateral", RunE: func(*cobra.Command, []string) error {
		ak, err := util.ReadCertificate(refreshCollateralFlags.akCert)
		if err != nil {
			return fmt.Errorf("reading AK certificate: %w", err)
		}
		root, err := util.ReadCertificate(refreshCollateralFlags.root)
		if err != nil {
			return fmt.Errorf("reading trusted root: %w", err)
		}
		if len(ak.IssuingCertificateURL) != 1 {
			return fmt.Errorf("AK certificate must advertise exactly one issuer URL")
		}
		issuerURL, err := googleAIAURL(ak.IssuingCertificateURL[0])
		if err != nil {
			return err
		}
		issuerDER, err := util.Fetch(issuerURL)
		if err != nil {
			return err
		}
		issuer, err := util.ParseCertificate(issuerDER)
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
		return util.WriteSnapshot(refreshCollateralFlags.output, "gcp", map[string][]byte{"ak.der": ak.Raw, "issuer.der": issuer.Raw, "root.der": root.Raw}, map[string]string{"issuer": issuerURL})
	}}
)

func init() {
	TpmCmd.AddCommand(collateralCmd)
	collateralCmd.AddCommand(refreshCollateralCmd)
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.akCert, "ak-cert", "", "GCP AK certificate")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.root, "trust-root", "", "Pinned Google EK/AK root certificate")
	refreshCollateralCmd.Flags().StringVar(&refreshCollateralFlags.output, "output", "", "New snapshot directory")
	_ = refreshCollateralCmd.MarkFlagRequired("ak-cert")
	_ = refreshCollateralCmd.MarkFlagRequired("trust-root")
	_ = refreshCollateralCmd.MarkFlagRequired("output")
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
