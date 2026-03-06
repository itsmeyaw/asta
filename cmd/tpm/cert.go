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

	"github.com/spf13/cobra"
)

type TpmProveCertCmdFlags struct {
}

var tpmProveCertCmdFlags = &TpmProveCertCmdFlags{}

var tpmProveCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Prove the certificate of the Attestation Key (AK) in TPM",
	RunE: func(cmd *cobra.Command, args []string) error {
		tpm, err := openTPM(tpmCmdFlags.DevicePath)
		if err != nil {
			return fmt.Errorf("opening TPM: %w", err)
		}
		defer tpm.Close()

		akResponse, err := attesationKeys[tpmCmdFlags.AttestationKeyType](tpm)
		if err != nil {
			return fmt.Errorf("creating attestation key: %w", err)
		}
		akCert := akResponse.certificate

		_, err = generateProof(akCert)
		if err != nil {
			return fmt.Errorf("generating proof: %w", err)
		}

		return nil
	},
}

func generateProof(cert x509.Certificate) ([]byte, error) {
	// For demonstration purposes, we will just return the certificate's raw bytes as the proof.
	// In a real implementation, you would generate a proper zero-knowledge proof here.
	return cert.Raw, nil
}

var tpmVerifyCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Verify the certificate of the Attestation Key (AK) in TPM",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	tpmProveCmd.AddCommand(tpmProveCertCmd)
	tpmVerifyCmd.AddCommand(tpmVerifyCertCmd)
}
