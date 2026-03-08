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
	"crypto/rand"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/spf13/cobra"
)

const (
	GceAKCertNVIndex     uint32 = 0x01c10002
	GceAKTemplateNVIndex uint32 = 0x01c10003
)

var attesationKeys = map[string]func(transport.TPM) (*TPM2Key, error){
	"gce": getGCEAttestationKey,
}

type TpmCmdFlags struct {
	DevicePath         string `yaml:"device_path"`
	Nonce              []byte `yaml:"nonce"` // We need nonce for all proofs for freshness
	AttestationKeyType string `yaml:"attestation_key_type"`
	Verbose            bool   `yaml:"verbose"`
}

var tpmCmdFlags = &TpmCmdFlags{}

var TpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Commands related to TPM operations",
	Long:  "This command group contains subcommands for performing various TPM operations.",
}

type TpmProveCmdFlags struct {
	OutputPath string
	// For debug only, the actual proof
	// should not require certificate and signatures
	OutputCertificatePath string
	OutputSignaturePath   string
}

var tpmProveCmdFlags = &TpmProveCmdFlags{}

var tpmProveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Prove a TPM quote zero knowledge proof",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		tpmCmdFlags.Verbose, err = cmd.Flags().GetBool("verbose")
		if err != nil {
			return err
		}
		return nil
	},
}

type TpmVerifyCmdFlags struct {
	InputPath string
}

var tpmVerifyCmdFlags = &TpmVerifyCmdFlags{}

var tpmVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the integrity of the system using TPM",
}

func openTPM(devicePath string) (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open(devicePath)
	if err != nil {
		return nil, fmt.Errorf("opening TPM device %s: %w", devicePath, err)
	}
	return tpm, nil
}

func generateSecureNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func init() {
	TpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.DevicePath, "device", "d", "/dev/tpm0", "Path to the TPM device (e.g., /dev/tpm0)")
	TpmCmd.PersistentFlags().StringVarP(&tpmProveCmdFlags.OutputSignaturePath, "signature-output", "s", "quote.sig", "Output file for the TPM quote signature")
	TpmCmd.PersistentFlags().StringVarP(&tpmCmdFlags.AttestationKeyType, "attestation-key-type", "t", "gce", "Type of attestation key to use (default: gce)")

	TpmCmd.AddCommand(tpmProveCmd)
	tpmProveCmd.PersistentFlags().StringVarP(&tpmProveCmdFlags.OutputPath, "output", "o", "proof.bin", "Output file for the TPM quote proof")

	TpmCmd.AddCommand(tpmVerifyCmd)
	tpmVerifyCmd.PersistentFlags().StringVarP(&tpmVerifyCmdFlags.InputPath, "input", "i", "proof.bin", "Input file for the TPM quote proof to verify")
}
