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

package quote

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/itsmeyaw/asta/cmd/types"
	"github.com/itsmeyaw/asta/cmd/util"
	"github.com/spf13/cobra"
)

type TpmQuoteFlags struct {
	Device string `json:"device" yaml:"device"`
}

var tpmFlags TpmQuoteFlags

var tpmQuoteCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Create a TPM quote",
	Long:  `Create a TPM quote for a given enclave.`,
	RunE: func(*cobra.Command, []string) error {
		devicePath, err := resolveTPMDevice(tpmFlags.Device)
		if err != nil {
			return err
		}

		tpm, err := util.OpenTPM(devicePath)
		if err != nil {
			return err
		}
		defer tpm.Close()

		pcrSelection, err := assignedPCRSelection(tpm)
		if err != nil {
			return err
		}

		pcrRsp, err := tpm2.PCRRead{PCRSelectionIn: *pcrSelection}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("reading PCRs: %w", err)
		}

		akHandle, akName, err := createAttestationKey(tpm)
		if err != nil {
			return err
		}
		defer func() {
			_, _ = tpm2.FlushContext{FlushHandle: akHandle}.Execute(tpm)
		}()

		quoteRsp, err := tpm2.Quote{
			SignHandle: tpm2.AuthHandle{
				Handle: akHandle,
				Name:   akName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			QualifyingData: tpm2.TPM2BData{Buffer: []byte(quoteFlags.Nonce)},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA},
			PCRSelect:      pcrRsp.PCRSelectionOut,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("quoting PCRs: %w", err)
		}

		payload := types.TpmQuote{
			Nonce:            quoteFlags.Nonce,
			Quote:            quoteRsp.Quoted.Bytes(),
			Signature:        tpm2.Marshal(quoteRsp.Signature),
			PCRSelection:     pcrRsp.PCRSelectionOut,
			PCRValues:        pcrRsp.PCRValues,
			Device:           devicePath,
			PCRUpdateCounter: pcrRsp.PCRUpdateCounter,
		}

		switch quoteFlags.Format {
		case FormatJSON:
			return writeQuoteJSON(quoteFlags.Out, payload)
		case FormatBin:
			return writeQuoteBinary(quoteFlags.Out, payload)
		default:
			return fmt.Errorf("unsupported format: %s", quoteFlags.Format)
		}
	},
}

func init() {
	quoteCmd.AddCommand(tpmQuoteCmd)

	tpmQuoteCmd.Flags().StringVar(&tpmFlags.Device, "device", "", "TPM device path (default: /dev/tpmrm0 or /dev/tpm0)")
}

func resolveTPMDevice(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	candidates := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no TPM device found (tried /dev/tpmrm0, /dev/tpm0)")
}

func assignedPCRSelection(tpm transport.TPM) (*tpm2.TPMLPCRSelection, error) {
	capRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("getting PCR capabilities: %w", err)
	}
	pcrs, err := capRsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("parsing PCR capabilities: %w", err)
	}
	if len(pcrs.PCRSelections) == 0 {
		return nil, fmt.Errorf("TPM reported no PCR banks")
	}
	return pcrs, nil
}

func createAttestationKey(tpm transport.TPM) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				KeyBits:  2048,
				Exponent: 0,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
		),
	}

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{},
		InPublic:    tpm2.New2B(template),
	}.Execute(tpm)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("creating attestation key: %w", err)
	}
	return createRsp.ObjectHandle, createRsp.Name, nil
}

func writeQuoteJSON(path string, payload types.TpmQuote) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func writeQuoteBinary(path string, payload types.TpmQuote) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer file.Close()

	if err := util.WriteBlob(file, payload.Quote); err != nil {
		return err
	}
	if err := util.WriteBlob(file, payload.Signature); err != nil {
		return err
	}
	if err := util.WriteBlob(file, tpm2.Marshal(payload.PCRSelection)); err != nil {
		return err
	}
	if err := util.WriteBlob(file, tpm2.Marshal(payload.PCRValues)); err != nil {
		return err
	}
	return nil
}
