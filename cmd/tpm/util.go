package tpm

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func getGCEAttestationKey(tpm transport.TPM) (*TPM2Key, error) {
	akTemplateBytes, err := readNVIndexData(tpm, GceAKTemplateNVIndex)
	if err != nil {
		return nil, fmt.Errorf("reading GCE AK template from NV index: %w", err)
	}

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](akTemplateBytes),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("creating GCE attestation key from NV template: %w", err)
	}

	outPublic, err := createRsp.OutPublic.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}.Execute(tpm)
		return nil, fmt.Errorf("parsing GCE AK public area: %w", err)
	}

	key := &TPM2Key{
		handle: createRsp.ObjectHandle,
		name:   createRsp.Name,
		public: *outPublic,
	}

	certBytes, err := readNVIndexData(tpm, GceAKCertNVIndex)
	if err == nil {
		x509Cert, certErr := x509.ParseCertificate(certBytes)
		if certErr != nil {
			_, _ = tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}.Execute(tpm)
			return nil, fmt.Errorf("failed to parse GCE AK certificate from NV memory: %w", certErr)
		}
		key.certificate = *x509Cert
	}

	return key, nil
}

func readNVIndexData(tpm transport.TPM, index uint32) ([]byte, error) {
	readPubRsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	capRsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	props, err := capRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	if len(props.TPMProperty) == 0 {
		return nil, fmt.Errorf("TPM did not return NV buffer max property")
	}

	blockSize := int(props.TPMProperty[0].Value)
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid NV buffer max value: %d", blockSize)
	}

	outBuff := make([]byte, 0, int(nvPublic.DataSize))
	for len(outBuff) < int(nvPublic.DataSize) {
		readSize := blockSize
		if remaining := int(nvPublic.DataSize) - len(outBuff); readSize > remaining {
			readSize = remaining
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.HandleName(tpm2.TPMRHOwner),
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: uint16(len(outBuff)),
		}.Execute(tpm)
		if err != nil {
			return nil, err
		}

		outBuff = append(outBuff, readRsp.Data.Buffer...)
	}

	return outBuff, nil
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
