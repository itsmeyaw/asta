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

package libtpm2

/*
#cgo CFLAGS: -I${SRCDIR}/../../../libraries/longfellow-zk-2/lib
#cgo pkg-config: openssl libzstd
#cgo LDFLAGS: -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/tpm2_quote -ltpm2_quote_static -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/x509 -lx509_native
#cgo linux LDFLAGS: -lstdc++ -lm
#cgo darwin LDFLAGS: -lc++ -lm

#include "circuits/tpm2_quote/tpm2_quote_zk.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	SerialBlocklistCapacity = 16
	SerialSize              = 20
	VerificationTimeSize    = 15
)

type Statement struct {
	Version          int
	Nonce            []byte
	MinFirmware      [8]byte
	PCRHash          [32]byte
	IssuerSPKI       []byte
	VerificationTime []byte
	SerialBlocklist  []byte
	ActiveSerials    int
}

func GenerateCircuit() ([]byte, error) {
	var output *C.uint8_t
	var outputLen C.size_t
	if rc := C.generate_gcp_tpm2_circuit(&output, &outputLen); rc != C.TPM2_QUOTE_CIRCUIT_GENERATION_SUCCESS {
		return nil, fmt.Errorf("generating GCP TPM circuit failed with error code %d", rc)
	}
	defer C.free(unsafe.Pointer(output))
	return C.GoBytes(unsafe.Pointer(output), C.int(outputLen)), nil
}

func CircuitID(circuit []byte, version int) ([32]byte, error) {
	if len(circuit) == 0 {
		return [32]byte{}, fmt.Errorf("circuit is empty")
	}
	spec, err := specFor(version)
	if err != nil {
		return [32]byte{}, err
	}
	var id [32]byte
	if rc := C.circuit_id((*C.uint8_t)(unsafe.Pointer(&id[0])), bytesPointer(circuit), C.size_t(len(circuit)), spec); rc != 1 {
		return [32]byte{}, fmt.Errorf("computing GCP TPM circuit ID failed with error code %d", rc)
	}
	return id, nil
}

func Prove(circuit []byte, statement Statement, quote []byte, r, s [32]byte, certificateDER []byte) ([]byte, error) {
	if err := validate(circuit, statement, quote, certificateDER); err != nil {
		return nil, err
	}
	spec, err := specFor(statement.Version)
	if err != nil {
		return nil, err
	}
	var proof *C.uint8_t
	var proofLen C.size_t
	rc := C.run_gcp_tpm2_quote_prover(
		spec,
		bytesPointer(circuit), C.size_t(len(circuit)),
		bytesPointer(statement.Nonce), C.size_t(len(statement.Nonce)),
		(*C.uint8_t)(unsafe.Pointer(&statement.MinFirmware[0])),
		(*C.uint8_t)(unsafe.Pointer(&statement.PCRHash[0])),
		bytesPointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		bytesPointer(statement.VerificationTime), C.size_t(len(statement.VerificationTime)),
		bytesPointer(statement.SerialBlocklist), C.size_t(len(statement.SerialBlocklist)),
		C.size_t(statement.ActiveSerials),
		bytesPointer(quote), C.size_t(len(quote)),
		(*C.uint8_t)(unsafe.Pointer(&r[0])), (*C.uint8_t)(unsafe.Pointer(&s[0])),
		bytesPointer(certificateDER), C.size_t(len(certificateDER)),
		&proof, &proofLen,
	)
	if rc != C.TPM2_QUOTE_PROVER_SUCCESS {
		return nil, fmt.Errorf("GCP TPM prover failed with error code %d", rc)
	}
	defer C.free(unsafe.Pointer(proof))
	return C.GoBytes(unsafe.Pointer(proof), C.int(proofLen)), nil
}

func Verify(circuit []byte, statement Statement, proof []byte) error {
	if err := validate(circuit, statement, proof, nil); err != nil {
		return err
	}
	spec, err := specFor(statement.Version)
	if err != nil {
		return err
	}
	rc := C.run_gcp_tpm2_quote_verifier(
		spec,
		bytesPointer(circuit), C.size_t(len(circuit)),
		bytesPointer(statement.Nonce), C.size_t(len(statement.Nonce)),
		(*C.uint8_t)(unsafe.Pointer(&statement.MinFirmware[0])),
		(*C.uint8_t)(unsafe.Pointer(&statement.PCRHash[0])),
		bytesPointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		bytesPointer(statement.VerificationTime), C.size_t(len(statement.VerificationTime)),
		bytesPointer(statement.SerialBlocklist), C.size_t(len(statement.SerialBlocklist)),
		C.size_t(statement.ActiveSerials),
		bytesPointer(proof), C.size_t(len(proof)),
	)
	if rc != C.TPM2_QUOTE_VERIFIER_SUCCESS {
		return fmt.Errorf("GCP TPM verifier failed with error code %d", rc)
	}
	return nil
}

func specFor(version int) (*C.Tpm2QuoteZkSpecStruct, error) {
	if version != 6 && version != 7 {
		return nil, fmt.Errorf("unsupported GCP TPM spec version %d", version)
	}
	spec := C.find_gcp_tpm2_zk_spec(C.size_t(version))
	if spec == nil {
		return nil, fmt.Errorf("GCP TPM spec version %d is unavailable", version)
	}
	return spec, nil
}

func validate(circuit []byte, statement Statement, variableInput, certificateDER []byte) error {
	if len(circuit) == 0 || len(variableInput) == 0 {
		return fmt.Errorf("circuit and proof or quote must not be empty")
	}
	if len(statement.Nonce) == 0 || len(statement.Nonce) > 32 {
		return fmt.Errorf("nonce must contain 1 to 32 bytes")
	}
	if len(statement.IssuerSPKI) == 0 || len(statement.VerificationTime) != VerificationTimeSize {
		return fmt.Errorf("issuer SPKI and a %d-byte verification time are required", VerificationTimeSize)
	}
	if len(statement.SerialBlocklist) != SerialBlocklistCapacity*SerialSize || statement.ActiveSerials < 0 || statement.ActiveSerials > SerialBlocklistCapacity {
		return fmt.Errorf("serial blocklist must contain %d entries", SerialBlocklistCapacity)
	}
	if certificateDER != nil && len(certificateDER) == 0 {
		return fmt.Errorf("AK certificate is empty")
	}
	return nil
}

func bytesPointer(value []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&value[0])) }
