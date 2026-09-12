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

package libsevsnp

/*
#cgo CFLAGS: -I${SRCDIR}/../../../libraries/longfellow-zk-2/lib
#cgo pkg-config: openssl libzstd
#cgo LDFLAGS: -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/sev_quote -lsev_quote_static -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/x509 -lx509_native
#cgo linux LDFLAGS: -lstdc++ -lm
#cgo darwin LDFLAGS: -lc++ -lm

#include "circuits/sev_quote/sev_quote_zk.h"
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
	IssuerSPKISize          = 550
	VerificationTimeSize    = 15
)

type Statement struct {
	Version          int
	MinGuestSVN      [4]byte
	Policy           [8]byte
	FamilyID         [16]byte
	ImageID          [16]byte
	VMPL             uint32
	MinCurrentTCB    [8]byte
	PlatformInfo     [8]byte
	Nonce            [64]byte
	Measurement      [48]byte
	HostData         [32]byte
	IDKeyDigest      [48]byte
	AuthorKeyDigest  [48]byte
	ReportID         [32]byte
	ReportIDMA       [32]byte
	MinBootloaderSVN byte
	MinTEESVN        byte
	MinSNPSVN        byte
	MinMicrocodeSVN  byte
	MinCommittedTCB  [8]byte
	MinLaunchTCB     [8]byte
	IssuerSPKI       []byte
	VerificationTime []byte
	SerialBlocklist  []byte
	ActiveSerials    int
}

func GenerateCircuit(version int) ([]byte, error) {
	spec, err := specFor(version)
	if err != nil {
		return nil, err
	}
	var output *C.uint8_t
	var outputLen C.size_t
	if rc := C.generate_sev_circuit(spec, &output, &outputLen); rc != C.SEV_QUOTE_CIRCUIT_GENERATION_SUCCESS {
		return nil, fmt.Errorf("generating SEV-SNP circuit failed with error code %d", rc)
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
	if rc := C.sev_circuit_id((*C.uint8_t)(unsafe.Pointer(&id[0])), pointer(circuit), C.size_t(len(circuit)), spec); rc != 1 {
		return [32]byte{}, fmt.Errorf("computing SEV-SNP circuit ID failed with error code %d", rc)
	}
	return id, nil
}

func Prove(circuit []byte, statement Statement, quote []byte) ([]byte, error) {
	if err := validate(circuit, statement, quote); err != nil {
		return nil, err
	}
	spec, err := specFor(statement.Version)
	if err != nil {
		return nil, err
	}
	var proof *C.uint8_t
	var proofLen C.size_t
	rc := C.run_milan_sev_quote_prover(
		spec, pointer(circuit), C.size_t(len(circuit)),
		array4(&statement.MinGuestSVN), array8(&statement.Policy), array16(&statement.FamilyID), array16(&statement.ImageID), C.uint32_t(statement.VMPL),
		array8(&statement.MinCurrentTCB), array8(&statement.PlatformInfo), array64(&statement.Nonce), array48(&statement.Measurement), array32(&statement.HostData),
		array48(&statement.IDKeyDigest), array48(&statement.AuthorKeyDigest), array32(&statement.ReportID), array32(&statement.ReportIDMA),
		C.uint8_t(statement.MinBootloaderSVN), C.uint8_t(statement.MinTEESVN), C.uint8_t(statement.MinSNPSVN), C.uint8_t(statement.MinMicrocodeSVN),
		array8(&statement.MinCommittedTCB), array8(&statement.MinLaunchTCB), pointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		pointer(statement.VerificationTime), C.size_t(len(statement.VerificationTime)), pointer(statement.SerialBlocklist), C.size_t(len(statement.SerialBlocklist)), C.size_t(statement.ActiveSerials),
		pointer(quote), C.size_t(len(quote)), &proof, &proofLen,
	)
	if rc != C.SEV_QUOTE_PROVER_SUCCESS {
		return nil, fmt.Errorf("SEV-SNP prover failed with error code %d", rc)
	}
	defer C.free(unsafe.Pointer(proof))
	return C.GoBytes(unsafe.Pointer(proof), C.int(proofLen)), nil
}

func Verify(circuit []byte, statement Statement, proof []byte) error {
	if err := validate(circuit, statement, proof); err != nil {
		return err
	}
	spec, err := specFor(statement.Version)
	if err != nil {
		return err
	}
	rc := C.run_milan_sev_quote_verifier(
		spec, pointer(circuit), C.size_t(len(circuit)),
		array4(&statement.MinGuestSVN), array8(&statement.Policy), array16(&statement.FamilyID), array16(&statement.ImageID), C.uint32_t(statement.VMPL),
		array8(&statement.MinCurrentTCB), array8(&statement.PlatformInfo), array64(&statement.Nonce), array48(&statement.Measurement), array32(&statement.HostData),
		array48(&statement.IDKeyDigest), array48(&statement.AuthorKeyDigest), array32(&statement.ReportID), array32(&statement.ReportIDMA),
		C.uint8_t(statement.MinBootloaderSVN), C.uint8_t(statement.MinTEESVN), C.uint8_t(statement.MinSNPSVN), C.uint8_t(statement.MinMicrocodeSVN),
		array8(&statement.MinCommittedTCB), array8(&statement.MinLaunchTCB), pointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		pointer(statement.VerificationTime), C.size_t(len(statement.VerificationTime)), pointer(statement.SerialBlocklist), C.size_t(len(statement.SerialBlocklist)), C.size_t(statement.ActiveSerials),
		pointer(proof), C.size_t(len(proof)),
	)
	if rc != C.SEV_QUOTE_VERIFIER_SUCCESS {
		return fmt.Errorf("SEV-SNP verifier failed with error code %d", rc)
	}
	return nil
}

func specFor(version int) (*C.SevQuoteZkSpecStruct, error) {
	if version != 6 && version != 7 {
		return nil, fmt.Errorf("unsupported SEV-SNP spec version %d", version)
	}
	spec := C.find_sev_quote_zk_spec(C.size_t(version))
	if spec == nil {
		return nil, fmt.Errorf("SEV-SNP spec version %d is unavailable", version)
	}
	return spec, nil
}

func validate(circuit []byte, statement Statement, variableInput []byte) error {
	if len(circuit) == 0 || len(variableInput) == 0 {
		return fmt.Errorf("circuit and proof or report must not be empty")
	}
	if len(statement.IssuerSPKI) != IssuerSPKISize || len(statement.VerificationTime) != VerificationTimeSize {
		return fmt.Errorf("SEV-SNP statement has invalid issuer SPKI or verification time length")
	}
	if len(statement.SerialBlocklist) != SerialBlocklistCapacity*SerialSize || statement.ActiveSerials < 0 || statement.ActiveSerials > SerialBlocklistCapacity {
		return fmt.Errorf("serial blocklist must contain %d entries", SerialBlocklistCapacity)
	}
	return nil
}

func pointer(value []byte) *C.uint8_t    { return (*C.uint8_t)(unsafe.Pointer(&value[0])) }
func array4(value *[4]byte) *C.uint8_t   { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array8(value *[8]byte) *C.uint8_t   { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array16(value *[16]byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array32(value *[32]byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array48(value *[48]byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array64(value *[64]byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(value)) }
