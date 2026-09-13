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

package libtdx

/*
#cgo CFLAGS: -I${SRCDIR}/../../../libraries/longfellow-zk-2/lib
#cgo pkg-config: openssl libzstd
#cgo LDFLAGS: -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/tdx_quote -ltdx_quote_static -L${SRCDIR}/../../../libraries/longfellow-zk-2/build-asta/circuits/x509 -lx509_native
#cgo linux LDFLAGS: -lstdc++ -lm
#cgo darwin LDFLAGS: -lc++ -lm

#include "circuits/tdx_quote/tdx_quote_zk.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

const (
	SerialBlocklistCapacity = 64
	SerialSize              = 20
	IssuerSPKISize          = 91
	VerificationTimeSize    = 15
)

type Statement struct {
	Version          int
	MinTCBSVN        [16]byte
	MRSEAM           [48]byte
	MRSignerSEAM     [48]byte
	SEAMAttributes   [8]byte
	TDAttributes     [8]byte
	MRTD             [48]byte
	MROwnerConfigID  [48]byte
	MROwner          [48]byte
	MROwnerConfig    [48]byte
	RTMR0            [48]byte
	RTMR1            [48]byte
	RTMR2Candidates  [][48]byte
	RTMR3Candidates  [][48]byte
	Nonce            []byte
	IssuerSPKI       []byte
	MinPCESVN        [1]byte
	MinCPUSVN        [16]byte
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
	if rc := C.generate_circuit(spec, &output, &outputLen); rc != C.TDX_QUOTE_CIRCUIT_GENERATION_SUCCESS {
		return nil, fmt.Errorf("generating TDX circuit failed with error code %d", rc)
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
	if rc := C.tdx_circuit_id((*C.uint8_t)(unsafe.Pointer(&id[0])), bytesPointer(circuit), C.size_t(len(circuit)), spec); rc != 1 {
		return [32]byte{}, fmt.Errorf("computing TDX circuit ID failed with error code %d", rc)
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
	utcTime, err := tdxVerificationTime(statement.VerificationTime)
	if err != nil {
		return nil, err
	}
	verificationTime := C.CString(utcTime)
	defer C.free(unsafe.Pointer(verificationTime))
	var proof *C.uint8_t
	var proofLen C.size_t
	rc := C.run_tdx_quote_prover(
		spec, bytesPointer(circuit), C.size_t(len(circuit)),
		array16(&statement.MinTCBSVN), array48(&statement.MRSEAM), array48(&statement.MRSignerSEAM),
		array8(&statement.SEAMAttributes), array8(&statement.TDAttributes), array48(&statement.MRTD),
		array48(&statement.MROwnerConfigID), array48(&statement.MROwner), array48(&statement.MROwnerConfig),
		array48(&statement.RTMR0), array48(&statement.RTMR1),
		candidatePointer(statement.RTMR2Candidates), C.size_t(len(statement.RTMR2Candidates)),
		candidatePointer(statement.RTMR3Candidates), C.size_t(len(statement.RTMR3Candidates)),
		bytesPointer(statement.Nonce), C.size_t(len(statement.Nonce)),
		bytesPointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		array1(&statement.MinPCESVN), array16(&statement.MinCPUSVN), verificationTime,
		serialPointer(statement.SerialBlocklist), C.size_t(statement.ActiveSerials),
		bytesPointer(quote), C.size_t(len(quote)), &proof, &proofLen,
	)
	if rc != C.TDX_QUOTE_PROVER_SUCCESS {
		return nil, fmt.Errorf("TDX prover failed with error code %d", rc)
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
	utcTime, err := tdxVerificationTime(statement.VerificationTime)
	if err != nil {
		return err
	}
	verificationTime := C.CString(utcTime)
	defer C.free(unsafe.Pointer(verificationTime))
	rc := C.run_tdx_quote_verifier(
		spec, bytesPointer(circuit), C.size_t(len(circuit)),
		array16(&statement.MinTCBSVN), array48(&statement.MRSEAM), array48(&statement.MRSignerSEAM),
		array8(&statement.SEAMAttributes), array8(&statement.TDAttributes), array48(&statement.MRTD),
		array48(&statement.MROwnerConfigID), array48(&statement.MROwner), array48(&statement.MROwnerConfig),
		array48(&statement.RTMR0), array48(&statement.RTMR1),
		candidatePointer(statement.RTMR2Candidates), C.size_t(len(statement.RTMR2Candidates)),
		candidatePointer(statement.RTMR3Candidates), C.size_t(len(statement.RTMR3Candidates)),
		bytesPointer(statement.Nonce), C.size_t(len(statement.Nonce)),
		bytesPointer(statement.IssuerSPKI), C.size_t(len(statement.IssuerSPKI)),
		array1(&statement.MinPCESVN), array16(&statement.MinCPUSVN), verificationTime,
		serialPointer(statement.SerialBlocklist), C.size_t(statement.ActiveSerials),
		bytesPointer(proof), C.size_t(len(proof)),
	)
	if rc != C.TDX_QUOTE_VERIFIER_SUCCESS {
		return fmt.Errorf("TDX verifier failed with error code %d", rc)
	}
	return nil
}

func specFor(version int) (*C.TdxQuoteZkSpecStruct, error) {
	if version != 6 && version != 7 {
		return nil, fmt.Errorf("unsupported TDX spec version %d", version)
	}
	spec := C.find_tdx_quote_zk_spec(C.size_t(version))
	if spec == nil {
		return nil, fmt.Errorf("TDX spec version %d is unavailable", version)
	}
	return spec, nil
}

func validate(circuit []byte, statement Statement, variableInput []byte) error {
	if len(circuit) == 0 || len(variableInput) == 0 {
		return fmt.Errorf("circuit and proof or quote must not be empty")
	}
	if len(statement.RTMR2Candidates) != 1 || len(statement.RTMR3Candidates) != 1 {
		return fmt.Errorf("current TDX profile requires one RTMR2 and one RTMR3 candidate")
	}
	if len(statement.Nonce) != 32 || len(statement.IssuerSPKI) != IssuerSPKISize || len(statement.VerificationTime) != VerificationTimeSize {
		return fmt.Errorf("TDX statement has invalid nonce, issuer SPKI, or verification time length")
	}
	if len(statement.SerialBlocklist) != SerialBlocklistCapacity*SerialSize || statement.ActiveSerials < 0 || statement.ActiveSerials > SerialBlocklistCapacity {
		return fmt.Errorf("serial blocklist must contain %d entries", SerialBlocklistCapacity)
	}
	return nil
}

func tdxVerificationTime(value []byte) (string, error) {
	parsed, err := time.Parse("20060102150405Z", string(value))
	if err != nil {
		return "", fmt.Errorf("invalid TDX verification time: %w", err)
	}
	if parsed.Year() < 1950 || parsed.Year() > 2049 {
		return "", fmt.Errorf("TDX verification time year %d is outside the UTCTime range 1950-2049", parsed.Year())
	}
	return parsed.Format("060102150405Z"), nil
}

func bytesPointer(value []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&value[0])) }
func array1(value *[1]byte) *C.uint8_t     { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array8(value *[8]byte) *C.uint8_t     { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array16(value *[16]byte) *C.uint8_t   { return (*C.uint8_t)(unsafe.Pointer(value)) }
func array48(value *[48]byte) *C.uint8_t   { return (*C.uint8_t)(unsafe.Pointer(value)) }
func candidatePointer(value [][48]byte) *[48]C.uint8_t {
	return (*[48]C.uint8_t)(unsafe.Pointer(&value[0]))
}

func serialPointer(value []byte) *[20]C.uint8_t { return (*[20]C.uint8_t)(unsafe.Pointer(&value[0])) }
