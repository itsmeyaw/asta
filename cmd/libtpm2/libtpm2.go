/*
Copyright 2026 Yudhistira Arief Wibowo

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
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}/../../../libraries/longfellow-zk/clang-build-release/circuits/tpm2_quote -ltpm2_quote_static -lzstd -lcrypto
#cgo linux CFLAGS: -I/usr/local/include
#cgo linux LDFLAGS: -L/usr/local/lib -lstdc++ -lm
#cgo darwin CFLAGS: -I/opt/homebrew/include
#cgo darwin LDFLAGS: -L/opt/homebrew/lib -lc++ -lm

#include "tpm2_quote_zk.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type ProverResult struct {
	Commitment [32]byte
	Proof      []byte
}

func GenerateCircuit() ([]byte, error) {
	var cb *C.uint8_t
	var clen C.size_t

	rc := C.generate_circuit(&cb, &clen)
	if rc != C.TPM2_QUOTE_CIRCUIT_GENERATION_SUCCESS {
		return nil, fmt.Errorf("generate_circuit failed with error code %d", int(rc))
	}
	defer C.free(unsafe.Pointer(cb))

	return C.GoBytes(unsafe.Pointer(cb), C.int(clen)), nil
}

func CircuitID(compressedCircuit []byte) ([32]byte, error) {
	var id [32]byte

	rc := C.circuit_id(
		(*C.uint8_t)(unsafe.Pointer(&id[0])),
		(*C.uint8_t)(unsafe.Pointer(&compressedCircuit[0])),
		C.size_t(len(compressedCircuit)),
		&C.zk_spec,
	)
	if rc != 0 {
		return id, fmt.Errorf("circuit_id failed with error code %d", rc)
	}

	return id, nil
}

// RunProver runs the ZKP prover for a TPM2 quote.
//
// Parameters:
//   - useV7: use Ligero v7 (higher security: ~109 bits vs ~86 bits)
//   - compressedCircuit: compressed circuit bytes from GenerateCircuit
//   - sigR, sigS: 32-byte ECDSA signature components
//   - nonce: nonce used in the TPM quote (max 32 bytes)
//   - minFirmwareVersion: 8-byte minimum firmware version
//   - expectedPCRHash: 32-byte SHA-256 hash of expected PCR values
//   - pkX, pkY: AK public key coordinates as decimal or hex strings
//   - quote: raw TPM quote bytes (TPMS_ATTEST)
func RunProver(
	useV7 bool,
	compressedCircuit []byte,
	sigR [32]byte,
	sigS [32]byte,
	nonce []byte,
	minFirmwareVersion [8]byte,
	expectedPCRHash [32]byte,
	pkX string,
	pkY string,
	quote []byte,
) (*ProverResult, error) {
	cPkx := C.CString(pkX)
	defer C.free(unsafe.Pointer(cPkx))
	cPky := C.CString(pkY)
	defer C.free(unsafe.Pointer(cPky))

	var commitment [32]byte
	var proofOut *C.uint8_t
	var proofLen C.size_t

	rc := C.run_tpm2_quote_prover(
		C.bool(useV7),
		(*C.uint8_t)(unsafe.Pointer(&compressedCircuit[0])),
		C.size_t(len(compressedCircuit)),
		(*C.uint8_t)(unsafe.Pointer(&sigR[0])),
		(*C.uint8_t)(unsafe.Pointer(&sigS[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&minFirmwareVersion[0])),
		(*C.uint8_t)(unsafe.Pointer(&expectedPCRHash[0])),
		cPkx,
		cPky,
		(*C.uint8_t)(unsafe.Pointer(&quote[0])),
		C.size_t(len(quote)),
		(*C.uint8_t)(unsafe.Pointer(&commitment[0])),
		&proofOut,
		&proofLen,
	)

	if rc != C.TPM2_QUOTE_PROVER_SUCCESS {
		return nil, fmt.Errorf("run_tpm2_quote_prover failed: %s", proverErrorString(rc))
	}
	defer C.free(unsafe.Pointer(proofOut))

	return &ProverResult{
		Commitment: commitment,
		Proof:      C.GoBytes(unsafe.Pointer(proofOut), C.int(proofLen)),
	}, nil
}

// RunVerifier runs the ZKP verifier for a TPM2 quote proof.
//
// Parameters:
//   - useV7: must match the value used during proving
//   - compressedCircuit: compressed circuit bytes from GenerateCircuit
//   - nonce: nonce used in the TPM quote (max 32 bytes)
//   - minFirmwareVersion: 8-byte minimum firmware version
//   - expectedPCRHash: 32-byte SHA-256 hash of expected PCR values
//   - proof: proof bytes from RunProver
func RunVerifier(
	useV7 bool,
	compressedCircuit []byte,
	nonce []byte,
	minFirmwareVersion [8]byte,
	expectedPCRHash [32]byte,
	proof []byte,
) error {
	proofBuf := C.CBytes(proof)
	defer C.free(proofBuf)
	proofPtr := (*C.uint8_t)(proofBuf)
	proofLen := C.size_t(len(proof))

	rc := C.run_tpm2_quote_verifier(
		C.bool(useV7),
		(*C.uint8_t)(unsafe.Pointer(&compressedCircuit[0])),
		C.size_t(len(compressedCircuit)),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&minFirmwareVersion[0])),
		(*C.uint8_t)(unsafe.Pointer(&expectedPCRHash[0])),
		&proofPtr,
		&proofLen,
	)

	if rc != C.TPM2_QUOTE_VERIFIER_SUCCESS {
		return fmt.Errorf("run_tpm2_quote_verifier failed: %s", verifierErrorString(rc))
	}

	return nil
}

func proverErrorString(code C.Tpm2ProverErrorCode) string {
	switch code {
	case C.TPM2_QUOTE_PROVER_SUCCESS:
		return "success"
	case C.TPM2_QUOTE_PROVER_NULL_INPUT:
		return "null input"
	case C.TPM2_QUOTE_PROVER_INVALID_INPUT:
		return "invalid input"
	case C.TPM2_QUOTE_PROVER_ERROR_INVALID_NONCE_LENGTH:
		return "invalid nonce length (max 32 bytes)"
	case C.TPM2_QUOTE_PROVER_CIRCUIT_PARSING_FAILURE:
		return "circuit parsing failure"
	case C.TPM2_QUOTE_PROVER_HASH_PARSING_FAILURE:
		return "hash parsing failure"
	case C.TPM2_QUOTE_PROVER_WITNESS_CREATION_FAILURE:
		return "witness creation failure"
	case C.TPM2_QUOTE_PROVER_SIGNATURE_FAILURE:
		return "signature failure"
	case C.TPM2_QUOTE_PROVER_GENERAL_FAILURE:
		return "general failure"
	case C.TPM2_QUOTE_PROVER_MEMORY_ALLOCATION_FAILURE:
		return "memory allocation failure"
	default:
		return fmt.Sprintf("unknown error code %d", int(code))
	}
}

func verifierErrorString(code C.Tpm2VerifierErrorCode) string {
	switch code {
	case C.TPM2_QUOTE_VERIFIER_SUCCESS:
		return "success"
	case C.TPM2_QUOTE_VERIFIER_CIRCUIT_PARSING_FAILURE:
		return "circuit parsing failure"
	case C.TPM2_QUOTE_VERIFIER_PROOF_TOO_SMALL:
		return "proof too small"
	case C.TPM2_QUOTE_VERIFIER_ERROR_INVALID_NONCE_LENGTH:
		return "invalid nonce length (max 32 bytes)"
	case C.TPM2_QUOTE_VERIFIER_HASH_PARSING_FAILURE:
		return "hash parsing failure"
	case C.TPM2_QUOTE_VERIFIER_SIGNATURE_PARSING_FAILURE:
		return "signature parsing failure"
	case C.TPM2_QUOTE_VERIFIER_GENERAL_FAILURE:
		return "general failure"
	case C.TPM2_QUOTE_VERIFIER_NULL_INPUT:
		return "null input"
	case C.TPM2_QUOTE_VERIFIER_INVALID_INPUT:
		return "invalid input"
	case C.TPM2_QUOTE_VERIFIER_ARGUMENTS_TOO_SMALL:
		return "arguments too small"
	case C.TPM2_QUOTE_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH:
		return "attribute number mismatch"
	default:
		return fmt.Sprintf("unknown error code %d", int(code))
	}
}
