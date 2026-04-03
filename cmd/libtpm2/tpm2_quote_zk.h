// Copyright 2026 Yudhistira Arief Wibowo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TPM2_QUOTE_TPM2_QUOTE_ZK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TPM2_QUOTE_TPM2_QUOTE_ZK_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    const size_t kLigeroRate = 4;
    const size_t kLigeroNreq = 128; // 86+ bits statistical security

    const size_t kLigeroRatev7 = 7;
    const size_t kLigeroNreqv7 = 132; // ~109 bits statistical security

    typedef enum
    {
        TPM2_QUOTE_PROVER_SUCCESS = 0,
        TPM2_QUOTE_PROVER_NULL_INPUT,
        TPM2_QUOTE_PROVER_INVALID_INPUT,
        TPM2_QUOTE_PROVER_ERROR_INVALID_NONCE_LENGTH,
        TPM2_QUOTE_PROVER_CIRCUIT_PARSING_FAILURE,
        TPM2_QUOTE_PROVER_HASH_PARSING_FAILURE,
        TPM2_QUOTE_PROVER_WITNESS_CREATION_FAILURE,
        TPM2_QUOTE_PROVER_SIGNATURE_FAILURE,
        TPM2_QUOTE_PROVER_GENERAL_FAILURE,
        TPM2_QUOTE_PROVER_MEMORY_ALLOCATION_FAILURE,
    } Tpm2ProverErrorCode;

    typedef enum
    {
        TPM2_QUOTE_VERIFIER_SUCCESS = 0,
        TPM2_QUOTE_VERIFIER_CIRCUIT_PARSING_FAILURE,
        TPM2_QUOTE_VERIFIER_PROOF_TOO_SMALL,
        TPM2_QUOTE_VERIFIER_ERROR_INVALID_NONCE_LENGTH,
        TPM2_QUOTE_VERIFIER_HASH_PARSING_FAILURE,
        TPM2_QUOTE_VERIFIER_SIGNATURE_PARSING_FAILURE,
        TPM2_QUOTE_VERIFIER_GENERAL_FAILURE,
        TPM2_QUOTE_VERIFIER_NULL_INPUT,
        TPM2_QUOTE_VERIFIER_INVALID_INPUT,
        TPM2_QUOTE_VERIFIER_ARGUMENTS_TOO_SMALL,
        TPM2_QUOTE_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH,
    } Tpm2VerifierErrorCode;

    typedef enum
    {
        TPM2_QUOTE_CIRCUIT_GENERATION_SUCCESS = 0,
        TPM2_QUOTE_CIRCUIT_GENERATION_NULL_INPUT,
        TPM2_QUOTE_CIRCUIT_GENERATION_ZLIB_FAILURE,
        TPM2_QUOTE_CIRCUIT_GENERATION_GENERAL_FAILURE,
        TPM2_QUOTE_CIRCUIT_GENERATION_INVALID_ZK_SPEC_VERSION,
    } Tpm2CircuitGenerationErrorCode;

    // Taken from MDOC code
    // An upper-bound on the decompressed circuit size. It is better to make this
    // bound tight to avoid memory failure in the resource restricted Android
    // gmscore environment.
    static const size_t kCircuitSizeMax = 150000000;

    // This structure represents a version of ZK specification supported by this
    // library. It is passed into all the methods for circuit generation, running
    // the prover and verifier.
    // It allows us to version the specification of the ZK system. The prover and
    // the verifier are supposed to negotiate the version of the specification they
    // both support before executing digital credential presentment.
    typedef struct
    {
        // The ZK system name and version- "longfellow-libzk-v*" for Google library.
        const char *system;
        // The hash of the compressed circuit (the way it's generated and passed to
        // prover/verifier)
        const char circuit_hash[65];
        // The version of the ZK specification.
        size_t version;
        // The block_enc parameter for the ZK proof.
        size_t block_enc;
    } ZkSpecStruct;

    extern const ZkSpecStruct zk_spec;

    Tpm2CircuitGenerationErrorCode generate_circuit(uint8_t **cb, size_t *clen);

    int circuit_id(uint8_t id[/*kSHA256DigestSize*/], const uint8_t *bcp,
                   size_t bcsz, const ZkSpecStruct *zk_spec);

    Tpm2ProverErrorCode run_tpm2_quote_prover(
        bool usev7, const uint8_t *bcp, size_t bcsz,
        const uint8_t r[32], const uint8_t s[32],
        const uint8_t nonce[], size_t nonce_len,
        const uint8_t minimumFirmwareVersion[8],
        const uint8_t expectedPcrHash[32], const char *pkx, const char *pky,
        const uint8_t quote[], size_t quote_len,
        uint8_t commitment[32],
        uint8_t **proof_out,
        size_t *proof_len);

    Tpm2VerifierErrorCode run_tpm2_quote_verifier(
        bool usev7, const uint8_t *bcp, size_t bcsz,
        const uint8_t nonce[], size_t nonce_len,
        const uint8_t minimumFirmwareVersion[8],
        const uint8_t expectedPcrHash[32],
        uint8_t **proof_out,
        size_t *proof_len);

#ifdef __cplusplus
}
#endif

#endif // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TPM2_QUOTE_TPM2_QUOTE_ZK_H_
