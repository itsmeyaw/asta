# Herta Longfellow Circuit CLI Plan

## Goal

Deliver `herta` commands for Longfellow GCP TPM2, Intel TDX Quote v4, and AMD
Milan SEV-SNP proof generation and verification, with optional prover-side
requirements checks and mandatory verifier-side issuer-to-root and CRL
validation.

Do not add live TDX or SNP collection commands. Existing collection scripts
remain the hardware boundary; the CLI consumes their raw artifacts.

## Security Model

- The verifier owns the policy, trusted root, issuer certificate, and CRL
  collateral. Leaf CRL collateral is optional when the vendor does not publish
  it; an absent leaf CRL binds an empty leaf serial denylist into the proof.
- TDX and SNP provers may run `--check-requirements` before expensive proof
  generation. TPM proof generation always validates its policy-bound inputs.
- The proof carries only circuit public inputs, including the issuer SPKI,
  verification time, and leaf denylist. It does not carry roots, issuer
  certificates, or CRLs.
- Verification derives the issuer SPKI from verifier-owned collateral and
  rejects a proof unless it exactly matches the statement bound by the circuit.
- No network access occurs during `prove`, `verify`, or requirements checking.
  Collateral is refreshed separately into immutable local snapshots.

## CLI

```text
herta collateral refresh gcp     --ak-cert ak.der --trust-root google-root.der --output collateral/
herta collateral refresh tdx     --quote quote.bin --trust-root intel-root.der --output collateral/
herta collateral refresh sev-snp --report report.bin --trust-root ark.der --output collateral/

herta tpm prove quote --quote-input quote.bin --signature-input quote.sig \
  --certificate-input ak.der --policy gcp-policy.json \
  --circuit gcp.circuit --output proof.json
herta tpm verify quote --input proof.json --policy gcp-policy.json --circuit gcp.circuit

herta tdx prove quote --input tdx-quote.bin --policy tdx-policy.json \
  --check-requirements --circuit tdx.circuit --output proof.json
herta tdx verify quote --input proof.json --policy tdx-policy.json --circuit tdx.circuit

herta sev-snp prove report --report report.bin --vcek vcek.der \
  --policy sev-policy.json --check-requirements \
  --circuit sev.circuit --output proof.json
herta sev-snp verify report --input proof.json --policy sev-policy.json --circuit sev.circuit
```

Each platform also gets `circuit generate <output>`. An omitted `--circuit`
retains on-demand generation, but pre-generated circuits remain the practical
path.

## Policy And Collateral

Use one versioned JSON policy per platform:

```json
{
  "profile": "intel-tdx-quote-v4-pck-issuer-v3",
  "spec_version": 6,
  "verification_time": "20260910165629Z",
  "requirements": {
    "minimum_tcb_svn": "hex",
    "mr_td": "hex",
    "rtmr2_candidates": ["hex"],
    "rtmr3_candidates": ["hex"]
  },
  "collateral": {
    "issuer_certificate": "collateral/pck-platform-ca.der",
    "trusted_root": "collateral/intel-sgx-root.der",
    "issuer_crl": "collateral/intel-root-ca.crl",
    "leaf_crl": "collateral/pck-platform-ca.crl"
  }
}
```

The exact requirement fields follow each existing Longfellow C ABI. File paths
stay local; the canonical public statement stored in a proof contains only byte
values passed to the circuit.

`collateral refresh` creates a bundle manifest containing source URL, retrieval
timestamp, SHA-256 hash, certificate and CRL validity period, and issuer and
subject identities. Refresh sources are fixed vendor endpoints only.

| Platform | Issuer chain | Leaf-revocation source |
| --- | --- | --- |
| GCP TPM | Google EK/AK intermediate to verifier-pinned Google root | No AK leaf CRL is advertised by the current artifacts |
| Intel TDX | PCK Platform CA to verifier-pinned Intel SGX root | Intel Platform CA CRL |
| AMD SNP | Milan ASK to verifier-pinned ARK-Milan | No VCEK leaf CRL is advertised by the current artifacts |

GCP issuer material comes from the AK certificate AIA when present, otherwise a
verifier-provisioned bundle. Intel extracts the PCK chain from the quote. AMD
retrieves VCEK, ASK, and ARK collateral from AMD KDS during explicit refresh.

Do not reuse the hardcoded Intel subscription key in
`scripts/get-platform-cert.sh`; it should be revoked and replaced by an
environment-provided credential if PCS access is needed.

## TDX And SNP Requirements Check

`--check-requirements` runs before circuit loading or generation for TDX and
SNP:

1. Parse raw quote or report and certificate inputs with strict fixed-profile
   bounds.
2. Validate nonce, measurements, attributes, TCB or SVN minima, allowlists,
   and denylist membership.
3. Validate issuer certificate to the pinned root at `verification_time`.
4. Validate CRL issuer signature, time range, and issuer serial revocation.
5. Build the canonical public statement and compare it to the requested policy.
6. Exit on the first mismatch without calling Longfellow.

This is a performance optimization only. The verifier repeats trust validation
and the circuit verifies the proof.

## CRL Handling

Two CRLs have distinct purposes:

| CRL | Native check | Circuit input |
| --- | --- | --- |
| Root-issued issuer CRL | Rejects a revoked GCP intermediate, PCK Platform CA, or Milan ASK | None |
| Issuer-issued leaf CRL | Rejects or identifies revoked AK, PCK, or VCEK leaves | Canonical leaf serial denylist |

For GCP TPM and TDX, each leaf serial is positive, at most 20 bytes,
right-aligned to 20 bytes, deduplicated, padded with zero entries, and paired
with an active count.

Current CRL measurements, taken 2026-09-10 UTC:

| Platform | Leaf CRL | Bytes | Revoked entries |
| --- | --- | ---: | ---: |
| GCP TPM | Not advertised | N/A | N/A |
| Intel TDX | Platform CA CRL | 3,355 | 57 |
| AMD SNP | Not advertised | N/A | N/A |

The current TDX circuit limit of 16 is insufficient. Raise the TDX leaf serial
capacity to 64 and fail closed if a future CRL has more entries. Add a
`ponytail:` comment documenting that 64 is a bounded operational ceiling and
that a capacity and profile upgrade is required on overflow.

The current SNP circuit accepts VCEK certificate fingerprints, not serials.
Extend it with a bounded 20-byte serial denylist and active count. Keep the
fingerprint denylist only if its separate emergency-revocation value is wanted;
otherwise replace it rather than maintaining two equivalent denylist mechanisms.

## Native Validation

Use only Go standard library packages for policy, certificates, CRLs, hashes,
HTTP refresh, and time handling.

- `crypto/x509` validates the immediate issuer to the pinned root at the
  statement verification time.
- `x509.ParseRevocationList`, `CheckSignatureFrom`, `ThisUpdate`, `NextUpdate`,
  and serial comparison validate CRLs.
- Platform-specific checks enforce the expected subject and issuer, key
  algorithm and size, CA and key-usage constraints, and certificate profile.
- Native validation derives the canonical issuer SPKI. Policy-supplied SPKI is
  never accepted without this derivation.
- The initial implementation validates the direct issuer-to-root chains used by
  all three supported profiles. Add a general intermediate-chain builder only
  if a supported profile actually gains another CA.

## Longfellow Changes

| Circuit | Required change |
| --- | --- |
| GCP TPM2 | No statement change for leaf CRLs; use existing 16-entry serial ABI. Replace Herta's obsolete generic TPM binding with `generate_gcp_tpm2_circuit`, `run_gcp_tpm2_quote_prover`, and `run_gcp_tpm2_quote_verifier`. |
| Intel TDX | Raise serial-blocklist capacity 16 to 64 in the spec, witness validation, public C header, circuit generator, circuit ID, and tests. Publish a new profile and identifier. |
| AMD SNP | Add the leaf serial-blocklist public inputs and membership circuit checks. Update C ABI, witness parsing, statement binding, generator, circuit ID, and tests. |

Generated circuit IDs must change for TDX and SNP. Proof envelopes include
profile, spec version, and computed circuit ID. Verification recomputes the ID
and rejects any mismatch.

## Go/Cgo Integration

- Replace the stale hand-copied TPM header and generic wrapper in
   `herta/cmd/libtpm2`; it no longer matches `longfellow-zk-2`.
- Add separate `cmd/libtdx` and `cmd/libsevsnp` cgo packages. Separate packages
  prevent conflicts from generic C symbols and constants in the circuit headers.
- Validate all slice lengths before obtaining cgo pointers. Empty buffers and
  wrong fixed-width fields fail in Go.
- Keep cgo wrappers thin: spec lookup, circuit generation and ID, prover,
  verifier, C-allocated result copying, and `C.free`.
- Build all three static Longfellow targets into one ignored
  `libraries/longfellow-zk-2/build-asta/` directory. Update cgo linker paths to
  that stable local output, not the absent `clang-build-release` path.
- Link no new Go dependencies.

## Implementation Order

1. Add shared policy, proof-envelope, collateral-manifest, X.509, CRL, and
    canonical-serial code in `herta/cmd`.
2. Add `collateral refresh` with vendor allowlists, root pinning, CRL snapshot
   storage, and no silent fallback when required collateral is unavailable.
3. Update the GCP TPM cgo wrapper and migrate `cmd/tpm/quote.go` to the current
   GCP ABI and policy and proof format.
4. Add TDX raw quote parsing, requirements checks, cgo wrapper, Cobra commands,
   and circuit generate, prove, and verify flows.
5. Add SNP report and VCEK parsing, requirements checks, cgo wrapper, Cobra
   commands, and circuit generate, prove, and verify flows.
6. Update the TDX circuit to 64 serials and publish the new circuit profile.
7. Update the SNP circuit for serial CRL denylist enforcement and publish the
   new circuit profile.
8. Add CLI help, sample policies, build instructions, and fixture provenance
   without committing generated circuits, proofs, credentials, or refreshed
   collateral.

## Verification

- Run Longfellow C++ tests after each circuit change, including new CRL capacity
  and blocked-leaf cases.
- Add Go tests for fixed-width parsing, policy statement serialization, CRL
  signature and time checks, serial canonicalization, overflow rejection, and
  issuer-SPKI mismatch.
- Test TDX and SNP `--check-requirements` rejects each altered policy field
  before invoking cgo.
- Test proof verification rejects mismatched policy, root, issuer, CRL, circuit
  ID, nonce, and leaf blocklist.
- Independently validate positive chains and signatures with OpenSSL as the
  external oracle.
- Obtain a coherent GCP AK certificate, quote, and signature fixture before
  claiming TPM end-to-end proof coverage; the existing Longfellow TPM fixture is
  not coherent.
- Run `go test ./...`, build the CLI with all three static libraries, then run
  fixture-backed prove and verify smoke tests for TDX and SNP.

## Leaf Revocation Policy

Leaf CRLs are optional for vendors that do not publish them. The verifier still
validates the issuer-to-root chain and the root-issued issuer CRL, but cannot
enforce revocation of individual leaves until suitable vendor collateral is
available.
