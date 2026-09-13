# TPM benchmark fixture blocker

The checked-in GCP AK certificate and chain are valid, but neither checked-in
raw signature verifies `quote.bin`. A coherent replacement fixture is in
`gcp/tpm-benchmark-20260914/`. Its AK certificate advertises no leaf CRL
endpoint; Herta therefore binds an empty leaf serial denylist while continuing
to validate the issuer CRL.

Do not report TPM prove/verify timings until the replacement fixture is
integrated and the Longfellow circuit/spec-ID mismatch is resolved.
