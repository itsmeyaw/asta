# TPM benchmark fixture blocker

The GCP AK certificate and chain are valid, but neither checked-in raw
signature verifies `quote.bin`. In addition, the AK certificate advertises no
leaf CRL endpoint while the current Herta TPM profile requires a leaf CRL.

Do not create `policy.json` or report TPM prove/verify timings until a coherent
quote/signature from this certified AK and an explicit verifier revocation
policy are available.
