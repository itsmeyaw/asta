# TDX benchmark fixture

`quote.bin` is the Longfellow Quote v4 fixture. The pinned Intel root is the
root embedded in that quote. `issuer.crl` and `leaf.crl` were retrieved by
`herta tdx collateral refresh` on 2026-09-13 and are archived by `manifest.json`.

The policy time is 2026-09-13 16:00:00 UTC. It is inside the certificate and
both CRL validity periods. The 57 leaf-CRL serials fit the v3 profile's
64-entry blocklist and are used by both direct Longfellow and Herta runs.
