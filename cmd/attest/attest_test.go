package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateTrustBuildsCanonicalBlocklist(t *testing.T) {
	fixed := time.Date(2026, time.September, 10, 17, 0, 0, 0, time.UTC)
	root, rootKey := testCertificate(t, nil, nil, 1, true, fixed)
	issuer, issuerKey := testCertificate(t, root, rootKey, 2, true, fixed)
	leaf, _ := testCertificate(t, issuer, issuerKey, 3, false, fixed)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("issuer.der", issuer.Raw)
	write("root.der", root.Raw)
	write("issuer.crl", testCRL(t, root, rootKey, nil, fixed))
	write("leaf.crl", testCRL(t, issuer, issuerKey, []int64{99, 5}, fixed))
	policyData, err := json.Marshal(Policy{
		Profile:          "test",
		SpecVersion:      6,
		VerificationTime: fixed.Format(VerificationTimeLayout),
		Collateral: Collateral{
			IssuerCertificate: "issuer.der",
			TrustedRoot:       "root.der",
			IssuerCRL:         "issuer.crl",
			LeafCRL:           "leaf.crl",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policyPath := write("policy.json", policyData)
	policy, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := ValidateTrust(policy, leaf, 2)
	if err != nil {
		t.Fatal(err)
	}
	if trust.ActiveBlocklistSize != 2 || len(trust.SerialBlocklist) != 40 {
		t.Fatalf("unexpected blocklist shape: active=%d bytes=%d", trust.ActiveBlocklistSize, len(trust.SerialBlocklist))
	}
	if got := trust.SerialBlocklist[19]; got != 5 {
		t.Fatalf("serials are not canonical and sorted: got first byte %d", got)
	}
}

func TestValidateTrustAllowsSNPMissingLeafCRL(t *testing.T) {
	fixed := time.Date(2026, time.September, 10, 17, 0, 0, 0, time.UTC)
	root, rootKey := testCertificate(t, nil, nil, 1, true, fixed)
	issuer, issuerKey := testCertificate(t, root, rootKey, 2, true, fixed)
	leaf, _ := testCertificate(t, issuer, issuerKey, 3, false, fixed)
	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.der")
	rootPath := filepath.Join(dir, "root.der")
	crlPath := filepath.Join(dir, "issuer.crl")
	for path, data := range map[string][]byte{issuerPath: issuer.Raw, rootPath: root.Raw, crlPath: testCRL(t, root, rootKey, nil, fixed)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	trust, err := ValidateTrust(Policy{
		Profile:          "longfellow-sev-snp-milan-vcek-v4",
		SpecVersion:      6,
		VerificationTime: fixed.Format(VerificationTimeLayout),
		Collateral:       Collateral{IssuerCertificate: issuerPath, TrustedRoot: rootPath, IssuerCRL: crlPath},
	}, leaf, 16)
	if err != nil {
		t.Fatal(err)
	}
	if trust.ActiveBlocklistSize != 0 || len(trust.SerialBlocklist) != 320 {
		t.Fatalf("unexpected empty SNP blocklist: active=%d bytes=%d", trust.ActiveBlocklistSize, len(trust.SerialBlocklist))
	}
}

func TestVerifyAtAllowsAttestationKeyUsage(t *testing.T) {
	fixed := time.Date(2026, time.September, 10, 17, 0, 0, 0, time.UTC)
	root, rootKey := testCertificate(t, nil, nil, 1, true, fixed, x509.ExtKeyUsageEmailProtection)
	issuer, issuerKey := testCertificate(t, root, rootKey, 2, true, fixed)
	leaf, _ := testCertificate(t, issuer, issuerKey, 3, false, fixed)
	if err := verifyAt(leaf, issuer, root, fixed); err != nil {
		t.Fatalf("verifyAt rejected a non-TLS attestation chain: %v", err)
	}
}

func testCertificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, serial int64, ca bool, now time.Time, usages ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testCRL(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, serials []int64, now time.Time) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, len(serials))
	for i, serial := range serials {
		entries[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: now}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(time.Minute),
		RevokedCertificateEntries: entries,
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
