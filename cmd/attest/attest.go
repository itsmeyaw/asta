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

// Package attest holds the verifier-owned policy and collateral boundary shared
// by the TPM, TDX, and SEV-SNP commands.
package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/itsmeyaw/asta/cmd/util"
)

const VerificationTimeLayout = "20060102150405Z"

type Collateral struct {
	IssuerCertificate string `json:"issuer_certificate"`
	TrustedRoot       string `json:"trusted_root"`
	IssuerCRL         string `json:"issuer_crl"`
	LeafCRL           string `json:"leaf_crl"`
}

type Policy struct {
	Profile          string          `json:"profile"`
	SpecVersion      int             `json:"spec_version"`
	VerificationTime string          `json:"verification_time"`
	Requirements     json.RawMessage `json:"requirements"`
	Collateral       Collateral      `json:"collateral"`
}

type Trust struct {
	IssuerSPKI          []byte
	VerificationTime    []byte
	SerialBlocklist     []byte
	ActiveBlocklistSize int
}

func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("reading policy: %w", err)
	}
	var policy Policy
	if err := DecodeJSON(data, &policy); err != nil {
		return Policy{}, fmt.Errorf("parsing policy: %w", err)
	}
	if policy.Profile == "" || policy.SpecVersion == 0 || policy.VerificationTime == "" {
		return Policy{}, fmt.Errorf("policy requires profile, spec_version, and verification_time")
	}
	if _, err := ParseVerificationTime(policy.VerificationTime); err != nil {
		return Policy{}, err
	}
	base := filepath.Dir(path)
	policy.Collateral.IssuerCertificate = resolvePath(base, policy.Collateral.IssuerCertificate)
	policy.Collateral.TrustedRoot = resolvePath(base, policy.Collateral.TrustedRoot)
	policy.Collateral.IssuerCRL = resolvePath(base, policy.Collateral.IssuerCRL)
	policy.Collateral.LeafCRL = resolvePath(base, policy.Collateral.LeafCRL)
	return policy, nil
}

// DecodeJSON accepts one JSON value and rejects fields outside the versioned schema.
func DecodeJSON(data []byte, value any) error {
	if err := validateJSONFields(data, reflect.TypeOf(value)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("expected one JSON value")
		}
		return err
	}
	return nil
}

func validateJSONFields(data []byte, target reflect.Type) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target.Kind() != reflect.Struct {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name, raw := range fields {
		field, ok := jsonField(target, name)
		if !ok {
			return fmt.Errorf("unknown JSON field %q", name)
		}
		if err := validateJSONFields(raw, field.Type); err != nil {
			return err
		}
	}
	return nil
}

func jsonField(target reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < target.NumField(); i++ {
		field := target.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == name {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

func ParseVerificationTime(value string) (time.Time, error) {
	parsed, err := time.Parse(VerificationTimeLayout, value)
	if err != nil || parsed.Format(VerificationTimeLayout) != value {
		return time.Time{}, fmt.Errorf("verification_time must be UTC in %s format", VerificationTimeLayout)
	}
	return parsed, nil
}

func ValidateTrust(policy Policy, leaf *x509.Certificate, capacity int) (Trust, error) {
	if leaf == nil {
		return Trust{}, fmt.Errorf("leaf certificate is required")
	}
	trust, issuer, leafCRL, err := validateCollateral(policy, capacity)
	if err != nil {
		return Trust{}, err
	}
	verifiedAt, _ := ParseVerificationTime(policy.VerificationTime)
	root, err := util.ReadCertificate(policy.Collateral.TrustedRoot)
	if err != nil {
		return Trust{}, fmt.Errorf("reading trusted root: %w", err)
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return Trust{}, fmt.Errorf("leaf certificate is not signed by configured issuer: %w", err)
	}
	if err := verifyAt(leaf, issuer, root, verifiedAt); err != nil {
		return Trust{}, err
	}
	if leafCRL != nil && serialRevoked(leafCRL, leaf.SerialNumber) {
		return Trust{}, fmt.Errorf("leaf certificate is revoked")
	}
	return trust, nil
}

// ValidateCollateral checks the verifier-owned issuer-to-root chain and CRLs.
// The circuit checks the private leaf certificate against the returned serial
// blocklist, so verification does not need the leaf certificate itself.
func ValidateCollateral(policy Policy, capacity int) (Trust, error) {
	trust, _, _, err := validateCollateral(policy, capacity)
	return trust, err
}

func validateCollateral(policy Policy, capacity int) (Trust, *x509.Certificate, *x509.RevocationList, error) {
	if capacity < 1 {
		return Trust{}, nil, nil, fmt.Errorf("serial blocklist capacity must be positive")
	}
	verifiedAt, err := ParseVerificationTime(policy.VerificationTime)
	if err != nil {
		return Trust{}, nil, nil, err
	}
	issuer, err := util.ReadCertificate(policy.Collateral.IssuerCertificate)
	if err != nil {
		return Trust{}, nil, nil, fmt.Errorf("reading issuer certificate: %w", err)
	}
	root, err := util.ReadCertificate(policy.Collateral.TrustedRoot)
	if err != nil {
		return Trust{}, nil, nil, fmt.Errorf("reading trusted root: %w", err)
	}
	if !issuer.IsCA || !root.IsCA {
		return Trust{}, nil, nil, fmt.Errorf("issuer and trusted root must be CA certificates")
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return Trust{}, nil, nil, fmt.Errorf("issuer certificate is not signed by configured root: %w", err)
	}
	if err := verifyAt(issuer, root, root, verifiedAt); err != nil {
		return Trust{}, nil, nil, err
	}
	issuerCRL, err := util.ReadCRL(policy.Collateral.IssuerCRL)
	if err != nil {
		return Trust{}, nil, nil, fmt.Errorf("reading issuer CRL: %w", err)
	}
	if err := util.ValidateCRL(issuerCRL, root, verifiedAt); err != nil {
		return Trust{}, nil, nil, fmt.Errorf("validating issuer CRL: %w", err)
	}
	if serialRevoked(issuerCRL, issuer.SerialNumber) {
		return Trust{}, nil, nil, fmt.Errorf("configured issuer certificate is revoked")
	}
	blocklist := make([]byte, capacity*20)
	active := 0
	var leafCRL *x509.RevocationList
	if policy.Collateral.LeafCRL == "" {
		if policy.Profile != "longfellow-sev-snp-milan-vcek-v4" {
			return Trust{}, nil, nil, fmt.Errorf("leaf CRL is required for profile %s", policy.Profile)
		}
	} else {
		leafCRL, err = util.ReadCRL(policy.Collateral.LeafCRL)
		if err != nil {
			return Trust{}, nil, nil, fmt.Errorf("reading leaf CRL: %w", err)
		}
		if err := util.ValidateCRL(leafCRL, issuer, verifiedAt); err != nil {
			return Trust{}, nil, nil, fmt.Errorf("validating leaf CRL: %w", err)
		}
		blocklist, active, err = serialBlocklist(leafCRL, capacity)
		if err != nil {
			return Trust{}, nil, nil, err
		}
	}
	return Trust{
		IssuerSPKI:          append([]byte(nil), issuer.RawSubjectPublicKeyInfo...),
		VerificationTime:    []byte(policy.VerificationTime),
		SerialBlocklist:     blocklist,
		ActiveBlocklistSize: active,
	}, issuer, leafCRL, nil
}

func resolvePath(base, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(base, value)
}

func verifyAt(leaf, issuer, root *x509.Certificate, verifiedAt time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verifiedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verifying issuer-to-root chain: %w", err)
	}
	return nil
}

func serialRevoked(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func serialBlocklist(crl *x509.RevocationList, capacity int) ([]byte, int, error) {
	entries := make([][20]byte, 0, len(crl.RevokedCertificateEntries))
	seen := make(map[[20]byte]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Sign() <= 0 || len(entry.SerialNumber.Bytes()) > 20 {
			return nil, 0, fmt.Errorf("revoked serial is not a positive 20-byte X.509 integer")
		}
		var canonical [20]byte
		entry.SerialNumber.FillBytes(canonical[:])
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			entries = append(entries, canonical)
		}
	}
	if len(entries) > capacity {
		return nil, 0, fmt.Errorf("leaf CRL has %d serials; circuit capacity is %d", len(entries), capacity)
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i][:], entries[j][:]) < 0 })
	blocklist := make([]byte, capacity*20)
	for i, serial := range entries {
		copy(blocklist[i*20:], serial[:])
	}
	return blocklist, len(entries), nil
}
