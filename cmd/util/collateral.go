package util

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type manifest struct {
	Platform  string            `json:"platform"`
	Retrieved string            `json:"retrieved"`
	Sources   map[string]string `json:"sources"`
	SHA256    map[string]string `json:"sha256"`
}

func Fetch(source string) ([]byte, error) {
	body, _, err := FetchWithHeaders(source)
	return body, err
}

func FetchWithHeaders(source string) ([]byte, http.Header, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, nil, fmt.Errorf("refusing non-HTTPS collateral URL %q", source)
	}
	client := http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(source)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %s: %w", source, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetching %s: status %s", source, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 10<<20))
	if err != nil {
		return nil, nil, err
	}
	return body, response.Header, nil
}

func ReadCertificate(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(raw)
}

func ParseCertificate(raw []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	return x509.ParseCertificate(raw)
}

func ReadCRL(path string) (*x509.RevocationList, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	return x509.ParseRevocationList(raw)
}

func ValidateCRL(crl *x509.RevocationList, signer *x509.Certificate, verifiedAt time.Time) error {
	if !bytes.Equal(crl.RawIssuer, signer.RawSubject) {
		return fmt.Errorf("CRL issuer does not match signer")
	}
	if err := crl.CheckSignatureFrom(signer); err != nil {
		return fmt.Errorf("checking CRL signature: %w", err)
	}
	if crl.ThisUpdate.After(verifiedAt) || crl.NextUpdate.IsZero() || verifiedAt.After(crl.NextUpdate) {
		return fmt.Errorf("CRL is not valid at verification time")
	}
	return nil
}

func WriteSnapshot(output, platform string, files map[string][]byte, sources map[string]string) error {
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("snapshot directory %q already exists", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	manifest := manifest{Platform: platform, Retrieved: time.Now().UTC().Format(time.RFC3339), Sources: sources, SHA256: map[string]string{}}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		manifest.SHA256[name] = hex.EncodeToString(sum[:])
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "manifest.json"), data, 0600)
}
