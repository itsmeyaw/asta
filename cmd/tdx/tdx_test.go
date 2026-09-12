package tdx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPCKCertificateAcceptsLeafOnlyQuoteChain(t *testing.T) {
	quote, err := os.ReadFile(filepath.Join("..", "..", "..", "libraries", "longfellow-zk-2", "lib", "circuits", "tdx_quote", "test_files", "tdx_quote.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pckCertificate(quote); err != nil {
		t.Fatalf("pckCertificate rejected fixture with leaf-only PCK chain: %v", err)
	}
}
