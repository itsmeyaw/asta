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

func TestQuoteCommandFlags(t *testing.T) {
	if proveQuoteCmd.Flags().Lookup("quote") == nil || proveQuoteCmd.Flags().Lookup("input") != nil {
		t.Fatal("prove quote must use --quote, not --input")
	}
	if output := proveQuoteCmd.Flags().Lookup("output"); output == nil || output.Shorthand != "o" || output.DefValue != "proof.json" {
		t.Fatal("prove quote must expose --output/-o with proof.json default")
	}
	if input := verifyQuoteCmd.Flags().Lookup("input"); input == nil || input.Shorthand != "i" {
		t.Fatal("verify quote must expose --input with -i")
	}
}

func TestCollateralRefreshCommand(t *testing.T) {
	if collateralCmd.Commands()[0].Name() != "refresh" {
		t.Fatal("TDX collateral must expose refresh")
	}
	for _, name := range []string{"quote", "trust-root", "output"} {
		if refreshCollateralCmd.Flags().Lookup(name) == nil {
			t.Fatalf("collateral refresh is missing --%s", name)
		}
	}
}
