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

package tpm

import "testing"

func TestQuoteCommandFlags(t *testing.T) {
	for _, name := range []string{"quote", "signature", "certificate", "policy", "circuit", "output"} {
		if tpmProveQuoteCmd.Flags().Lookup(name) == nil {
			t.Fatalf("prove quote is missing --%s", name)
		}
	}
	for _, name := range []string{"quote-input", "signature-input", "certificate-input", "input"} {
		if tpmProveQuoteCmd.Flags().Lookup(name) != nil {
			t.Fatalf("prove quote still exposes --%s", name)
		}
	}
	if output := tpmProveQuoteCmd.Flags().Lookup("output"); output.Shorthand != "o" || output.DefValue != "proof.json" {
		t.Fatalf("unexpected --output contract: -%s %q", output.Shorthand, output.DefValue)
	}
	if input := tpmVerifyQuoteCmd.Flags().Lookup("input"); input == nil || input.Shorthand != "i" {
		t.Fatal("verify quote must expose --input with -i")
	}
}

func TestCollateralRefreshCommand(t *testing.T) {
	if collateralCmd.Commands()[0].Name() != "refresh" {
		t.Fatal("TPM collateral must expose refresh")
	}
	for _, name := range []string{"ak-cert", "trust-root", "output"} {
		if refreshCollateralCmd.Flags().Lookup(name) == nil {
			t.Fatalf("collateral refresh is missing --%s", name)
		}
	}
}
