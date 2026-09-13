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

package sevsnp

import (
	"encoding/json"
	"testing"

	"github.com/itsmeyaw/herta/cmd/attest"
)

func TestQuoteCommandFlags(t *testing.T) {
	if proveCmd.Commands()[0].Name() != "quote" || verifyCmd.Commands()[0].Name() != "quote" {
		t.Fatal("SEV-SNP prove and verify commands must use quote")
	}
	if proveQuoteCmd.Flags().Lookup("quote") == nil || proveQuoteCmd.Flags().Lookup("report") != nil {
		t.Fatal("prove quote must use --quote, not --report")
	}
	if output := proveQuoteCmd.Flags().Lookup("output"); output == nil || output.Shorthand != "o" || output.DefValue != "proof.json" {
		t.Fatal("prove quote must expose --output/-o with proof.json default")
	}
	if input := verifyQuoteCmd.Flags().Lookup("input"); input == nil || input.Shorthand != "i" {
		t.Fatal("verify quote must expose --input with -i")
	}
}

func TestRequirementsUseSnakeCaseJSON(t *testing.T) {
	var requirements requirements
	if err := attest.DecodeJSON([]byte(`{"min_guest_svn":"01020304","min_tee_svn":2}`), &requirements); err != nil {
		t.Fatal(err)
	}
	if requirements.MinGuestSVN != "01020304" || requirements.MinTEESVN != 2 {
		t.Fatalf("unexpected requirements: %#v", requirements)
	}
	if err := attest.DecodeJSON([]byte(`{"MinGuestSVN":"01020304"}`), &requirements); err == nil {
		t.Fatal("Go-style requirements field was accepted")
	}
	encoded, err := json.Marshal(statement{IssuerSPKI: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["issuer_spki"]; !ok {
		t.Fatal("statement does not serialize issuer_spki")
	}
	if _, ok := fields["IssuerSPKI"]; ok {
		t.Fatal("statement serialized a Go-style key")
	}
}

func TestCollateralRefreshCommand(t *testing.T) {
	if collateralCmd.Commands()[0].Name() != "refresh" {
		t.Fatal("SEV-SNP collateral must expose refresh")
	}
	for _, name := range []string{"quote", "trust-root", "output"} {
		if refreshCollateralCmd.Flags().Lookup(name) == nil {
			t.Fatalf("collateral refresh is missing --%s", name)
		}
	}
}
