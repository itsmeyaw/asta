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

package cmd

import "testing"

func TestRootCommandName(t *testing.T) {
	if RootCmd.Name() != "herta" {
		t.Fatalf("root command name = %q, want herta", RootCmd.Name())
	}
}

func TestCollateralRefreshCommandsArePlatformLocal(t *testing.T) {
	for _, path := range [][]string{{"tpm", "collateral", "refresh"}, {"tdx", "collateral", "refresh"}, {"sev-snp", "collateral", "refresh"}} {
		command, _, err := RootCmd.Find(path)
		if err != nil || command.Name() != "refresh" {
			t.Fatalf("missing platform-local collateral command %v", path)
		}
	}
	for _, command := range RootCmd.Commands() {
		if command.Name() == "collateral" {
			t.Fatal("root command must not expose collateral")
		}
	}
}
