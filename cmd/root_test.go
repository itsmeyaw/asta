package cmd

import "testing"

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
