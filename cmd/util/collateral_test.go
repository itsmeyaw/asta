package util

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSnapshot(t *testing.T) {
	output := filepath.Join(t.TempDir(), "snapshot")
	if err := WriteSnapshot(output, "test", map[string][]byte{"artifact": []byte("data")}, map[string]string{"artifact": "https://example.com/artifact"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("data"))
	if manifest.Platform != "test" || manifest.SHA256["artifact"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}
