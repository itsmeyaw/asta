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
