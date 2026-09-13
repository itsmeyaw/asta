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

func TestGoogleAIAURL(t *testing.T) {
	got, err := googleAIAURL("http://privateca-content-123.storage.googleapis.com/path/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://privateca-content-123.storage.googleapis.com/path/ca.crt" {
		t.Fatalf("googleAIAURL() = %q", got)
	}
	if _, err := googleAIAURL("https://example.com/ca.crt"); err == nil {
		t.Fatal("googleAIAURL accepted a non-Google host")
	}
}
