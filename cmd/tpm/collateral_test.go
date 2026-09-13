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
