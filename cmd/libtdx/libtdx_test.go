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

package libtdx

import "testing"

func TestTDXVerificationTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ordinary", input: "20260910165629Z", want: "260910165629Z"},
		{name: "lower bound", input: "19500101000000Z", want: "500101000000Z"},
		{name: "upper bound", input: "20491231235959Z", want: "491231235959Z"},
		{name: "before range", input: "19491231235959Z", wantErr: true},
		{name: "after range", input: "20500101000000Z", wantErr: true},
		{name: "invalid date", input: "20260230000000Z", wantErr: true},
		{name: "invalid length", input: "260910165629Z", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := tdxVerificationTime([]byte(test.input))
			if test.wantErr {
				if err == nil {
					t.Fatalf("tdxVerificationTime(%q) succeeded, want error", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("tdxVerificationTime(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("tdxVerificationTime(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}
