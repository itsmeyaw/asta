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

package types

import "github.com/google/go-tpm/tpm2"

type TpmQuote struct {
	Nonce            string                `json:"nonce" yaml:"nonce"`
	Device           string                `json:"device" yaml:"device"`
	PCRUpdateCounter uint32                `json:"pcrUpdateCounter" yaml:"pcrUpdateCounter"`
	PCRSelection     tpm2.TPMLPCRSelection `json:"pcrSelection" yaml:"pcrSelection"`
	PCRValues        tpm2.TPMLDigest       `json:"pcrValues" yaml:"pcrValues"`
	Quote            []byte                `json:"quote" yaml:"quote"`
	Signature        []byte                `json:"signature" yaml:"signature"`
}
