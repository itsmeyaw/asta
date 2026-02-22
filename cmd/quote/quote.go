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

package quote

import (
	"fmt"
	"strconv"
	"time"

	"github.com/itsmeyaw/asta/cmd"
	"github.com/spf13/cobra"
)

type Format string

const (
	FormatBin  Format = "bin"
	FormatJSON Format = "json"
)

func (f *Format) String() string { return string(*f) }
func (f *Format) Type() string   { return "format" }
func (f *Format) Set(s string) error {
	switch s {
	case string(FormatBin), string(FormatJSON):
		*f = Format(s)
		return nil
	default:
		return fmt.Errorf("must be one of: bin, json")
	}
}

type QuoteFlags struct {
	Out    string `json:"out" yaml:"out"`
	Nonce  string `json:"nonce" yaml:"nonce"`
	Format Format `json:"format" yaml:"format"`
}

var quoteFlags QuoteFlags

var quoteCmd = &cobra.Command{
	Use:   "quote",
	Short: "Create an attestation quote",
	Long:  `Create an attestation quote for a given enclave.`,
}

func init() {
	cmd.RootCmd.AddCommand(quoteCmd)

	quoteFlags.Format = FormatBin
	quoteFlags.Nonce = strconv.FormatInt(time.Now().UnixNano(), 10)

	quoteCmd.PersistentFlags().StringVarP(&quoteFlags.Out, "out", "o", "quote.bin", "Output file for the quote")
	quoteCmd.PersistentFlags().VarP(&quoteFlags.Format, "format", "f", "Output format (bin or json)")
	quoteCmd.PersistentFlags().StringVarP(&quoteFlags.Nonce, "nonce", "n", "", "Nonce for the quote")
}
