package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

func ParseNonceFlag(cmd *cobra.Command) ([]byte, error) {
	nonceHex, err := cmd.Flags().GetString("nonce")
	if err != nil {
		return nil, fmt.Errorf("reading nonce flag: %w", err)
	}

	if nonceHex == "" {
		return nil, nil
	}

	parsedNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	// Enforce that the length of nonce does not exceed 32 bytes because we use SHA256 digest which is 32 bytes
	// See TPM 2.0 Library Specification Part 2 Section 10.4.3
	if len(parsedNonce) > 32 {
		return nil, fmt.Errorf("nonce cannot exceed 32 bytes (got %d bytes)", len(parsedNonce))
	}

	return parsedNonce, nil
}

func UsageError(cmd *cobra.Command, err error) error {
	_ = cmd.Usage()
	return err
}
