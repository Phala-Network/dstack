package tappd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	client := NewTappdClient("", slog.Default())
	resp, err := client.DeriveKey(context.Background(), "/", "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Test ToBytes
	key, err := resp.ToBytes(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) == 0 {
		t.Error("expected key bytes to not be empty")
	}

	// Test ToBytes with max length
	key, err = resp.ToBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Errorf("expected key length to be 32, got %d", len(key))
	}
}

func TestTdxQuote(t *testing.T) {
	client := NewTappdClient("", slog.Default())
	resp, err := client.TdxQuote(context.Background(), []byte("test"), "")
	if err != nil {
		t.Fatal(err)
	}

	if resp.Quote == "" {
		t.Error("expected quote to not be empty")
	}

	if !strings.HasPrefix(resp.Quote, "0x") {
		t.Error("expected quote to start with 0x")
	}

	if resp.EventLog == "" {
		t.Error("expected event log to not be empty")
	}

	var eventLog map[string]interface{}
	err = json.Unmarshal([]byte(resp.EventLog), &eventLog)
	if err != nil {
		t.Errorf("expected event log to be a valid JSON object: %v", err)
	}

	// Test ReplayRTMRs
	rtmrs, err := resp.ReplayRTMRs()
	if err != nil {
		t.Fatal(err)
	}

	if len(rtmrs) != 4 {
		t.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}

	for i := 0; i < 4; i++ {
		if rtmrs[i] == "" {
			t.Errorf("expected RTMR %d to not be empty", i)
		}
		// Verify hex string
		if _, err := hex.DecodeString(rtmrs[i]); err != nil {
			t.Errorf("expected RTMR %d to be valid hex: %v", i, err)
		}
	}
}

func TestTdxQuoteRawHash(t *testing.T) {
	client := NewTappdClient("", slog.Default())

	// Test valid raw hash
	resp, err := client.TdxQuote(context.Background(), []byte("test"), RAW)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Quote == "" {
		t.Error("expected quote to not be empty")
	}

	// Test too large raw hash
	largeData := make([]byte, 65)
	_, err = client.TdxQuote(context.Background(), largeData, RAW)
	if err == nil {
		t.Error("expected error for large raw hash data")
	}
	if !strings.Contains(err.Error(), "report data is too large") {
		t.Errorf("unexpected error message: %v", err)
	}
}
