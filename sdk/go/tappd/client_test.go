package tappd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	client := NewTappdClient("")
	result, err := client.DeriveKey(context.Background(), "/", "test")
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	if result.Key == "" {
		t.Error("key should not be empty")
	}

	if len(result.CertificateChain) == 0 {
		t.Error("certificate chain should not be empty")
	}

	// Test key bytes conversion
	keyBytes, err := result.ToBytes(-1)
	if err != nil {
		t.Fatalf("failed to convert key to bytes: %v", err)
	}
	if len(keyBytes) == 0 {
		t.Error("key bytes should not be empty")
	}

	// Test truncated key bytes
	truncatedBytes, err := result.ToBytes(32)
	if err != nil {
		t.Fatalf("failed to convert truncated key to bytes: %v", err)
	}
	if len(truncatedBytes) != 32 {
		t.Errorf("truncated key length should be 32, got %d", len(truncatedBytes))
	}
}

func TestTdxQuote(t *testing.T) {
	client := NewTappdClient("")
	testData := []byte("some data or anything")
	result, err := client.TdxQuote(context.Background(), testData)
	if err != nil {
		t.Fatalf("failed to get tdx quote: %v", err)
	}

	if !strings.HasPrefix(result.Quote, "0x") {
		t.Error("quote should start with 0x")
	}

	if !strings.HasPrefix(result.EventLog, "{") {
		t.Error("event log should be a JSON object")
	}

	var eventLog interface{}
	if err := json.Unmarshal([]byte(result.EventLog), &eventLog); err != nil {
		t.Errorf("event log should be valid JSON: %v", err)
	}
}
