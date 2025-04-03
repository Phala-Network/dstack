package dstack_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"crypto/x509"
	"encoding/pem"

	"github.com/Dstack-TEE/dstack/sdk/go/dstack"
)

func TestGetKey(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetKey(context.Background(), "/", "test")
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.SignatureChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}
}

func TestGetQuote(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.GetQuote(context.Background(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Quote) == 0 {
		t.Error("expected quote to not be empty")
	}

	if resp.EventLog == "" {
		t.Error("expected event log to not be empty")
	}

	var eventLog []map[string]interface{}
	err = json.Unmarshal([]byte(resp.EventLog), &eventLog)
	if err != nil {
		t.Errorf("expected event log to be a valid JSON object: %v", err)
	}

	// Get quote RTMRs manually
	quoteRtmrs := [4][48]byte{
		[48]byte(resp.Quote[376:424]),
		[48]byte(resp.Quote[424:472]),
		[48]byte(resp.Quote[472:520]),
		[48]byte(resp.Quote[520:568]),
	}

	// Test ReplayRTMRs
	rtmrs, err := resp.ReplayRTMRs()
	if err != nil {
		t.Fatal(err)
	}

	if len(rtmrs) != 4 {
		t.Errorf("expected 4 RTMRs, got %d", len(rtmrs))
	}

	// Verify RTMRs
	for i := 0; i < 4; i++ {
		if rtmrs[i] == "" {
			t.Errorf("expected RTMR %d to not be empty", i)
		}

		rtmrBytes, err := hex.DecodeString(rtmrs[i])
		if err != nil {
			t.Errorf("expected RTMR %d to be valid hex: %v", i, err)
		}

		if !bytes.Equal(rtmrBytes, quoteRtmrs[i][:]) {
			t.Errorf("expected RTMR %d to be %s, got %s", i, hex.EncodeToString(quoteRtmrs[i][:]), rtmrs[i])
		}
	}
}

func TestGetTlsKey(t *testing.T) {
	client := dstack.NewDstackClient()
	altNames := []string{"localhost"}
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("test-subject"),
		dstack.WithAltNames(altNames),
		dstack.WithUsageRaTls(true),
		dstack.WithUsageServerAuth(true),
		dstack.WithUsageClientAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "test-subject") {
		t.Errorf("expected subject to contain 'test-subject', got %s", cert.Subject.String())
	}

	// Check alt names
	dnsNames := cert.DNSNames

	if len(dnsNames) < 1 || dnsNames[0] != "localhost" {
		t.Errorf("expected DNS name 'localhost', got %v", dnsNames)
	}

	// Check key usage and extended key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected KeyUsageDigitalSignature to be set")
	}

	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to be set")
	}

	if !hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to be set")
	}
}

func TestGetTlsKeyMinimalOptions(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with minimal options (just subject)
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("minimal-subject"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "minimal-subject") {
		t.Errorf("expected subject to contain 'minimal-subject', got %s", cert.Subject.String())
	}

	// Check that no alt names are set
	if len(cert.DNSNames) > 0 {
		t.Errorf("expected no DNS names, got %v", cert.DNSNames)
	}

	if len(cert.IPAddresses) > 0 {
		t.Errorf("expected no IP addresses, got %v", cert.IPAddresses)
	}
}

func TestGetTlsKeyServerOnly(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with server auth only
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("server-only"),
		dstack.WithUsageServerAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "server-only") {
		t.Errorf("expected subject to contain 'server-only', got %s", cert.Subject.String())
	}

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to be set")
	}

	if hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to not be set")
	}
}

func TestGetTlsKeyClientOnly(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with client auth only
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("client-only"),
		dstack.WithUsageClientAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "client-only") {
		t.Errorf("expected subject to contain 'client-only', got %s", cert.Subject.String())
	}

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	if hasServerAuth {
		t.Error("expected ExtKeyUsageServerAuth to not be set")
	}

	if !hasClientAuth {
		t.Error("expected ExtKeyUsageClientAuth to be set")
	}
}

func TestGetTlsKeyWithMultipleAltNames(t *testing.T) {
	client := dstack.NewDstackClient()
	// Test with multiple alternative names
	altNames := []string{"example.com", "test.example.com"}
	resp, err := client.GetTlsKey(
		context.Background(),
		dstack.WithSubject("multi-altnames"),
		dstack.WithAltNames(altNames),
		dstack.WithUsageServerAuth(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Key == "" {
		t.Error("expected key to not be empty")
	}

	if len(resp.CertificateChain) == 0 {
		t.Error("expected certificate chain to not be empty")
	}

	// Verify certificate content
	cert, err := parseCertificate(resp.CertificateChain[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check subject
	if !strings.Contains(cert.Subject.String(), "multi-altnames") {
		t.Errorf("expected subject to contain 'multi-altnames', got %s", cert.Subject.String())
	}

	// Check DNS names
	expectedDNSNames := []string{"example.com", "test.example.com"}
	for _, name := range expectedDNSNames {
		found := false
		for _, dnsName := range cert.DNSNames {
			if dnsName == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected DNS name %s not found in certificate", name)
		}
	}
}

// Helper function to parse PEM certificate
func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func TestInfo(t *testing.T) {
	client := dstack.NewDstackClient()
	resp, err := client.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if resp.AppID == "" {
		t.Error("expected app_id to not be empty")
	}

	if resp.InstanceID == "" {
		t.Error("expected instance_id to not be empty")
	}

	if resp.TcbInfo == "" {
		t.Error("expected tcb_info to not be empty")
	}

	// Test DecodeTcbInfo
	tcbInfo, err := resp.DecodeTcbInfo()
	if err != nil {
		t.Fatal(err)
	}

	if tcbInfo.Rtmr0 == "" {
		t.Error("expected rtmr0 to not be empty")
	}

	if tcbInfo.Rtmr1 == "" {
		t.Error("expected rtmr1 to not be empty")
	}

	if tcbInfo.Rtmr2 == "" {
		t.Error("expected rtmr2 to not be empty")
	}

	if tcbInfo.Rtmr3 == "" {
		t.Error("expected rtmr3 to not be empty")
	}

	if len(tcbInfo.EventLog) == 0 {
		t.Error("expected event log to not be empty")
	}
}
