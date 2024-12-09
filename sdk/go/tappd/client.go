package tappd

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

// Represents the hash algorithm used in TDX quote generation.
type QuoteHashAlgorithm string

const (
	SHA256    QuoteHashAlgorithm = "sha256"
	SHA384    QuoteHashAlgorithm = "sha384"
	SHA512    QuoteHashAlgorithm = "sha512"
	SHA3_256  QuoteHashAlgorithm = "sha3-256"
	SHA3_384  QuoteHashAlgorithm = "sha3-384"
	SHA3_512  QuoteHashAlgorithm = "sha3-512"
	KECCAK256 QuoteHashAlgorithm = "keccak256"
	KECCAK384 QuoteHashAlgorithm = "keccak384"
	KECCAK512 QuoteHashAlgorithm = "keccak512"
	RAW       QuoteHashAlgorithm = "raw"
)

// Represents the response from a key derivation request.
type DeriveKeyResponse struct {
	Key              string   `json:"key"`
	CertificateChain []string `json:"certificate_chain"`
}

// Decodes the key to bytes, optionally truncating to maxLength. If maxLength
// < 0, the key is not truncated.
func (d *DeriveKeyResponse) ToBytes(maxLength int) ([]byte, error) {
	content := d.Key

	content = strings.Replace(content, "-----BEGIN PRIVATE KEY-----", "", 1)
	content = strings.Replace(content, "-----END PRIVATE KEY-----", "", 1)
	content = strings.Replace(content, "\n", "", -1)

	binary, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, err
	}

	if maxLength >= 0 && len(binary) > maxLength {
		return binary[:maxLength], nil
	}
	return binary, nil
}

// Represents the response from a TDX quote request.
type TdxQuoteResponse struct {
	Quote    string `json:"quote"`
	EventLog string `json:"event_log"`
}

const INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// Replays the RTMR history to calculate final RTMR values
func replayRTMR(history []string) (string, error) {
	if len(history) == 0 {
		return INIT_MR, nil
	}

	mr, err := hex.DecodeString(INIT_MR)
	if err != nil {
		return "", err
	}

	for _, content := range history {
		contentBytes, err := hex.DecodeString(content)
		if err != nil {
			return "", err
		}

		if len(contentBytes) < 48 {
			padding := make([]byte, 48-len(contentBytes))
			contentBytes = append(contentBytes, padding...)
		}

		h := sha512.New384()
		h.Write(append(mr, contentBytes...))
		mr = h.Sum(nil)
	}

	return hex.EncodeToString(mr), nil
}

// Replays the RTMR history to calculate final RTMR values
func (r *TdxQuoteResponse) ReplayRTMRs() (map[int]string, error) {
	var eventLog []struct {
		IMR    int    `json:"imr"`
		Digest string `json:"digest"`
	}
	json.Unmarshal([]byte(r.EventLog), &eventLog)

	rtmrs := make(map[int]string, 4)
	for idx := 0; idx < 4; idx++ {
		history := make([]string, 0)
		for _, event := range eventLog {
			if event.IMR == idx {
				history = append(history, event.Digest)
			}
		}

		rtmr, err := replayRTMR(history)
		if err != nil {
			return nil, err
		}

		rtmrs[idx] = rtmr
	}

	return rtmrs, nil
}

// Returns the appropriate endpoint based on environment and input. If the
// endpoint is empty, it will use the simulator endpoint if it is set in the
// environment through DSTACK_SIMULATOR_ENDPOINT. Otherwise, it will use the
// default endpoint at /var/run/tappd.sock.
func getEndpoint(endpoint string) string {
	if endpoint != "" {
		return endpoint
	}
	if simEndpoint, exists := os.LookupEnv("DSTACK_SIMULATOR_ENDPOINT"); exists {
		slog.Warn("Using simulator endpoint", "endpoint", simEndpoint)
		return simEndpoint
	}
	return "/var/run/tappd.sock"
}

// Handles communication with the Tappd service.
type TappdClient struct {
	baseURL    string
	httpClient *http.Client
}

// Creates a new TappdClient instance based on the provided endpoint.
// If the endpoint is empty, it will use the simulator endpoint if it is
// set in the environment through DSTACK_SIMULATOR_ENDPOINT. Otherwise, it
// will use the default endpoint at /var/run/tappd.sock.
func NewTappdClient(endpoint string) *TappdClient {
	endpoint = getEndpoint(endpoint)
	baseURL := endpoint
	httpClient := &http.Client{}

	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		baseURL = "http://localhost"
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", endpoint)
				},
			},
		}
	}

	return &TappdClient{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// Sends an RPC request to the Tappd service.
func (c *TappdClient) sendRPCRequest(ctx context.Context, path string, payload interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Derives a key from the Tappd service.
func (c *TappdClient) DeriveKey(ctx context.Context, path, subject string) (*DeriveKeyResponse, error) {
	payload := map[string]string{
		"path":    path,
		"subject": subject,
	}

	data, err := c.sendRPCRequest(ctx, "/prpc/Tappd.DeriveKey", payload)
	if err != nil {
		return nil, err
	}

	var response DeriveKeyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Sends a TDX quote request to the Tappd service.
func (c *TappdClient) TdxQuote(ctx context.Context, reportData []byte, hashAlgorithm QuoteHashAlgorithm) (*TdxQuoteResponse, error) {
	hexData := hex.EncodeToString(reportData)
	if hashAlgorithm == RAW {
		if len(hexData) > 128 {
			return nil, fmt.Errorf("report data is too large, it should be less than 128 characters when hash_algorithm is raw")
		}
		if len(hexData) < 128 {
			hexData = strings.Repeat("0", 128-len(hexData)) + hexData
		}
	}

	payload := map[string]interface{}{
		"report_data":    hexData,
		"hash_algorithm": string(hashAlgorithm),
	}

	data, err := c.sendRPCRequest(ctx, "/prpc/Tappd.TdxQuote", payload)
	if err != nil {
		return nil, err
	}

	var response TdxQuoteResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
