# DStack SDK

The DStack SDK for Go.

## Installation

```bash
go get github.com/Dstack-TEE/dstack/sdk/go
```

## Basic Usage

```go
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Dstack-TEE/dstack/sdk/go/tappd"
)

func main() {
	client := tappd.NewTappdClient(
		// tappd.WithEndpoint("http://localhost"),
		// tappd.WithLogger(slog.Default()),
	)

	// Get information about the Tappd instance
	info, err := client.Info(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(info.AppID)  // Application ID
	fmt.Println(info.TcbInfo.Mrtd)  // Access TCB info directly
	fmt.Println(info.TcbInfo.EventLog[0].Event)  // Access event log entries

	// Derive a key with optional path and subject
	deriveKeyResp, err := client.DeriveKey(context.Background(), "/")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(deriveKeyResp.Key)  // -----BEGIN PRIVATE KEY--- ...
	keyBytes, _ := deriveKeyResp.ToBytes(-1)  // Get key as bytes

	// Generate TDX quote
	tdxQuoteResp, err := client.TdxQuote(context.Background(), []byte("test"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tdxQuoteResp.Quote)  // 0x0000000000000000000 ...

	rtmrs, err := tdxQuoteResp.ReplayRTMRs()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(rtmrs)  // map[0:00000000000000000 ...
}
```

## API Reference

### TappdClient

#### Constructor

```go
func NewTappdClient(opts ...TappdClientOption) *TappdClient
```

Options:
- `WithEndpoint(endpoint string)`: Sets the endpoint (Unix socket path or HTTP(S) URL). Defaults to '/var/run/tappd.sock'.
- `WithLogger(logger *slog.Logger)`: Sets the logger. Defaults to `slog.Default()`.

The client uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set.

NOTE: Leave endpoint empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/tappd.sock:/var/run/tappd.sock
```

For local development without TDX devices, you can use the simulator available for download here:

https://github.com/Leechael/tappd-simulator/releases

#### Methods

##### `DeriveKey(ctx context.Context, path string) (*DeriveKeyResponse, error)`

Derives a key for the given path. This is a convenience method that uses the path as the subject.

##### `DeriveKeyWithSubject(ctx context.Context, path string, subject string) (*DeriveKeyResponse, error)`

Derives a key for the given path and subject.

##### `DeriveKeyWithSubjectAndAltNames(ctx context.Context, path string, subject string, altNames []string) (*DeriveKeyResponse, error)`

Derives a key for the given path, subject, and alternative names.

**NOTE: Only the `path` affects the derived result. `subject` & `altNames` are for the generated certificate and do not affect the derived result.**

##### `TdxQuote(ctx context.Context, reportData []byte) (*TdxQuoteResponse, error)`

Generates a TDX quote using SHA512 as the hash algorithm.

##### `TdxQuoteWithHashAlgorithm(ctx context.Context, reportData []byte, hashAlgorithm QuoteHashAlgorithm) (*TdxQuoteResponse, error)`

Generates a TDX quote with a specific hash algorithm. The quote is returned in hex format, and you can paste your quote into https://proof.t16z.com/ to get the attestation report.

##### `Info(ctx context.Context) (*TappdInfoResponse, error)`

Retrieves information about the Tappd instance, including TCB info and event logs.

### Types

```go
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

type DeriveKeyResponse struct {
    Key              string
    CertificateChain []string
}

func (d *DeriveKeyResponse) ToBytes(maxLength int) ([]byte, error)

type TdxQuoteResponse struct {
    Quote    string
    EventLog string
}

func (r *TdxQuoteResponse) ReplayRTMRs() (map[int]string, error)

type EventLog struct {
    IMR          int
    EventType    int
    Digest       string
    Event        string
    EventPayload string
}

type TcbInfo struct {
    Mrtd       string
    RootfsHash string
    Rtmr0      string
    Rtmr1      string
    Rtmr2      string
    Rtmr3      string
    EventLog   []EventLog
}

type TappdInfoResponse struct {
    AppID        string
    InstanceID   string
    AppCert      string
    TcbInfo      TcbInfo
    AppName      string
    PublicLogs   bool
    PublicSysinfo bool
}
```

## Development

Set up [Go](https://go.dev/doc/install).

### Running Tests

There are several ways to run the tests:

1. Run all tests with local simulator:
```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test ./...
```

2. Run specific test package:
```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test ./tappd
```

3. Run tests with verbose output:
```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test -v ./...
```

4. Run specific test function:
```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test -v ./tappd -run TestDeriveKey
```

5. Run tests with coverage report:
```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test -coverprofile=coverage.out ./...
# View coverage in browser
go tool cover -html=coverage.out
```

Note: The tests require a running Tappd simulator. You can download it from:
https://github.com/Leechael/tappd-simulator/releases

Make sure the simulator is running and accessible at the path specified in `DSTACK_SIMULATOR_ENDPOINT` before running the tests.

## License

Apache License
