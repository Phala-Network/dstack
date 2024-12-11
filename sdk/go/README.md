# Go SDK

The DStack SDK for Go.

# Installation

```bash
go get github.com/Dstack-TEE/dstack/sdk/go
```

# Usage

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

	deriveKeyResp, err := client.DeriveKey(context.Background(), "/")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(deriveKeyResp) // &{-----BEGIN PRIVATE KEY--- ...

	tdxQuoteResp, err := client.TdxQuote(context.Background(), []byte("test"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tdxQuoteResp) // &{0x0000000000000000000 ...

	rtmrs, err := tdxQuoteResp.ReplayRTMRs()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(rtmrs) // map[0:00000000000000000 ...
}
```

# For Development

Set up [Go](https://go.dev/doc/install).

Running the unit tests with local simulator via `/tmp/tappd.sock`:

```bash
DSTACK_SIMULATOR_ENDPOINT=/tmp/tappd.sock go test ./...
```
