# bouncelayer-go

Official Go client library for [BounceLayer](https://bouncelayer.com) — high-throughput RFC 5321 email verification.

## Installation

```bash
go get github.com/BounceLayer/bouncelayer-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/BounceLayer/bouncelayer-go"
)

func main() {
	client := bouncelayer.NewClient(os.Getenv("BOUNCELAYER_API_KEY"))

	result, err := client.VerifySingle("alex@stripe.com")
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Printf("Email: %s, Status: %s, Confidence: %d%%\n", 
		result.Email, result.Status, result.ConfidenceScore)
}
```

## License
MIT
