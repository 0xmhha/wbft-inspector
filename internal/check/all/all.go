// Package all links every checker of this repository into a binary.
package all

import (
	// Checkers register themselves in their init functions.
	_ "github.com/0xmhha/wbft-inspector/internal/check/net"
	_ "github.com/0xmhha/wbft-inspector/internal/check/sm"
	_ "github.com/0xmhha/wbft-inspector/internal/check/timer"
)
