// Package all links every checker of this repository into a binary.
package all

import (
	// Checkers register themselves in their init functions.
	_ "github.com/0xmhha/wbft-inspector/internal/check/app"
	_ "github.com/0xmhha/wbft-inspector/internal/check/hdr"
	_ "github.com/0xmhha/wbft-inspector/internal/check/net"
	_ "github.com/0xmhha/wbft-inspector/internal/check/sec"
	_ "github.com/0xmhha/wbft-inspector/internal/check/sm"
	_ "github.com/0xmhha/wbft-inspector/internal/check/synccontrol"
	_ "github.com/0xmhha/wbft-inspector/internal/check/timer"
)
