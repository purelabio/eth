module github.com/purelabio/eth

require (
	// Test-only
	github.com/davecgh/go-spew v1.1.1

	// We're using gorilla websockets rather than "golang.org/x/net/websocket"
	// because Parity sometimes uses fragmented frames (?). "x/net/websocket"
	// doesn't support them, and gives us partial messages that fail to decode.
	github.com/gorilla/websocket v1.4.0

	github.com/pkg/errors v0.8.0

	// For legacy Keccak256 hashing.
	golang.org/x/crypto v0.0.0-20181015023909-0c41d7ab0a0e
)
