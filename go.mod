module github.com/purelabio/eth

require (
	// Only for testing
	github.com/davecgh/go-spew v1.1.1
	// We're using gorilla websockets rather than "golang.org/x/net/websocket"
	// because the latter doesn't support fragmented frames (?), which are
	// sometimes used by Parity.
	github.com/gorilla/websocket v1.4.0
	// Only for code generation
	github.com/mitranim/repr v0.0.0-20181106161538-227d8c7751ac
	github.com/pkg/errors v0.8.0
	// For "legacy" Keccak256 hashing.
	golang.org/x/crypto v0.0.0-20181015023909-0c41d7ab0a0e
)
