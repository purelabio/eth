package eth

import (
	"math/big"
	"time"
	"unsafe"
)

// Conversion ratios.
const (
	Wei   = 1
	Ether = 1e18 // Measured in wei
)

// "Magic" words understood by RPC methods that expect a block number.
const (
	BlockNumberEarliest = "earliest"
	BlockNumberLatest   = "latest"
	BlockNumberPending  = "pending"
)

// Zero-initialized arrays for equality comparisons.
var (
	ZeroAddress Address
	ZeroWord    Word
	ZeroHash    Hash
	ZeroBloom   Bloom
)

var (
	// Determines the default reconnect interval of long-lived RPC transports,
	// such as WsTrans. Configurable on per-transport basis.
	defaultReconnectInterval = time.Second

	etherBig = big.NewFloat(Ether)
)

/*
Converts ethers to wei. Truncates leftover fractional digits. Beware: floats
should not be used for financial calculations. Conversion functions are
provided only for display purposes and for handling user input.
*/
func EthToWei(eth float64) *big.Int {
	num := big.NewFloat(eth)
	num.Mul(num, etherBig)
	// TODO: round instead of truncating.
	out, _ := num.Int(nil)
	return out
}

/*
Converts wei to ethers. Beware: floats should not be used for financial
calculations. Conversion functions are provided only for display purposes and
for handling user input.
*/
func WeiToEth(wei *big.Int) float64 {
	num := new(big.Float).SetInt(wei)
	num.Quo(num, etherBig)
	out, _ := num.Float64()
	return out
}

/*
Reinterprets a byte slice as a string, saving an allocation.
Borrowed from the standard library. Reasonably safe.
*/
func bytesToMutableString(bytes []byte) string {
	return *(*string)(unsafe.Pointer(&bytes))
}

/*
Returns a byte slice backed by the provided string. Mutations are reflected in
the source string, unless it's backed by constant storage, in which case they
trigger a segfault. Reslicing the bytes should work fine. Should be safe as long
as the bytes are treated as read-only.
*/
func stringToBytesUnsafe(str string) []byte {
	type sliceHeader struct {
		dat uintptr
		len int
		cap int
	}
	slice := *(*sliceHeader)(unsafe.Pointer(&str))
	slice.cap = slice.len
	return *(*[]byte)(unsafe.Pointer(&slice))
}

// Launches a goroutine, returning a channel that will close on completion,
// transmitting its error or panic, if any.
func gogo(fun func() error) chan error {
	out := make(chan error, 1)

	go func() {
		defer func() {
			err, _ := recover().(error)
			if err != nil {
				select {
				case out <- err:
				default:
				}
			}
			close(out)
		}()

		err := fun()
		if err != nil {
			out <- err
		}
	}()

	return out
}
