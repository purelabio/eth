package eth

import (
	"database/sql/driver"
	"encoding/json"
	"math/big"
	"strconv"
	"sync"

	"github.com/pkg/errors"
)

var null = []byte{'n', 'u', 'l', 'l'}

// Version of "[]byte" that uses "0x"-prefixed hex encoding and decoding.
type HexBytes []byte

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func DecodeHexBytes(input []byte) (HexBytes, error) {
	var out HexBytes
	err := out.UnmarshalText(input)
	return out, err
}

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustDecodeHexBytes(input []byte) HexBytes {
	out, err := DecodeHexBytes(input)
	if err != nil {
		panic(err)
	}
	return out
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func ParseHexBytes(input string) (HexBytes, error) {
	return DecodeHexBytes(stringToBytesUnsafe(input))
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustParseHexBytes(input string) HexBytes {
	return MustDecodeHexBytes(stringToBytesUnsafe(input))
}

/*
Implements "encoding.Marshaler". Uses hex encoding prefixed with "0x".
*/
func (self HexBytes) MarshalText() ([]byte, error) {
	return HexEncode([]byte(self)), nil
}

/*
Implements "encoding.Unmarshaler". Empty input is ok. Otherwise, it must be
prefixed with "0x".
*/
func (self *HexBytes) UnmarshalText(input []byte) error {
	out, err := HexDecode(input)
	if err != nil {
		return err
	}
	*self = HexBytes(out)
	return nil
}

/*
Implements "json.Marshaler". A zero-length value encodes as "null". Otherwise,
it encodes as a hex string, prefixed with "0x".
*/
func (self HexBytes) MarshalJSON() ([]byte, error) {
	if len(self) == 0 {
		return null, nil
	}
	return hexEncodeQuoted(self), nil
}

/*
Implements "fmt.Stringer". Follows the same rules as "MarshalText".
*/
func (self HexBytes) String() string {
	return bytesToMutableString(HexEncode([]byte(self)))
}

// Version of `big.Int` that encodes/decodes in base 16 with the "0x" prefix.
type HexInt big.Int

/*
Implements "encoding.Marshaler". Uses hex encoding prefixed with "0x".
*/
func (self *HexInt) MarshalText() ([]byte, error) {
	out := make([]byte, 0, 16)
	out = append(out, '0', 'x')
	return (*big.Int)(self).Append(out, 16), nil
}

/*
Implements "encoding.Unmarshaler". The input must be in base 16, prefixed with
"0x".
*/
func (self *HexInt) UnmarshalText(input []byte) error {
	input, err := drop0x(input)
	if err != nil {
		return err
	}

	_, ok := (*big.Int)(self).SetString(bytesToMutableString(input), 16)
	if !ok {
		return errors.Errorf("failed to decode %q as a hex integer", input)
	}
	return nil
}

/*
Implements "fmt.Stringer". Follows the same rules as "MarshalText".
*/
func (self *HexInt) String() string {
	bytes, _ := self.MarshalText()
	return bytesToMutableString(bytes)
}

// Version of `uint64` that encodes/decodes in base 16 with the "0x" prefix.
type HexUint64 uint64

/*
Implements "encoding.Marshaler". Uses hex encoding prefixed with "0x".
*/
func (self HexUint64) MarshalText() ([]byte, error) {
	out := make([]byte, 0, 16)
	out = append(out, '0', 'x')
	return strconv.AppendUint(out, uint64(self), 16), nil
}

/*
Implements "encoding.Unmarshaler". The input must be in base 16, prefixed with
"0x".
*/
func (self *HexUint64) UnmarshalText(input []byte) error {
	input, err := drop0x(input)
	if err != nil {
		return err
	}
	out, err := strconv.ParseUint(bytesToMutableString(input), 16, 64)
	*self = HexUint64(out)
	return err
}

/*
Implements "fmt.Stringer". Follows the same rules as "MarshalText".
*/
func (self HexUint64) String() string {
	bytes, _ := self.MarshalText()
	return bytesToMutableString(bytes)
}

/*
Compact representation of an Ethereum address. Uses hex-encoding and
hex-decoding with the mandatory "0x" prefix.

To avoid gotchas, a zero-initialized Address{} JSON-encodes as "null" and
text-encodes as "".
*/
type Address [20]byte

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func DecodeAddress(input []byte) (Address, error) {
	var out Address
	err := out.UnmarshalText(input)
	return out, err
}

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustDecodeAddress(input []byte) Address {
	out, err := DecodeAddress(input)
	if err != nil {
		panic(err)
	}
	return out
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func ParseAddress(input string) (Address, error) {
	return DecodeAddress(stringToBytesUnsafe(input))
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustParseAddress(input string) Address {
	return MustDecodeAddress(stringToBytesUnsafe(input))
}

/*
Implements "encoding.Marshaler". A zero-initialized value encodes as "",
otherwise uses hex encoding prefixed with "0x".
*/
func (self Address) MarshalText() ([]byte, error) {
	if self == ZeroAddress {
		return nil, nil
	}
	return HexEncode(self[:]), nil
}

/*
Implements "encoding.Unmarshaler". Empty input is ok. Otherwise, it must be
prefixed with "0x".
*/
func (self *Address) UnmarshalText(input []byte) error {
	if len(input) == 0 {
		*self = Address{}
		return nil
	}
	return HexDecodeTo(self[:], input)
}

/*
Implements "json.Marshaler". A zero-initialized value encodes as "null".
Otherwise, it encodes as a hex string, prefixed with "0x".
*/
func (self Address) MarshalJSON() ([]byte, error) {
	if self == ZeroAddress {
		return null, nil
	}
	return hexEncodeQuoted(self[:]), nil
}

/*
Implements "fmt.Stringer". Uses hex encoding prefixed with "0x". Unlike
"MarshalText" and "MarshalJSON", doesn't have special rules for zero-initialized
values.
*/
func (self Address) String() string {
	return bytesToMutableString(HexEncode(self[:]))
}

// Converts into a Word for event log filtering, zero-padded on the left.
func (self Address) Word() Word {
	var out Word
	copy(out[len(out)-len(self):], self[:])
	return out
}

// Implements "sql.Scanner" in terms of "UnmarshalText".
func (self *Address) Scan(src interface{}) error {
	switch src := src.(type) {
	case string:
		return self.UnmarshalText(stringToBytesUnsafe(src))
	case []byte:
		return self.UnmarshalText(src)
	default:
		return errors.Errorf("unrecognized input for %T: %T %v", self, src, src)
	}
}

// Implements "sql/driver.Valuer". A zero-initialized Address{} encodes as "null".
func (self Address) Value() (driver.Value, error) {
	if self == ZeroAddress {
		return null, nil
	}
	return self.MarshalText()
}

/*
A Word represents the standard memory granularity of the EVM: 32 bytes of
arbitrary content. Reminiscent of the register granularity of contemporary CPUs.
All EVM types are padded to at least this size when ABI-encoded. This size is
also used for hashes, log/event topics, etc.

Note that Hash has exactly the same structure, but a slightly different
interpretation. A Word is not assumed to be a hash.

Uses the 0x-prefixed hex notation for encoding and decoding. An empty Word{}
will text-encode as "" and JSON-encode as `null` rather than
"0x0000000000000000000000000000000000000000000000000000000000000000".
*/
type Word [32]byte

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func DecodeWord(input []byte) (Word, error) {
	var out Word
	err := out.UnmarshalText(input)
	return out, err
}

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustDecodeWord(input []byte) Word {
	out, err := DecodeWord(input)
	if err != nil {
		panic(err)
	}
	return out
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func ParseWord(input string) (Word, error) {
	return DecodeWord(stringToBytesUnsafe(input))
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustParseWord(input string) Word {
	return MustDecodeWord(stringToBytesUnsafe(input))
}

/*
Implements "encoding.Marshaler". A zero-initialized value encodes as "",
otherwise uses hex encoding prefixed with "0x".
*/
func (self Word) MarshalText() ([]byte, error) {
	if self == ZeroWord {
		return nil, nil
	}
	return HexEncode(self[:]), nil
}

/*
Implements "encoding.Unmarshaler". Empty input is ok. Otherwise, it must be
prefixed with "0x".
*/
func (self *Word) UnmarshalText(input []byte) error {
	if len(input) == 0 {
		*self = Word{}
		return nil
	}
	return HexDecodeTo(self[:], input)
}

/*
Implements "json.Marshaler". A zero-initialized value encodes as "null".
Otherwise, it encodes as a hex string, prefixed with "0x".
*/
func (self Word) MarshalJSON() ([]byte, error) {
	if self == ZeroWord {
		return null, nil
	}
	return hexEncodeQuoted(self[:]), nil
}

/*
Implements "fmt.Stringer". Uses hex encoding prefixed with "0x". Unlike
"MarshalText" and "MarshalJSON", doesn't have special rules for zero-initialized
values.
*/
func (self Word) String() string {
	return bytesToMutableString(HexEncode(self[:]))
}

/*
Usually represents a block or transaction hash.

Note that while this shares structure and encoding/decoding behavior with Word,
the assumed interpretation is different: a Word is not assumed to be a hash.
*/
type Hash [32]byte

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func DecodeHash(input []byte) (Hash, error) {
	hash, err := DecodeWord(input)
	return Hash(hash), err
}

/*
Decodes the provided input. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustDecodeHash(input []byte) Hash { return Hash(MustDecodeWord(input)) }

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x".
*/
func ParseHash(input string) (Hash, error) {
	hash, err := ParseWord(input)
	return Hash(hash), err
}

/*
Decodes the provided string. Zero-length input is ok. Otherwise, it must be
prefixed with "0x". Panics on error. Convenient for initializing global
variables.
*/
func MustParseHash(input string) Hash { return Hash(MustParseWord(input)) }

/*
Implements "encoding.Marshaler". A zero-initialized value encodes as "",
otherwise uses hex encoding prefixed with "0x".
*/
func (self Hash) MarshalText() ([]byte, error) { return Word(self).MarshalText() }

/*
Implements "encoding.Unmarshaler". Empty input is ok. Otherwise, it must be
prefixed with "0x".
*/
func (self *Hash) UnmarshalText(input []byte) error { return (*Word)(self).UnmarshalText(input) }

/*
Implements "json.Marshaler". A zero-initialized value encodes as "null".
Otherwise, it encodes as a hex string, prefixed with "0x".
*/
func (self Hash) MarshalJSON() ([]byte, error) { return Word(self).MarshalJSON() }

/*
Implements "fmt.Stringer". Uses hex encoding prefixed with "0x". Unlike
"MarshalText" and "MarshalJSON", doesn't have special rules for zero-initialized
values.
*/
func (self Hash) String() string { return Word(self).String() }

type Bloom [256]byte

/*
Implements "encoding.Marshaler". A zero-initialized value encodes as "",
otherwise uses hex encoding prefixed with "0x".
*/
func (self Bloom) MarshalText() ([]byte, error) {
	if self == ZeroBloom {
		return nil, nil
	}
	return HexEncode(self[:]), nil
}

/*
Implements "encoding.Unmarshaler". Empty input is ok. Otherwise, it must be
prefixed with "0x".
*/
func (self *Bloom) UnmarshalText(input []byte) error {
	if len(input) == 0 {
		*self = ZeroBloom
		return nil
	}
	return HexDecodeTo(self[:], input)
}

/*
Implements "json.Marshaler". A zero-initialized value encodes as "null".
Otherwise, it encodes as a hex string, prefixed with "0x".
*/
func (self Bloom) MarshalJSON() ([]byte, error) {
	if self == ZeroBloom {
		return null, nil
	}
	return hexEncodeQuoted(self[:]), nil
}

/*
Implements "fmt.Stringer". Uses hex encoding prefixed with "0x". Unlike
"MarshalText" and "MarshalJSON", doesn't have special rules for zero-initialized
values.
*/
func (self Bloom) String() string {
	return bytesToMutableString(HexEncode(self[:]))
}

type either struct {
	val []byte
	err error
}

// https://www.jsonrpc.org/specification#request_object
// https://www.jsonrpc.org/specification#notification
type rpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// Notification is a variant of rpcRequest without an ID:
// https://www.jsonrpc.org/specification#notification
// Specialized for Parity notifications:
// https://wiki.parity.io/JSONRPC-eth_pubsub-module.html
type rpcNotification struct {
	Jsonrpc string              `json:"jsonrpc"`
	Method  string              `json:"method"`
	Params  rpcNotificationBody `json:"params"`
}

type rpcNotificationBody struct {
	Subscription string          `json:"subscription"` // subscription ID
	Result       json.RawMessage `json:"result"`
}

// https://www.jsonrpc.org/specification#response_object
type rpcResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result"` // assign `*someType` to decode as that type
	Error   *RpcError       `json:"error"`
}

/*
Represents an error that arrives over JSON RPC. See
https://www.jsonrpc.org/specification#error_object for details.
*/
type RpcError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// Implements "error". Includes the RPC error details if possible.
func (self RpcError) Error() string {
	str := "RPC error " + strconv.FormatInt(self.Code, 10) + ": " + self.Message
	if len(self.Data) > 0 {
		str += " Additional details: " + string(self.Data)
	}
	return str
}

/*
Represents the input for an Ethereum transaction, or the input to a non-mutating
contract call. Passed to the various RPC methods.
*/
type TxMsg struct {
	From     Address  `json:"from"`
	To       Address  `json:"to"`
	Data     HexBytes `json:"data"`
	Value    *HexInt  `json:"value"`
	GasPrice *HexInt  `json:"gasPrice"`
	GasLimit *HexInt  `json:"gas"`
}

// Represents an Ethereum block without any attached transactions.
type BlockHead struct {
	Author           Address  `json:"author"`
	Difficulty       *HexInt  `json:"difficulty"`
	ExtraData        HexBytes `json:"extraData"`
	GasLimit         *HexInt  `json:"gasLimit"`
	GasUsed          *HexInt  `json:"gasUsed"`
	Hash             Hash     `json:"hash"`
	LogsBloom        Bloom    `json:"logsBloom"`
	Miner            Address  `json:"miner"`
	MixHash          Hash     `json:"mixHash"`
	Nonce            HexBytes `json:"nonce"`
	Number           *HexInt  `json:"number"`
	ParentHash       Hash     `json:"parentHash"`
	ReceiptsRoot     Hash     `json:"receiptsRoot"`
	Sha3Uncles       Hash     `json:"sha3Uncles"`
	StateRoot        Hash     `json:"stateRoot"`
	Timestamp        *HexInt  `json:"timestamp"`
	TransactionsRoot Hash     `json:"transactionsRoot"`
}

// Represents an Ethereum transaction.
type Transaction struct {
	Hash             Hash     `json:"hash"`
	Nonce            *HexInt  `json:"nonce"`
	BlockHash        Hash     `json:"blockHash"`
	BlockNumber      *HexInt  `json:"blockNumber"`
	TransactionIndex *HexInt  `json:"transactionIndex"`
	From             Address  `json:"from"`
	To               Address  `json:"to"`
	Value            *HexInt  `json:"value"`
	GasPrice         *HexInt  `json:"gasPrice"`
	Gas              *HexInt  `json:"gas"`
	Input            HexBytes `json:"input"`
	Creates          Address  `json:"creates"`
	Raw              HexBytes `json:"raw"`
	PublicKey        HexBytes `json:"publicKey"`
	ChainId          *HexInt  `json:"chainId"`
	StandardV        *HexInt  `json:"standardV"`
	V                *HexInt  `json:"v"`
	R                *HexInt  `json:"r"`
	S                *HexInt  `json:"s"`
}

// Represents a transaction receipt.
type TxReceipt struct {
	BlockHash         Hash       `json:"blockHash"`
	BlockNumber       *HexInt    `json:"blockNumber"`
	ContractAddress   Address    `json:"contractAddress"`
	GasUsed           *HexInt    `json:"gasUsed"`
	Logs              []LogEntry `json:"logs"`
	LogsBloom         Bloom      `json:"logsBloom"`
	CumulativeGasUsed *HexInt    `json:"cumulativeGasUsed"`
	Status            *HexInt    `json:"status"`
	TransactionHash   Hash       `json:"transactionHash"`
	TransactionIndex  *HexInt    `json:"transactionIndex"`
}

/*
A log entry, typically obtained via "EthGetLogs" and used for contracts events.

Original definitions in "go-ethereum" and Parity:
https://github.com/ethereum/go-ethereum/blob/0ae462fb80b8a95e38af08d894ea9ecf9e45f2e7/core/types/log.go#L31
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/log.rs#L22
*/
type LogEntry struct {
	Address             Address   `json:"address"`
	Topics              []Word    `json:"topics"`
	Data                HexBytes  `json:"data"`
	BlockHash           Hash      `json:"blockHash"`
	BlockNumber         HexUint64 `json:"blockNumber"`
	TransactionHash     Hash      `json:"transactionHash"`
	TransactionIndex    HexUint64 `json:"transactionIndex"`
	LogIndex            HexUint64 `json:"logIndex"`
	TransactionLogIndex HexUint64 `json:"transactionLogIndex"` // Parity only?
	Type                string    `json:"type"`                // Parity only?
	Removed             bool      `json:"removed"`
}

/*
Stand-in for anything representing a block number. Makes the signatures of
RPC functions more readable.

RPC methods in geth and Parity accept block numbers in several formats: a
regular number, a hex-encoded number, or the magic strings "earliest", "latest",
"pending". See the "BlockNumberX" constants.
*/
type BlockNumber interface{}

/*
LogFilter is passed to "EthGetLogs". See
https://wiki.parity.io/JSONRPC-eth-module.html#eth_newfilter for details on log
filtering.

Original definitions in "go-ethereum" and Parity:
https://github.com/ethereum/go-ethereum/blob/0ae462fb80b8a95e38af08d894ea9ecf9e45f2e7/interfaces.go#L133
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/filter.rs#L60
*/
type LogFilter struct {
	FromBlock BlockNumber `json:"fromBlock"` // optional
	ToBlock   BlockNumber `json:"toBlock"`   // optional
	Address   []Address   `json:"address"`

	/**
	"Topics" represent indexed event parameters. For any fixed-size parameter, a
	"topic" is its ABI-encoded representation, which is always Word-sized (32
	bytes). For a variable-sized parameter, a "topic" is its Word-sized hash.
	Note that since hashing loses information, indexed variable-sized parameters
	can't be recovered from topics.

	TODO:
		* add a function to ABI-hash a variable-sized value
		* add a function that marshals/hashes a tuple of arbitrary Go values
		  into topics
	*/
	Topics interface{} `json:"topics"`
	Limit  uint64      `json:"limit,omitempty"` // Parity only?

	// Listed in Parity source, but for some reason rejected by RPC
	// BlockHash Hash        `json:"blockHash"` // optional
}

/*
Specialized variant of "sync.Map": "sync.Map<string, chan BlockHead>".
Useful for block subscriptions and broadcasts.
*/
type BlockHeadChanMap sync.Map

// Specialized variant of "sync.Map.Store".
func (self *BlockHeadChanMap) Store(key string, value chan BlockHead) {
	(*sync.Map)(self).Store(key, value)
}

// Specialized variant of "sync.Map.Delete".
func (self *BlockHeadChanMap) Delete(key string) {
	(*sync.Map)(self).Delete(key)
}

// Specialized variant of "sync.Map.Range".
func (self *BlockHeadChanMap) Range(fun func(string, chan BlockHead) bool) {
	(*sync.Map)(self).Range(func(key, value interface{}) bool {
		return fun(key.(string), value.(chan BlockHead))
	})
}

/*
String256 is a regular string that behaves as "[32]byte" for ABI encoding and
decoding. When encoding, it's interpreted as raw bytes, zero-padded on the
right. If the string is longer than 32 bytes, encoding fails. When decoding, it
takes 32 bytes from the input and truncates them at the first zero byte.

Useful for event parameters. Normally, you can use "string" as an event
parameter, and see this string in event logs. However, marking a string, or any
other variable-sized parameter, as "indexed" causes information loss: it becomes
hashed for filtering, with no way to recover the original string from event
logs. String256 allows you to treat a "bytes32" parameter as a string.

32 bytes is the memory granularity of the EVM. See the comments on Word.
*/
type String256 string

// Implements "AbiMarshaler".
func (self String256) EthAbiMarshal() ([]byte, error) {
	word, err := self.Word()
	if err != nil {
		return nil, err
	}
	return word[:], nil
}

// Implements "AbiUnmarshaler".
func (self *String256) EthAbiUnmarshal(input []byte) error {
	if len(input) < 256/8 {
		return errors.New(lenMismatch(256/8, len(input)))
	}

	length := 256 / 8
	zerolen := strlen(input)
	if zerolen < length {
		length = zerolen
	}

	*self = String256(input[:length+1])
	return nil
}

// Converts to a Word for use in log filtering.
func (self String256) Word() (Word, error) {
	var out Word
	if len(self) > len(out) {
		return out, errors.Errorf(`can't fit string %q into %v bytes`, self, len(out))
	}
	copy(out[:], self)
	return out, nil
}

// Length of a C-style zero-terminated string
func strlen(input []byte) int {
	for i, char := range input {
		if char == 0 {
			return i - 1
		}
	}
	return 0
}

// Input to the Parity-specific RPC method "trace_filter".
type ParityTraceFilterParams struct {
	FromBlock   BlockNumber `json:"fromBlock"`
	ToBlock     BlockNumber `json:"toBlock"`
	FromAddress []Address   `json:"fromAddress"`
	ToAddress   []Address   `json:"toAddress"`
	After       uint64      `json:"after,omitempty"`
	Count       uint64      `json:"count,omitempty"`
}

/*
Output from the Parity-specific RPC method "trace_filter".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L488
*/
type ParityTrace struct {
	// Action variant: "call", "create", "suicide", "reward"
	Type string `json:"type"`

	/**
	https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L377

	One of: ParityCall | ParityCreate | ParityReward | ParitySuicide
	*/
	Action interface{} `json:"action"`

	Result interface{} `json:"result"` // ParityCallResult, ParityCreateResult; mut-ex with Error
	Error  string      `json:"error"`  // mut-ex with Result

	TraceAddress        []uint64 `json:"traceAddress"`
	Subtraces           uint64   `json:"subtraces"`
	TransactionPosition uint64   `json:"transactionPosition"` // optional
	TransactionHash     Hash     `json:"transactionHash"`     // optional
	BlockNumber         uint64   `json:"blockNumber"`
	BlockHash           Hash     `json:"blockHash"`
}

/*
Implements "json.Unmarshaler". Chooses the concrete types for .Action and
.Result based on .Type.
*/
func (self *ParityTrace) UnmarshalJSON(input []byte) error {
	var header struct{ Type string }

	err := json.Unmarshal(input, &header)
	if err != nil {
		return err
	}

	type blank ParityTrace

	// TODO shorten
	switch header.Type {
	case "call":
		var action ParityCall
		var result ParityCallResult
		self.Action = &action
		self.Result = &result
		err := json.Unmarshal(input, (*blank)(self))
		self.Action = action
		self.Result = result
		return err

	case "create":
		var action ParityCreate
		var result ParityCreateResult
		self.Action = &action
		self.Result = &result
		err := json.Unmarshal(input, (*blank)(self))
		self.Action = action
		self.Result = result
		return err

	case "reward":
		var action ParityReward
		self.Action = &action
		err := json.Unmarshal(input, (*blank)(self))
		self.Action = action
		return err

	case "suicide":
		var action ParitySuicide
		self.Action = &action
		err := json.Unmarshal(input, (*blank)(self))
		self.Action = action
		return err
	}

	return json.Unmarshal(input, (*blank)(self))
}

/*
One of the several possible types for "ParityTrace.Action".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L274
*/
type ParityCall struct {
	CallType string   `json:"callType"`
	Gas      *HexInt  `json:"gas"`
	From     Address  `json:"from"`
	To       Address  `json:"to"`
	Value    *HexInt  `json:"value"`
	Input    HexBytes `json:"input"`
}

/*
One of the several possible types for "ParityTrace.Action".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L218
*/
type ParityCreate struct {
	Gas   *HexInt  `json:"gas"`
	From  Address  `json:"from"`
	Value *HexInt  `json:"value"`
	Init  HexBytes `json:"init"`
}

/*
One of the several possible types for "ParityTrace.Action".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L355
*/
type ParitySuicide struct {
	Address       Address `json:"address"`
	RefundAddress Address `json:"refundAddress"`
	Balance       *HexInt `json:"balance"`
}

/*
One of the several possible types for "ParityTrace.Action".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L333
*/
type ParityReward struct {
	Author     Address `json:"author"`
	Value      *HexInt `json:"value"`
	RewardType string  `json:"rewardtype"`
}

/*
One of the several possible types for "ParityTrace.Result".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L401
*/
type ParityCallResult struct {
	GasUsed *HexInt  `json:"gasUsed"`
	Output  HexBytes `json:"output"`
}

/*
One of the several possible types for "ParityTrace.Result".

Original definition:
https://github.com/paritytech/parity-ethereum/blob/1f2426226b99a318da03c2bc261ac7d91e362d0c/rpc/src/v1/types/trace.rs#L420
*/
type ParityCreateResult struct {
	GasUsed *HexInt  `json:"gasUsed"`
	Code    HexBytes `json:"code"`
	Address Address  `json:"address"`
}
