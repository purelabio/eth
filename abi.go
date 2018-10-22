package eth

/*
See https://solidity.readthedocs.io/en/develop/abi-spec.html
*/

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

/*
Decodes output from a Solidity compiler. Expects JSON produced by the following
incantation:

	solc --combined-json=abi,bin --optimize

Maps contract identifiers to decoded "ContractDef" values. Each identifier has
the form "filePath:contractName".

Note: check the "github.com/purelabio/eth/gen_eth" subpackage for a
simpler way of dealing with solc.
*/
func ReadContractDefs(src io.Reader) (map[string]ContractDef, error) {
	var input struct {
		Contracts map[string]struct {
			Abi string
			Bin string
		}
	}

	err := json.NewDecoder(src).Decode(&input)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read Solidity output`)
	}

	out := make(map[string]ContractDef, len(input.Contracts))
	for name, inp := range input.Contracts {
		path := strings.SplitN(name, ":", 2)

		def := ContractDef{
			FileName:     path[0],
			ContractName: path[1],
			AbiJson:      inp.Abi,
		}

		err := json.Unmarshal(stringToBytesUnsafe(inp.Abi), &def.Abi)
		if err != nil {
			return nil, errors.Wrap(err, `failed to decode Solidity output`)
		}

		code := stringToBytesUnsafe(inp.Bin)
		buf := make([]byte, hex.DecodedLen(len(code)))
		_, err = hex.Decode(buf, code)
		if err != nil {
			return nil, errors.Wrap(err, `failed to decode Solidity output`)
		}
		def.Code = HexBytes(buf)

		out[name] = def
	}

	return out, nil
}

/*
Decodes output from a Solidity compiler. See ReadContractDefs for details.
*/
func DecodeContractDefs(input []byte) (map[string]ContractDef, error) {
	return ReadContractDefs(bytes.NewReader(input))
}

/*
A structure representing the output of a Solidity compiler for a single
contract. See "ReadContractDefs" for details.
*/
type ContractDef struct {
	FileName     string
	ContractName string
	Abi          Abi
	AbiJson      string
	Code         HexBytes
}

/*
Abi represents method and event definitions of a Solidity contract. It's parsed
from the output of a Solidity compiler. See the subpackage
"github.com/purelabio/eth/gen_eth" for a convenient bridge from
Solidity to Go.

Decoding follows the informal ABI definition in the original C++ source:
https://github.com/ethereum/solidity/blob/f676325d60dbc6c1120ce5a4478f363622c1b1cf/libsolidity/interface/ABI.cpp#L28

See the "AbiMethod" definition.
*/
type Abi []AbiMethod

/*
^^^
Implementation note for later reconsideration. Defining this type as a slice of
method definitions is conceptually simple and corresponds 1-to-1 to the JSON,
allowing reversible deserialization and serialization. The downside is that
looking for function and event definitions requires us to loop through the
slice, comparing each item by name. The obvious alternative, using pre-built
lookup maps, is several times faster, but breaks this nice, reversible
simplicity, and is also dominated by the costs of ABI encoding and decoding.
*/

/*
Parses an ABI definition. The input must be JSON from a Solidity compiler.
Panics on failure. Convenient for initializing global variables on startup:

	var TestAbi = eth.MustParseAbiJson(`[{"name": "test", "type": "", "params": [...]}]`)
*/
func MustParseAbiJson(input string) Abi {
	var abi Abi
	err := abi.UnmarshalJSON(stringToBytesUnsafe(input))
	if err != nil {
		panic(err)
	}
	return abi
}

// Attempts to find the constructor definition. Boolean indicates success or failure.
func (self Abi) MaybeConstructor() (AbiConstructor, bool) {
	for _, entry := range self {
		switch entry := entry.(type) {
		case AbiConstructor:
			return entry, true
		}
	}
	return AbiConstructor{}, false
}

// Returns the constructor definition. Panics if the constructor is not present.
func (self Abi) Constructor() AbiConstructor {
	out, ok := self.MaybeConstructor()
	if !ok {
		panic("constructor not found in ABI definition")
	}
	return out
}

// Attempts to find the method by name. Boolean indicates success or failure.
func (self Abi) MaybeFunction(name string) (AbiFunction, bool) {
	for _, entry := range self {
		switch entry := entry.(type) {
		case AbiFunction:
			if entry.Name == name {
				return entry, true
			}
		}
	}
	return AbiFunction{}, false
}

// Finds the method by name. Panics if not found.
func (self Abi) Function(name string) AbiFunction {
	out, ok := self.MaybeFunction(name)
	if !ok {
		panic(fmt.Sprintf("function %v not found in ABI definition", name))
	}
	return out
}

// Attempts to find the event by name. Boolean indicates success or failure.
func (self Abi) MaybeEvent(name string) (AbiEvent, bool) {
	for _, entry := range self {
		switch entry := entry.(type) {
		case AbiEvent:
			if entry.Name == name {
				return entry, true
			}
		}
	}
	return AbiEvent{}, false
}

// Finds the event by name. Panics if not found.
func (self Abi) Event(name string) AbiEvent {
	out, ok := self.MaybeEvent(name)
	if !ok {
		panic(fmt.Sprintf("event %v not found in ABI definition", name))
	}
	return out
}

/*
Implements "json.Unmarshaler". Decodes a JSON ABI definition produced by a
Solidity compiler. Automatically selects the appropriate data structures for
constructors, functions and events, based on their type.
*/
func (self *Abi) UnmarshalJSON(input []byte) error {
	var chunks []json.RawMessage

	err := json.Unmarshal(input, &chunks)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, chunk := range chunks {
		val, err := unmarshalAbiMethod(chunk)
		if err != nil {
			return err
		}
		*self = append(*self, val)
	}
	return nil
}

func unmarshalAbiMethod(input []byte) (AbiMethod, error) {
	var tag struct{ Type string }

	err := json.Unmarshal(input, &tag)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var out AbiMethod
	switch tag.Type {
	case "constructor":
		var val AbiConstructor
		err = json.Unmarshal(input, &val)
		out = val
	case "function", "":
		var val AbiFunction
		err = json.Unmarshal(input, &val)
		out = val
	case "event":
		var val AbiEvent
		err = json.Unmarshal(input, &val)
		out = val
	default:
		return nil, errors.Errorf("unknown ABI type: %v", tag.Type)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return out, nil
}

/*
Represents one of several possible ABI definitions. Possible types:

	AbiConstructor
	AbiFunction
	AbiEvent
*/
type AbiMethod interface{}

/*
Represents a contract constructor. This typically doesn't appear in JSON ABI
definitions, and is included only for completeness.
*/
type AbiConstructor struct {
	Type            string     `json:"type"` // "constructor"
	Name            string     `json:"name"` // ""
	Inputs          []AbiParam `json:"inputs"`
	Payable         bool       `json:"payable"`
	StateMutability string     `json:"stateMutability"`
}

/*
Represents a contract method. Useful for ABI-encoding arguments and ABI-decoding
return values. Usually obtained via "Abi.Function()".
*/
type AbiFunction struct {
	Type            string     `json:"type"` // "function" | ""
	Name            string     `json:"name"`
	Constant        bool       `json:"constant"`
	Inputs          []AbiParam `json:"inputs"`
	Outputs         []AbiParam `json:"outputs"`
	Payable         bool       `json:"payable"`
	StateMutability string     `json:"stateMutability"`
	Selector        [4]byte    `json:"-"`
}

/*
ABI-encodes the arguments, which must exactly match this method's parameter
signature. Prepends the method's ".Selector". The result should be used as a
transaction payload, i.e. "TxMsg.Data". Returns an error in case of arity or
type mismatch.
*/
func (self AbiFunction) Marshal(args ...interface{}) ([]byte, error) {
	return abiAppendTuple(self.Selector[:], self.Inputs, args)
}

/*
ABI-decodes raw bytes into the provided Go values, which must exactly match this
method's return signature. The outputs must be pointers. Returns an error in
case of arity mismatch, type mismatch, or malformed input.
*/
func (self AbiFunction) Unmarshal(input []byte, outs ...interface{}) error {
	return AbiUnmarshalTuple(input, self.Outputs, outs)
}

/*
Implements "json.Unmarshaler". In addition to parsing the JSON structure, this
precomputes the method's ".Selector", which is used when ABI-encoding arguments
for method calls.
*/
func (self *AbiFunction) UnmarshalJSON(input []byte) error {
	var plain struct {
		Type            string
		Name            string
		Constant        bool
		Inputs          []AbiParam
		Outputs         []AbiParam
		Payable         bool
		StateMutability string
	}

	err := json.Unmarshal(input, &plain)
	if err != nil {
		return err
	}

	sum := AbiParamsChecksum(plain.Name, plain.Inputs)
	*self = AbiFunction{
		Type:            plain.Type,
		Name:            plain.Name,
		Constant:        plain.Constant,
		Inputs:          plain.Inputs,
		Outputs:         plain.Outputs,
		Payable:         plain.Payable,
		StateMutability: plain.StateMutability,
		Selector:        [4]byte{sum[0], sum[1], sum[2], sum[3]},
	}
	return nil
}

/*
Represents a contract event. Useful for filtering and decoding event logs.
Usually obtained via "Abi.Event()".
*/
type AbiEvent struct {
	Type             string     `json:"type"` // "event"
	Name             string     `json:"name"`
	Inputs           []AbiParam `json:"inputs"`
	Anonymous        bool       `json:"anonymous"`
	Selector         Word       `json:"-"`
	IndexedInputs    []AbiParam `json:"-"`
	NonIndexedInputs []AbiParam `json:"-"`
}

/*
Implements "json.Unmarshaler". In addition to parsing the JSON structure, this
precomputes the event's ".Selector", which is used for filtering logs.
*/
func (self *AbiEvent) UnmarshalJSON(input []byte) error {
	var plain struct {
		Type      string
		Name      string
		Inputs    []AbiParam
		Anonymous bool
	}

	err := json.Unmarshal(input, &plain)
	if err != nil {
		return err
	}

	var indexed []AbiParam
	var nonIndexed []AbiParam
	for _, param := range plain.Inputs {
		if param.Indexed {
			indexed = append(indexed, param)
		} else {
			nonIndexed = append(nonIndexed, param)
		}
	}

	*self = AbiEvent{
		Type:             plain.Type,
		Name:             plain.Name,
		Inputs:           plain.Inputs,
		Anonymous:        plain.Anonymous,
		Selector:         bytesToWord(AbiParamsChecksum(plain.Name, plain.Inputs)),
		IndexedInputs:    indexed,
		NonIndexedInputs: nonIndexed,
	}
	return nil
}

/*
Attempts to ABI-decode event parameters from the log entry into the provided
outputs, which must exactly match the event's signature. The outputs must be
pointers. Log entries are usually obtained via "EthGetLogs".

Returns an error in case of event mismatch, arity mismatch, type mismatch, or
malformed input.

Notes on event encoding and indexing:

Both "go-ethereum" and Parity partially lose event information. Instead of
encoding event parameters like any other tuple, they separate indexed and
non-indexed parameters. Non-indexed parameters are encoded as their own tuple,
as if the other parameters don't exist. Indexed parameters are converted into
32-byte "words": fixed-size inputs are ABI-encoded, which involves padding them
to 32 bytes, and presented as-is; variable-sized inputs are hashed, hashes are
truncated to 32 bytes.

The order of topics and parameters in the encoded payload does NOT match the
original order. We have to recover the order by consulting the event definition.

Since hashing loses information, it's impossible to decode a variable-sized
parameter from a log entry. For now, we detect this, abort decoding, and return
an error. In the future, we might attempt to decode as many other parameters as
possible and return a special error indicating that some parameters are invalid.
*/
func (self AbiEvent) UnmarshalLogEntry(input LogEntry, outs ...interface{}) error {
	selector, indexedTopics := input.Topics[0], input.Topics[1:]
	if selector != self.Selector {
		return errors.Errorf(`log entry doesn't appear to contain event %v`, self.Name)
	}

	for i, param := range self.Inputs {
		if param.Indexed && !param.AbiType.IsStaticallySized() {
			return errors.Errorf(
				`can't ABI-decode parameter %v of type %v in event %v: parameter is hashed`,
				i, param.AbiType.Type, self.Name)
		}
	}

	if len(outs) != len(self.Inputs) {
		return errors.Errorf(`parameter/output mismatch in event %v: have %v parameters, found %v outputs`,
			self.Name, len(self.Inputs), len(outs))
	}

	if len(indexedTopics) != len(self.IndexedInputs) {
		return errors.Errorf(`parameter mismatch in event %v: expected %v indexed parameters, found %v`,
			self.Name, len(self.IndexedInputs), len(indexedTopics))
	}

	for t, topic := range indexedTopics {
		var out interface{}
		var param AbiParam

		// Find the matching parameter and its index among all parameters.
		// We need this index for the output.
		for p := range self.Inputs {
			if !self.Inputs[p].Indexed {
				continue
			}
			if t > 0 {
				t--
				continue
			}
			out = outs[p]
			param = self.Inputs[p]
			break
		}

		err := AbiUnmarshal(topic[:], param.AbiType, out)
		if err != nil {
			return err
		}
	}

	outsNonIndexed := make([]interface{}, 0, len(self.NonIndexedInputs))
	for i, param := range self.Inputs {
		if !param.Indexed {
			outsNonIndexed = append(outsNonIndexed, outs[i])
		}
	}

	return AbiUnmarshalTuple(input.Data, self.NonIndexedInputs, outsNonIndexed)
}

/*
Represents a method parameter, method return value, or event parameter.
Part of an ABI definition, used for encoding and decoding.
*/
type AbiParam struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Components []AbiParam `json:"components"`        // tuple type only
	Indexed    bool       `json:"indexed,omitempty"` // event only
	AbiType    AbiType    `json:"-"`
}

// Implements "json.Unmarshaler".
func (self *AbiParam) UnmarshalJSON(input []byte) error {
	var plain struct {
		Type       string
		Components []AbiParam
		Name       string
		Indexed    bool
	}

	err := json.Unmarshal(input, &plain)
	if err != nil {
		return err
	}

	abiType, err := ParseAbiType(plain.Type)
	if err != nil {
		return err
	}

	*self = AbiParam{
		Type:       plain.Type,
		Components: plain.Components,
		Name:       plain.Name,
		Indexed:    plain.Indexed,
		AbiType:    abiType,
	}
	return nil
}

/*
Computes a checksum of a method or event definition. This is an intermediary
step to computing a function identifier (for method calls) or event topic (for
log filtering). This is used internally, and shouldn't be necessary for most
users.
*/
func AbiParamsChecksum(name string, params []AbiParam) []byte {
	var buf []byte

	buf = append(buf, name...)
	buf = append(buf, '(')
	for i, param := range params {
		buf = append(buf, param.Type...)
		if i < len(params)-1 {
			buf = append(buf, ',')
		}
	}
	buf = append(buf, ')')

	hash := sha3.NewLegacyKeccak256()
	hash.Write(buf)
	return hash.Sum(nil)
}

/*
End-biased: if the input it shorter, it's written to the end; if the input is
longer, it's sliced from the end.
*/
func bytesToWord(input []byte) Word {
	var out Word
	if len(input) > len(out) {
		copy(out[:], input[len(input)-len(out):])
	} else {
		copy(out[len(out)-len(input):], input)
	}
	return out
}

/*
Allows a user-defined type to implement its own ABI encoding. Invoked by
ABI-encoding functions.
*/
type AbiMarshaler interface {
	EthAbiMarshal() ([]byte, error)
}

/*
Allows a user-defined type to implement its own ABI decoding. Invoked by
ABI-decoding functions.
*/
type AbiUnmarshaler interface {
	EthAbiUnmarshal([]byte) error
}

/*
Represents a broad category of EVM types. Used internally for ABI encoding and
decoding.
*/
type AbiKind byte

const (
	AbiKindBool AbiKind = iota + 1
	AbiKindUint
	AbiKindInt
	AbiKindAddress
	AbiKindFunction
	AbiKindDenseArray // `string` and all variants of `bytes`
	AbiKindSparseArray
)

// Implements "fmt.Stringer".
func (self AbiKind) String() string {
	switch self {
	case AbiKindBool:
		return "AbiKindBool"
	case AbiKindUint:
		return "AbiKindUint"
	case AbiKindInt:
		return "AbiKindInt"
	case AbiKindAddress:
		return "AbiKindAddress"
	case AbiKindFunction:
		return "AbiKindFunction"
	case AbiKindDenseArray:
		return "AbiKindDenseArray"
	case AbiKindSparseArray:
		return "AbiKindSparseArray"
	default:
		return ""
	}
}

// Details about a concrete EVM type. Used internally for ABI encoding and decoding.
type AbiType struct {
	Type     string
	Kind     AbiKind
	ArrayLen int      // can be 0 when FixedLen == true
	FixedLen bool     // implies Kind == AbiKindDenseArray || Kind == AbiKindSparseArray
	Elem     *AbiType // must be present if Kind == AbiKindSparseArray
}

/*
Determines how many bytes are needed to ABI-encode a value of this type. Returns
-1 for dynamically-sized types. Otherwise, it's a multiple of 32, starting at 0.
*/
func (self AbiType) Size() int {
	switch self.Kind {
	case AbiKindDenseArray:
		if !self.FixedLen {
			return -1
		}
		return abiPaddedLen(self.ArrayLen)
	case AbiKindSparseArray:
		if !self.FixedLen {
			return -1
		}
		size := self.Elem.Size()
		if size >= 0 {
			return size * self.ArrayLen
		}
		return -1
	default:
		return 256 / 8
	}
}

// True if a value of this type has a fixed size and is ABI-encoded inline,
// without a "heap" reference.
func (self AbiType) IsStaticallySized() bool {
	return self.Size() >= 0
}

var (
	abiUintReg       = regexp.MustCompile(`^uint\d*$`)
	abiIntReg        = regexp.MustCompile(`^int\d*$`)
	abiByteArrayReg  = regexp.MustCompile(`^bytes(\d+)$`)
	abiFixedArrayReg = regexp.MustCompile(`^(.+)\[(\d+)\]$`)
	abiArrayReg      = regexp.MustCompile(`^(.+)\[\]$`)
)

/*
Accepts a name of an EVM type, such as "bytes32", "uint256" or "address[12]",
and returns its details as an AbiType. Used internally.
*/
func ParseAbiType(typeName string) (AbiType, error) {
	switch {
	case typeName == "bool":
		return AbiType{Type: typeName, Kind: AbiKindBool}, nil

	case typeName == "address":
		return AbiType{Type: typeName, Kind: AbiKindAddress}, nil

	case typeName == "function":
		return AbiType{Type: typeName, Kind: AbiKindFunction}, nil

	case typeName == "string" || typeName == "bytes":
		return AbiType{Type: typeName, Kind: AbiKindDenseArray}, nil

	case typeName == "byte":
		return AbiType{Type: typeName, Kind: AbiKindDenseArray, ArrayLen: 1, FixedLen: true}, nil

	case abiByteArrayReg.MatchString(typeName):
		match := abiByteArrayReg.FindStringSubmatch(typeName)
		length, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			return AbiType{}, errors.Wrapf(err, `failed to parse %q as Solidity type`, typeName)
		}
		return AbiType{Type: typeName, Kind: AbiKindDenseArray, ArrayLen: int(length), FixedLen: true}, nil

	case abiFixedArrayReg.MatchString(typeName):
		match := abiFixedArrayReg.FindStringSubmatch(typeName)
		length, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			return AbiType{}, errors.Wrapf(err, `failed to parse %q as Solidity type`, typeName)
		}
		elemType, err := ParseAbiType(match[1])
		if err != nil {
			return AbiType{}, errors.Wrapf(err, `failed to parse %q as Solidity type`, typeName)
		}
		return AbiType{Type: typeName, Kind: AbiKindSparseArray, ArrayLen: int(length), FixedLen: true, Elem: &elemType}, nil

	case abiArrayReg.MatchString(typeName):
		match := abiArrayReg.FindStringSubmatch(typeName)
		elemType, err := ParseAbiType(match[1])
		if err != nil {
			return AbiType{}, errors.Wrapf(err, `failed to parse %q as Solidity type`, typeName)
		}
		return AbiType{Type: typeName, Kind: AbiKindSparseArray, Elem: &elemType}, nil

	case abiUintReg.MatchString(typeName):
		return AbiType{Type: typeName, Kind: AbiKindUint}, nil

	case abiIntReg.MatchString(typeName):
		return AbiType{Type: typeName, Kind: AbiKindInt}, nil

	default:
		return AbiType{}, errors.Errorf(`failed to parse %q as Solidity type`, typeName)
	}
}

/*
ABI-encodes an arbitrary Go value, using the provided spec. Returns an error in
case of type mismatch.
*/
func AbiMarshal(atype AbiType, input interface{}) ([]byte, error) {
	return abiAppend(nil, atype, reflect.ValueOf(input))
}

func abiAppend(out []byte, atype AbiType, val reflect.Value) ([]byte, error) {
	val = deref(val)
	input := val.Interface()

	mar, ok := input.(AbiMarshaler)
	if ok {
		chunk, err := mar.EthAbiMarshal()
		return append(out, chunk...), err
	}

	typ := val.Type()

	switch atype.Kind {
	case AbiKindBool:
		if typ.Kind() == reflect.Bool {
			if val.Bool() {
				return append(out, trueWord[:]...), nil
			}
			return append(out, falseWord[:]...), nil
		}
		return out, errors.New(typeMismatch(atype.Type, typ))

	case AbiKindUint:
		switch typ.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return abiAppendUint64(out, val.Uint()), nil
		}

		switch input := input.(type) {
		case *big.Int:
			return abiAppendBigInt(out, input)
		case *HexInt:
			return abiAppendBigInt(out, (*big.Int)(input))
		}

		if typ.ConvertibleTo(bigIntPtrType) {
			return abiAppendBigInt(out, val.Convert(bigIntPtrType).Interface().(*big.Int))
		}

		return out, errors.New(typeMismatch(atype.Type, typ))

	case AbiKindInt:
		switch typ.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return abiAppendInt64(out, val.Int()), nil
		}

		switch input := input.(type) {
		case *big.Int:
			return abiAppendBigInt(out, input)
		case *HexInt:
			return abiAppendBigInt(out, (*big.Int)(input))
		}

		if typ.ConvertibleTo(bigIntPtrType) {
			return abiAppendBigInt(out, val.Convert(bigIntPtrType).Interface().(*big.Int))
		}

		return out, errors.New(typeMismatch(atype.Type, typ))

	case AbiKindAddress:
		switch input := input.(type) {
		case Address:
			return appendLeftPadded(out, input[:]), nil
		}

		if typ.ConvertibleTo(addressType) {
			input := val.Convert(addressType).Interface().(Address)
			return appendLeftPadded(out, input[:]), nil
		}

		return out, errors.New(typeMismatch(atype.Type, typ))

	case AbiKindFunction:
		switch input := input.(type) {
		case solFunc:
			return appendRightPadded(out, input[:]), nil
		}

		if typ.ConvertibleTo(functionType) {
			input := val.Convert(functionType).Interface().(Address)
			return appendRightPadded(out, input[:]), nil
		}

		return out, errors.New(typeMismatch(atype.Type, typ))

	case AbiKindDenseArray:
		if atype.FixedLen {
			length := atype.ArrayLen
			if typ.Kind() == reflect.Array &&
				typ.Elem().Kind() == reflect.Uint8 &&
				typ.Len() == length {
				slice := reflect.MakeSlice(byteSliceType, length, length)
				reflect.Copy(slice, val)
				return appendRightPadded(out, slice.Bytes()), nil
			}
			return out, errors.New(typeMismatch(atype.Type, typ))
		}

		var input []byte

		if val.Kind() == reflect.String {
			input = stringToBytesUnsafe(val.String())
		} else if inp, ok := val.Interface().([]byte); ok {
			input = inp
		} else if inp, ok := val.Interface().(HexBytes); ok {
			input = []byte(inp)
		} else if typ.ConvertibleTo(byteSliceType) {
			input = val.Convert(byteSliceType).Bytes()
		} else {
			return out, errors.New(typeMismatch(atype.Type, typ))
		}

		out = abiAppendInt64(out, int64(len(input)))
		return appendRightPadded(out, input), nil

	case AbiKindSparseArray:
		// Note: for sparse arrays, this is element count, not byte count
		var length int
		if atype.FixedLen {
			length = atype.ArrayLen
			if !(typ.Kind() == reflect.Array && typ.Len() == length) {
				return out, errors.New(typeMismatch(atype.Type, typ))
			}
		} else {
			if typ.Kind() != reflect.Slice {
				return out, errors.New(typeMismatch(atype.Type, typ))
			}
			length = val.Len()
			out = abiAppendInt64(out, int64(length))
		}

		if atype.Elem.IsStaticallySized() {
			for i := 0; i < length; i++ {
				var err error
				out, err = abiAppend(out, *atype.Elem, val.Index(i))
				if err != nil {
					return out, err
				}
			}
			return out, nil
		}

		var buf []byte
		var heap []byte
		heapOffset := length * (256 / 8)

		for i := 0; i < length; i++ {
			buf = buf[:]
			buf, err := abiAppend(buf, *atype.Elem, val.Index(i))
			if err != nil {
				return out, err
			}
			out = abiAppendInt64(out, int64(heapOffset))
			heap = append(heap, buf...)
			heapOffset += len(buf)
		}

		out = append(out, heap...)
		return out, nil

	default:
		return out, errors.New(typeMismatch(atype.Type, typ))
	}
}

var (
	bigMaxUint8  = new(big.Int).SetUint64(math.MaxUint8)
	bigMaxUint16 = new(big.Int).SetUint64(math.MaxUint16)
	bigMaxUint32 = new(big.Int).SetUint64(math.MaxUint32)
	bigMaxUint64 = new(big.Int).SetUint64(math.MaxUint64)

	bigMaxInt8  = big.NewInt(math.MaxInt8)
	bigMaxInt16 = big.NewInt(math.MaxInt16)
	bigMaxInt32 = big.NewInt(math.MaxInt32)
	bigMaxInt64 = big.NewInt(math.MaxInt64)

	bigMinInt8  = big.NewInt(math.MinInt8)
	bigMinInt16 = big.NewInt(math.MinInt16)
	bigMinInt32 = big.NewInt(math.MinInt32)
	bigMinInt64 = big.NewInt(math.MinInt64)
)

/*
ABI-decodes arbitrary data into a Go value, using the provided spec. The output
must be a pointer. Returns an error in case of type mismatch or malformed input.
*/
func AbiUnmarshal(input []byte, atype AbiType, out interface{}) error {
	un, ok := out.(AbiUnmarshaler)
	if ok {
		return un.EthAbiUnmarshal(input)
	}

	val := reflect.ValueOf(out)
	typ := val.Type()
	if typ.Kind() != reflect.Ptr {
		return errors.Errorf(`can't unmarshal into non-pointer of type %v`, typ)
	}
	val = val.Elem()
	if !val.CanSet() {
		return errors.Errorf(`can't unmarshal into non-settable value of type %v`, typ)
	}
	typ = val.Type()

	switch atype.Kind {
	case AbiKindBool:
		if typ.Kind() == reflect.Bool {
			for i, char := range input[:(256/8)-1] {
				if char != 0 {
					return errors.Errorf("malformed bool input: byte %#02x at index %v of 255", char, i)
				}
			}
			char := input[(256/8)-1]
			switch char {
			case 0:
				val.SetBool(false)
			case 1:
				val.SetBool(true)
			default:
				return errors.Errorf("malformed bool input: byte %#02x in last position", char)
			}
			return nil
		}
		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindUint:
		num := new(big.Int).SetBytes(input)

		switch typ.Kind() {
		case reflect.Uint:
			return errors.New(`can't unmarshal into non-portable type "uint", please use a fixed-size type`)
		case reflect.Uint8:
			if num.Cmp(bigMaxUint8) == 1 {
				return errors.Errorf("%v overflows uint8", num)
			}
			val.SetUint(num.Uint64())
			return nil
		case reflect.Uint16:
			if num.Cmp(bigMaxUint16) == 1 {
				return errors.Errorf("%v overflows uint16", num)
			}
			val.SetUint(num.Uint64())
			return nil
		case reflect.Uint32:
			if num.Cmp(bigMaxUint32) == 1 {
				return errors.Errorf("%v overflows uint32", num)
			}
			val.SetUint(num.Uint64())
			return nil
		case reflect.Uint64:
			if num.Cmp(bigMaxUint64) == 1 {
				return errors.Errorf("%v overflows uint64", num)
			}
			val.SetUint(num.Uint64())
			return nil
		}

		if abiMaybeSetBigInt(val, num) {
			return nil
		}
		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindInt:
		neg := input[0]&0x80 != 0
		input[0] &^= 0x80
		num := new(big.Int).SetBytes(input)
		if neg {
			num.Neg(num)
		}

		switch typ.Kind() {
		case reflect.Int:
			return errors.New(`can't unmarshal into non-portable type "int", please use a fixed-size type`)
		case reflect.Int8:
			if num.Cmp(bigMaxInt8) == 1 {
				return errors.Errorf("%v overflows int8", num)
			}
			if num.Cmp(bigMinInt8) == -1 {
				return errors.Errorf("%v underflows int8", num)
			}
			val.SetInt(num.Int64())
			return nil
		case reflect.Int16:
			if num.Cmp(bigMaxInt16) == 1 {
				return errors.Errorf("%v overflows int16", num)
			}
			if num.Cmp(bigMinInt16) == -1 {
				return errors.Errorf("%v underflows int16", num)
			}
			val.SetInt(num.Int64())
			return nil
		case reflect.Int32:
			if num.Cmp(bigMaxInt32) == 1 {
				return errors.Errorf("%v overflows int32", num)
			}
			if num.Cmp(bigMinInt32) == -1 {
				return errors.Errorf("%v underflows int32", num)
			}
			val.SetInt(num.Int64())
			return nil
		case reflect.Int64:
			if num.Cmp(bigMaxInt64) == 1 {
				return errors.Errorf("%v overflows int64", num)
			}
			if num.Cmp(bigMinInt64) == -1 {
				return errors.Errorf("%v underflows int64", num)
			}
			val.SetInt(num.Int64())
			return nil
		}

		if abiMaybeSetBigInt(val, num) {
			return nil
		}
		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindAddress:
		if typ.Kind() == reflect.Array &&
			typ.Elem().Kind() == reflect.Uint8 &&
			typ.Len() == len(Address{}) {
			var addr Address
			copy(addr[:], input[32-20:32])
			val.Set(reflect.ValueOf(addr))
			return nil
		}
		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindFunction:
		if typ.Kind() == reflect.Array &&
			typ.Elem().Kind() == reflect.Uint8 &&
			typ.Len() == len(solFunc{}) {
			var fun solFunc
			copy(fun[:], input)
			val.Set(reflect.ValueOf(fun))
			return nil
		}
		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindDenseArray:
		if atype.FixedLen {
			length := atype.ArrayLen
			if typ.Kind() == reflect.Array &&
				typ.Elem().Kind() == reflect.Uint8 &&
				typ.Len() == length {
				if len(input) < length {
					return errors.New(lenMismatch(length, len(input)))
				}
				reflect.Copy(val, reflect.ValueOf(input[:length]))
				return nil
			}
			return errors.New(typeMismatch(atype.Type, typ))
		}

		if len(input) < 256/8 {
			return errors.New(lenMismatch(256/8, len(input)))
		}

		length := int(binary.BigEndian.Uint64(input[(256/8)-(64/8) : 256/8]))
		offset := 256 / 8
		body := input[offset : offset+length]

		if typ.Kind() == reflect.String {
			val.SetString(string(body))
			return nil
		}

		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			val.SetBytes(body)
			return nil
		}

		return errors.New(typeMismatch(atype.Type, typ))

	case AbiKindSparseArray:
		// Note: for sparse arrays, this is element count, not byte count
		var length int
		var offset int
		var storage reflect.Value

		if atype.FixedLen {
			length = atype.ArrayLen
			offset = 0
			storage = val
			if !(typ.Kind() == reflect.Array && typ.Len() == length) {
				return errors.New(typeMismatch(atype.Type, typ))
			}
		} else {
			if typ.Kind() != reflect.Slice {
				return errors.New(typeMismatch(atype.Type, typ))
			}
			length = int(binary.BigEndian.Uint64(input[(256/8)-(64/8) : 256/8]))
			offset = 256 / 8
			storage = reflect.MakeSlice(typ, length, length)
		}

		esize := atype.Elem.Size()

		if esize >= 0 {
			for i := 0; i < length; i++ {
				if len(input) < offset+esize {
					return errors.New(lenMismatch(offset+esize, len(input)))
				}
				err := AbiUnmarshal(input[offset:offset+esize], *atype.Elem, storage.Index(i).Addr().Interface())
				if err != nil {
					return err
				}
				offset += esize
			}
		} else {
			input := input[offset:]
			offset := 0
			for i := 0; i < length; i++ {
				next := offset + 256/8
				if len(input) < next {
					return errors.New(lenMismatch(next, len(input)))
				}

				heapOffset := int(binary.BigEndian.Uint64(input[next-(64/8) : next]))
				if len(input) < heapOffset {
					return errors.New(lenMismatch(heapOffset, len(input)))
				}

				err := AbiUnmarshal(input[heapOffset:], *atype.Elem, storage.Index(i).Addr().Interface())
				if err != nil {
					return err
				}
				offset = next
			}
		}

		if storage != val {
			val.Set(storage)
		}

		return nil
	}

	return errors.New(typeMismatch(atype.Type, typ))
}

func abiMaybeSetBigInt(val reflect.Value, num *big.Int) bool {
	typ := val.Type()
	switch {
	case typ == bigIntType:
		val.Set(reflect.ValueOf(*num))
	case bigIntType.ConvertibleTo(typ):
		val.Set(reflect.ValueOf(*num).Convert(typ))
	case typ == bigIntPtrType:
		val.Set(reflect.ValueOf(num))
	case bigIntPtrType.ConvertibleTo(typ):
		val.Set(reflect.ValueOf(num).Convert(typ))
	default:
		return false
	}
	return true
}

/*
ABI-encodes multiple values, typically parameters to a method call. Returns an
error in case of arity mismatch, type mismatch, or malformed input.
*/
func AbiMarshalTuple(params []AbiParam, args ...interface{}) ([]byte, error) {
	return abiAppendTuple(nil, params, args)
}

func abiAppendTuple(out []byte, params []AbiParam, inputs []interface{}) ([]byte, error) {
	if len(params) != len(inputs) {
		return out, errors.Errorf(`arity mismatch: expected %v inputs, got %v`, len(params), len(inputs))
	}

	heapOffset := 0
	for _, param := range params {
		size := param.AbiType.Size()
		if size >= 0 {
			heapOffset += size
		} else {
			heapOffset += 256 / 8
		}
	}

	var buf []byte
	var heap []byte

	for i, param := range params {
		buf = buf[:]
		buf, err := abiAppend(buf, param.AbiType, deref(reflect.ValueOf(inputs[i])))
		if err != nil {
			return out, errors.Wrapf(err, `failed to encode param %v of type %q`, i, param.Type)
		}

		if len(buf)%(256/8) != 0 {
			return out, errors.Errorf(`internal error while encoding param %v of type %q: expected output to be %v-byte-aligned, found length %v`, i, param.Type, 256/8, len(buf))
		}

		size := param.AbiType.Size()
		if size >= 0 {
			if len(buf) != size {
				return out, errors.Errorf(`internal error while encoding param %v of type %q: expected output size to be %v bytes, found %v bytes`, i, param.Type, size, len(buf))
			}
			out = append(out, buf...)
		} else {
			out = abiAppendInt64(out, int64(heapOffset))
			heap = append(heap, buf...)
			heapOffset += len(buf)
		}
	}

	return append(out, heap...), nil
}

/*
ABI-decodes multiple values, typically return values from a method call, or
event parameters. The outputs must be pointers. Returns an error in case of
arity mismatch, type mismatch, or malformed input.
*/
func AbiUnmarshalTuple(input []byte, params []AbiParam, outs []interface{}) error {
	paramOffset := 0

	for i, param := range params {
		size := param.AbiType.Size()
		if size >= 0 {
			paramEnd := paramOffset + size
			if len(input) < paramEnd {
				return errors.New(lenMismatch(paramEnd, len(input)))
			}
			err := AbiUnmarshal(input[paramOffset:paramEnd], param.AbiType, outs[i])
			if err != nil {
				return errors.Wrapf(err, `failed to unmarshal param %v of type %q`, i, param.Type)
			}
			paramOffset += size
			continue
		}

		if len(input) < paramOffset+256/8 {
			return errors.New(lenMismatch(paramOffset+(256/8), len(input)))
		}

		head := input[paramOffset+(256/8)-(64/8) : paramOffset+(256/8)]
		heapOffset := int(binary.BigEndian.Uint64(head))

		err := AbiUnmarshal(input[heapOffset:], param.AbiType, outs[i])
		if err != nil {
			return errors.Wrapf(err, `failed to unmarshal param %v of type %q`, i, param.Type)
		}
		paramOffset += size
	}
	return nil
}

var (
	bigIntType    = reflect.TypeOf(big.Int{})
	bigIntPtrType = reflect.TypeOf((*big.Int)(nil))
	addressType   = reflect.TypeOf(Address{})
	functionType  = reflect.TypeOf(solFunc{})
	byteSliceType = reflect.TypeOf([]byte(nil))
)

type solFunc = [24]byte

func typeMismatch(expected string, actual reflect.Type) string {
	return fmt.Sprintf(`type mismatch: Solidity type %q, Go type %q`, expected, actual)
}

func lenMismatch(expected, actual int) string {
	return fmt.Sprintf(`length mismatch: expected at least %v bytes, got %v`, expected, actual)
}

func abiPaddedLen(length int) int {
	if length <= 0 {
		return length
	}
	return (length + (256 / 8) - 1) / (256 / 8) * (256 / 8)
}

func abiPaddingDelta(length int) int {
	if length <= 0 {
		return 0
	}
	return abiPaddedLen(length) - length
}

var (
	zeros32 [8]byte

	ones32 = func() [8]byte {
		var buf [8]byte
		for i := range buf {
			buf[i] = ^byte(0)
		}
		return buf
	}()
)

func appendLeftPadded(out []byte, buf []byte) []byte {
	delta := abiPaddingDelta(len(buf))
	for delta > 0 {
		out = append(out, 0)
		delta--
	}
	return append(out, buf...)
}

func appendRightPadded(out []byte, buf []byte) []byte {
	out = append(out, buf...)
	delta := abiPaddingDelta(len(buf))
	for delta > 0 {
		out = append(out, 0)
		delta--
	}
	return out
}

func abiAppendUint64(out []byte, num uint64) []byte {
	out = append(out, zeros32[:]...)
	out = append(out, zeros32[:]...)
	out = append(out, zeros32[:]...)
	out = append(out, zeros32[:]...)
	binary.BigEndian.PutUint64(out[len(out)-64/8:], num)
	return out
}

func abiAppendInt64(out []byte, num int64) []byte {
	if num < 0 {
		out = append(out, ones32[:]...)
		out = append(out, ones32[:]...)
		out = append(out, ones32[:]...)
		out = append(out, zeros32[:]...)
	} else {
		out = append(out, zeros32[:]...)
		out = append(out, zeros32[:]...)
		out = append(out, zeros32[:]...)
		out = append(out, zeros32[:]...)
	}
	// Note: uint64(int64) reinterprets the bytes as-is.
	binary.BigEndian.PutUint64(out[len(out)-64/8:], uint64(num))
	return out
}

var (
	trueWord = func() Word {
		var out Word
		out[len(out)-1] = 1
		return out
	}()
	falseWord Word
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// Has avoidable allocations, TODO improve.
func abiAppendBigInt(out []byte, num *big.Int) ([]byte, error) {
	var word Word

	neg := num.Cmp(bigZero) < 0
	if neg {
		num = new(big.Int).Add(num, bigOne)
	}

	slice := num.Bytes()
	if len(slice) > len(word) ||
		// If the top bit is used for the natural number, we can't use it for
		// the int256's sign.
		len(slice) == len(word) && ((slice[0]&0x80) != 0) {
		return out, errors.Errorf("%v overflows int256", num.String())
	}

	copy(word[len(word)-len(slice):], slice)
	if neg {
		uints := (*[256 / 8 / 8]uint64)(unsafe.Pointer(&word))
		uints[0] = ^uints[0]
		uints[1] = ^uints[1]
		uints[2] = ^uints[2]
		uints[3] = ^uints[3]
	}

	return append(out, word[:]...), nil
}

func deref(val reflect.Value) reflect.Value {
	for val.Type().Kind() == reflect.Ptr && !val.Type().ConvertibleTo(bigIntPtrType) {
		val = val.Elem()
	}
	return val
}
