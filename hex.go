package eth

import (
	"encoding/hex"

	"github.com/pkg/errors"
)

/*
Similar to "hex.Encode" from "encoding/hex". Writes a hex-encoded string
representing the input into the output buffer, prepending "0x". Requires the
input and output sizes to match exactly. Specifically, the output size must be
"HexEncodedLen(len(input))".
*/
func HexEncodeTo(output []byte, input []byte) error {
	if HexEncodedLen(len(input)) != len(output) {
		return errors.Errorf("hex-encoded output has %d bytes, have space for %d",
			HexEncodedLen(len(input)), len(output))
	}
	output[0] = '0'
	output[1] = 'x'
	hex.Encode(output[2:], input)
	return nil
}

// Version of "HexEncodeTo" that always allocates the output.
func HexEncode(input []byte) []byte {
	out := make([]byte, HexEncodedLen(len(input)))
	err := HexEncodeTo(out, input)
	if err != nil {
		panic(err)
	}
	return out
}

/*
Similar to "hex.Decode" from "encoding/hex". Hex-decodes the input, dropping the
mandatory "0x" prefix, and writes it to the output. Requires the input and
output sizes to match exactly. Specifically, the output size must be
"HexDecodedLen(len(input))".

Empty or nil input is ok.

TODO: don't modify the output when returning an error.
*/
func HexDecodeTo(output []byte, input []byte) error {
	raw, err := drop0x(input)
	if err != nil {
		return err
	}
	if HexDecodedLen(len(input)) != len(output) {
		return errors.Errorf("hex input %s has %d bytes, want %d",
			input, HexDecodedLen(len(input)), len(output))
	}
	_, err = hex.Decode(output, raw)
	return errors.WithStack(err)
}

// Version of "HexDecodeTo" that always allocates the output.
func HexDecode(input []byte) ([]byte, error) {
	output := make([]byte, HexDecodedLen(len(input)))
	err := HexDecodeTo(output, input)
	return output, err
}

// Version of "HexDecode" that panics on error. Convenient for initializing
// global variables.
func MustHexDecode(input []byte) []byte {
	output, err := HexDecode(input)
	if err != nil {
		panic(err)
	}
	return output
}

// Version of "HexDecode" that accepts a string and panics on error. Convenient
// for initializing global variables.
func MustHexParse(input string) []byte {
	return MustHexDecode(stringToBytesUnsafe(input))
}

func drop0x(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if len(input) >= 2 && input[0] == '0' && input[1] == 'x' {
		return input[2:], nil
	}
	return input, errors.Errorf("malformed input %s: missing 0x prefix", input)
}

/*
Similar to "hex.EncodedLen" from "encoding/hex". Takes an unencoded byte count
and returns how many bytes are needed to hex-encode it with the "0x" prefix.
Namely, it returns "(len * 2) + 2".
*/
func HexEncodedLen(len int) int {
	return (len * 2) + 2
}

/*
Similar to "hex.DecodedLen" from "encoding/hex". Takes an encoded byte count,
which must include the "0x" prefix, and returns how many bytes are necessary to
hold the decoded output. Namely, it returns "(len - 2) / 2". Empty input size is
ok and requires zero output.
*/
func HexDecodedLen(len int) int {
	if len < 2 {
		return 0
	}
	return (len - 2) / 2
}

func hexEncodeQuoted(input []byte) []byte {
	out := make([]byte, HexEncodedLen(len(input))+2)
	out[0] = '"'
	HexEncodeTo(out[1:len(out)-1], input)
	out[len(out)-1] = '"'
	return out
}
