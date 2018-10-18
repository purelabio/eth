/*
Library for interacting with Ethereum from within a Go program. Compatible with
go-ethereum and Parity.

Used at ShanzhaiCity / Purelab. Visit https://shanzhaicity.com to learn about
what we're doing.

Work in progress. Some RPC methods are missing, but they're trivial to add. Pull
requests are welcome.

Features:

	* Ethereum types

	* RPC transports

	* strongly-typed RPC methods

	* hex encoding and decoding for various types

	* ABI encoding and decoding

	* optional CLI tool for outputting contract ABI definitions as Go code
	  (requires a Solidity compiler)

Why

The "official" Ethereum implementation, "github.com/ethereum/go-ethereum",
includes client packages with similar features. This package exists because
"go-ethereum" didn't meet our standards. Here's some of its problems:

	* Way too large: too many packages, too many dependencies, greatly increases
	  your compilation time.

	* Horrifically bad APIs for everything contract- and ABI-related. Contract
	  deployment is concurrency-unsafe. Method calls are buggy and partially
	  broken, often failing in mysterious ways. ABI encoding and decoding is
	  inaccessible without several layers of unnecessary, poorly over-abstracted
	  OO garbage. Terrible information loss in ABI decoding makes it impossible
	  to serialize an ABI definition. And more.

In contrast, this library consists of just ONE package, has way fewer
dependencies, little impact on compilation or startup time, a much better
API, and works much more reliably.

Types

Interacting with Ethereum over RPC involves transmitting raw bytes, addresses,
hashes, and numbers in a hex-encoded format prefixed with "0x". This package
provides aliases for regular Go types such as []byte, [32]byte, *big.Int,
uint64, specialized for hex encoding and decoding. It also includes types
for various RPC methods.

To avoid potential gotchas, all byte array types such as Address, Hash, and Word
have a special rule: a zero-initialized array is JSON-encoded as "null", not as
"0x0000000000000.....". For consistency, this rule also affects MarshalText,
where an empty array encodes as "". However, the .String() method is unaffected.

RPC

Connect to an Ethereum node:

	myRpcTransport, err := eth.Dial("wss://some-host:8546")

Currently supported transports: HTTP and WebSocket. More may be added on demand.
The WebSocket transport supports automatic reconnect and live subscriptions.

Call RPC methods:

	address, err := eth.EthCoinbase(context.TODO(), myRpcTransport)

The rest of the documentation assumes that you have an active transport.

Contracts

Steps to using an Ethereum smart contract:

	* compile
	* deploy
	* call methods
	* filter event logs

The instructions for each step are below.

Contract Compilation

Obtain the Solidity compiler: https://github.com/ethereum/solidity

The compiler produces EVM code and JSON ABI definitions:

	solc --combined-json=bin,abi --pretty-json MyContract.sol

To bridge Solidity to Go, use the "github.com/purelabio/eth/gen_eth"
subpackage. It generates *.go files with the code and ABI definitions necessary
for deployment and RPC. Install:

	go get -u github.com/purelabio/eth/gen_eth

Generate Go code:

	gen_eth -out=gen.go MyContract.sol:MyContract

This will create a file with the following variables (values elided for brevity):

	var MyContractAbi eth.Abi
	var MyContractCode []byte
	const MyContractAbiJson string
	const MyContractCodeHex string

The rest of this documentation assumes that you have used "gen_eth",
and uses these variables in code examples.

For frequent updates during development, use "go generate":

	//go:generate gen_eth -out=gen.go MyContract.sol:MyContract

For dealing with solc "manually", see "DecodeContractDefs" and "ContractDef".

Contract Deployment

Deploying a contract consists of sending a plain transaction with the contract's
EVM code as the payload, with no receiver or payment other than gas. The sender
becomes the owner.

This package provides a shortcut:

	hash, contractAddress, err := eth.PersonalDeployContract(
		context.TODO(),
		myRpcTransport,
		MyContractCode,
		myCoinbase,
		"",
	)
	// You must save the contract address

Contract ABI

Interacting with smart contracts involves an "application binary interface", or
ABI. This package provides types and functions for ABI-encoding and ABI-decoding
in accordance with the spec:
https://solidity.readthedocs.io/en/develop/abi-spec.html

Using a "view" or "pure" method:

	* use the ABI definition to find the method
	* use the method to marshal the arguments into a "data payload" ([]byte)
	* formulate a transaction message (TxMsg) from the contract address
	  and the data payload
	* invoke the "eth_call" RPC method, receiving the output ([]byte)
	* use the method to unmarshal the output into Go types

Example code (error handling elided for brevity):

	method := MyContractAbi.Function("tokenBalance")

	input, err := method.Marshal(someAddress)

	msg := eth.TxMsg{
		To:   MyContractAddress,
		Data: input,
	}
	output, err := eth.CallLatest(context.TODO(), myRpcTransport, msg)

	var returnValue *big.Int
	err = method.Unmarshal(output, &returnValue)

Using a "mutating" method:

	* use the ABI definition to find the method
	* use the method to marshal the arguments into a "data payload" ([]byte)
	* formulate a transaction message (TxMsg) from the contract address,
	  the data payload, and the optional payment (in wei)
	* invoke the "eth_sendTransaction" or "personal_sendTransaction" RPC method,
	  receiving the transaction hash
	* optionally wait N blocks to "confirm" the transaction

Example code (error handling elided for brevity):

	method := MyContractAbi.Function("depositTokens")

	input, err := method.Marshal(someAddress, someAmount)

	msg := eth.TxMsg{
		To:   MyContractAddress,
		Data: input,
	}
	hash, err := eth.PersonalSendTx(context.TODO(), myRpcTransport, msg, "")

	// Optional
	err = eth.WaitForTx(context.TODO(), myRpcTransport, hash)

Unlike "go-ethereum", this package doesn't hide these steps behind an OO
interface. Such attempts don't lead to robust programs.

ABI encoding and decoding supports most "well-known" EVM and Go types. At
present, component types (tuples) are not yet supported; please open an issue if
you need this functionality. In addition, it has the "AbiMarshaler" and
"AbiUnmarshaler" interfaces, allowing unknown types to provide their own
encoding and decoding implementations.

Cancelation

All network operations accept a context.Context as the first argument. Use
it for cancelation:

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, err := eth.EthCoinbase(ctx, myRpcTransport)

In a web server with "net/http", use the request context, which automatically
cancels when the request is finished:

	address, err := eth.EthCoinbase(req.Context(), myRpcTransport)

TODO

More code examples.

More tests.

Add missing RPC methods.

Reconsider if zero values of array types should JSON-encode as `null`; this can
be surprising and even undesirable when the user wants to actually send
something encoded as "0x000000000000...".

More descriptive RPC errors.

Validate RPC version in received messages.

Consider IPC transport.

Consider TCP transport.

Implement io.Closer for long-lived transports, i.e. WsTrans. Figure out how it
interacts with Transport.Connected(). Probably end up keeping this method out of
the transport interface to avoid bloating it with functionality that's not
supported by every transport. The user can just cast a given transport into
io.Closer.

Add a function that waits N blocks to confirm a transaction. Currently, we
provide a utility that waits for one block, which is often not enough.

*/
package eth
