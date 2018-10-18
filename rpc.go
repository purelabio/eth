package eth

import (
	"context"
	"encoding/json"
	"math/big"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// Strongly-typed version of the "eth_coinbase" RPC method.
func EthCoinbase(ctx context.Context, trans Trans) (Address, error) {
	var out Address
	err := trans.Call(ctx, &out, "eth_coinbase")
	return out, errors.Wrap(err, `error in "eth_coinbase"`)
}

// Strongly-typed version of the "eth_getBalance" RPC method.
func EthGetBalance(ctx context.Context, trans Trans, addr Address) (*big.Int, error) {
	var out HexInt
	err := trans.Call(ctx, &out, "eth_getBalance", addr)
	return (*big.Int)(&out), errors.Wrap(err, `error in "eth_getBalance"`)
}

// Strongly-typed version of the "eth_gasPrice" RPC method.
func EthGasPrice(ctx context.Context, trans Trans) (*big.Int, error) {
	var out HexInt
	err := trans.Call(ctx, &out, "eth_gasPrice")
	return (*big.Int)(&out), errors.Wrap(err, `error in "eth_gasPrice"`)
}

/*
Strongly-typed version of the "eth_estimateGas" RPC method.

Note that estimating gas is a somewhat slow operation; the remote node will
attempt to execute the transaction against the current block, running EVM code
if required. This can easily take tens of milliseconds, or more.
*/
func EthEstimateGas(ctx context.Context, trans Trans, msg TxMsg) (*big.Int, error) {
	var out HexInt
	err := trans.Call(ctx, &out, "eth_estimateGas", msg)
	return (*big.Int)(&out), errors.Wrap(err, `error in "eth_estimateGas"`)
}

// Strongly-typed version of the "eth_getBlockByHash" RPC method.
func EthGetBlockByHash(ctx context.Context, trans Trans, hash Hash) (BlockHead, error) {
	var out BlockHead
	err := trans.Call(ctx, &out, "eth_getBlockByHash", hash, false)
	return out, errors.Wrap(err, `error in "eth_getBlockByHash"`)
}

/*
Variant of "EthGetBlockByHash" with deduplication and caching. For any given
hash, the corresponding block is fetched no more than once, and ceched forever.

Note: this is implemented only for block hash, not block number. The "hash ↔︎
block" association is unique and immutable, while the "blockNumber ↔︎ block"
association may change when switching between forks.

TODO implement cache pruning based on access timestamp and maybe on memory
pressure. Alternatively, suggest an external mature cache implementation. Until
then, this is basically a memory leak.
*/
func EthGetBlockByHashCached(ctx context.Context, trans Trans, cache *sync.Map, hash Hash) (BlockHead, error) {
	val, _ := cache.LoadOrStore(hash, &blockHeaderCacheEntry{})
	entry := val.(*blockHeaderCacheEntry)

	entry.lock.Lock()
	defer entry.lock.Unlock()

	if entry.IsValid() {
		entry.touched = time.Now()
		return entry.blockHeader, nil
	}

	block, err := EthGetBlockByHash(ctx, trans, hash)
	if err != nil {
		return block, err
	}

	entry.blockHeader = block
	entry.touched = time.Now()
	return block, nil
}

type blockHeaderCacheEntry struct {
	lock        sync.Mutex
	blockHeader BlockHead
	touched     time.Time
}

func (self *blockHeaderCacheEntry) IsValid() bool {
	return !self.touched.IsZero()
}

/*
Strongly-typed version of the "eth_getBlockByNumber" RPC method. The input must
be a number or one of the magic strings; see the "BlockNumber" constants.
*/
func EthGetBlockByNumber(ctx context.Context, trans Trans, num BlockNumber) (BlockHead, error) {
	number := num
	switch num := num.(type) {
	case uint64:
		number = (HexUint64)(num)
	case *big.Int:
		number = (*HexInt)(num)
	}

	var out BlockHead
	err := trans.Call(ctx, &out, "eth_getBlockByNumber", number, false)
	return out, errors.Wrap(err, `error in "eth_getBlockByNumber"`)
}

// Strongly-typed version of the "eth_blockNumber" RPC method.
func EthBlockNumber(ctx context.Context, trans Trans) (*big.Int, error) {
	var out *HexInt
	err := trans.Call(ctx, &out, "eth_blockNumber")
	return (*big.Int)(out), errors.Wrap(err, `error in "eth_blockNumber"`)
}

// Strongly-typed version of the Parity-specific "trace_filter" RPC method.
func TraceFilter(ctx context.Context, trans Trans, params ParityTraceFilterParams) ([]ParityTrace, error) {
	var out []ParityTrace
	err := trans.Call(ctx, &out, "trace_filter", params)
	return out, errors.Wrap(err, `error in "trace_filter"`)
}

/*
Asks the remote node to estimate the gas required for the transaction. Useful
for ensuring that a contract method will succeed regardless of the expense,
instead of trying to manually "guess" a sensible limit. Use with caution.

At present, this is used automatically in some transacting methods, such as
"PersonalSendTx".
*/
func AddEstimates(ctx context.Context, trans Trans, msg TxMsg) (TxMsg, error) {
	// Is this necessary?
	if msg.GasPrice == nil {
		gasPrice, err := EthGasPrice(ctx, trans)
		if err != nil {
			return msg, err
		}
		msg.GasPrice = (*HexInt)(gasPrice)
	}

	// Estimating gas is a somewhat slow operation, but leaving this empty
	// allows transactions to execute with near-infinite gas, and may cause
	// transactions to be spuriously rejected.
	if msg.GasLimit == nil {
		gasLimit, err := EthEstimateGas(ctx, trans, msg)
		if err != nil {
			return msg, err
		}
		msg.GasLimit = (*HexInt)(gasLimit)
	}

	return msg, nil
}

// Strongly-typed version of the "personal_newAccount" RPC method.
func PersonalNewAccount(ctx context.Context, trans Trans, pass string) (Address, error) {
	var out Address
	err := trans.Call(ctx, &out, "personal_newAccount", pass)
	return out, errors.Wrap(err, `error in "personal_newAccount"`)
}

/*
Strongly-typed version of the "personal_sendTransaction" RPC method.
Automatically adds gas estimates.
*/
func PersonalSendTx(ctx context.Context, trans Trans, msg TxMsg, pass string) (Hash, error) {
	msg, err := AddEstimates(ctx, trans, msg)
	if err != nil {
		return Hash{}, errors.Wrap(err, "failed to add gas estimates")
	}

	var hash Hash
	err = trans.Call(ctx, &hash, "personal_sendTransaction", msg, pass)
	return hash, errors.Wrap(err, `error in "personal_sendTransaction"`)
}

/*
Same as "PersonalSendTx", but also waits for the transaction to appear in at
least one new block, via "WaitForTx".
*/
func PersonalSendAndWaitForTx(ctx context.Context, trans Trans, msg TxMsg, pass string) (Hash, error) {
	hash, err := PersonalSendTx(ctx, trans, msg, pass)
	if err != nil {
		return hash, err
	}
	err = WaitForTx(ctx, trans, hash)
	return hash, err
}

/*
Waits until the transaction appears in the blockchain. Useful for confirming
freshly-sent transactions.

TODO: implement fork detection. The current implementation may hang in case of a
chain fork.

TODO: add a similar function that waits for N blocks and has fork detection.
*/
func WaitForTx(ctx context.Context, trans Trans, hash Hash) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Subscribe first, so that we don't miss a block notification if it happens
	// between RPC calls.
	inputs := make(chan []byte, 1)
	errs := gogo(func() error {
		return trans.Subscribe(ctx, inputs, "newHeads")
	})

retry:
	confirmed, err := IsTxConfirmed(ctx, trans, hash)
	if err != nil {
		return err
	}
	if confirmed {
		return nil
	}
	for range inputs {
		goto retry
	}
	return <-errs
}

// Strongly-typed version of the "eth_getTransactionReceipt" RPC method.
func IsTxConfirmed(ctx context.Context, trans Trans, hash Hash) (bool, error) {
	var body json.RawMessage
	err := trans.Call(ctx, &body, "eth_getTransactionReceipt", hash)
	return len(body) > 0, errors.Wrap(err, `error in "eth_getTransactionReceipt"`)
}

// Strongly-typed version of the "eth_getTransactionReceipt" RPC method.
func EthGetTxReceipt(ctx context.Context, trans Trans, hash Hash) (TxReceipt, error) {
	var out TxReceipt
	err := trans.Call(ctx, &out, "eth_getTransactionReceipt", hash)
	return out, errors.Wrap(err, `error in "eth_getTransactionReceipt"`)
}

// Strongly-typed version of the "eth_getTransactionByHash" RPC method.
func EthGetTxByHash(ctx context.Context, trans Trans, hash Hash) (Transaction, error) {
	var out Transaction
	err := trans.Call(ctx, &out, "eth_getTransactionByHash", hash)
	return out, errors.Wrap(err, `error in "eth_getTransactionByHash"`)
}

// Strongly-typed version of the "eth_getLogs" RPC method.
func EthGetLogs(ctx context.Context, trans Trans, filter LogFilter) ([]LogEntry, error) {
	var out []LogEntry
	err := trans.Call(ctx, &out, "eth_getLogs", filter)
	return out, errors.Wrap(err, `error in "eth_getLogs"`)
}

/*
Subscribes to future blocks, sending them over the provided channel. Returns an
error when the context is canceled, or when the connection is interrupted. Does
NOT automatically resubscribe.
*/
func SubscribeToBlockHeads(ctx context.Context, trans Trans, out chan<- BlockHead) error {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		close(out)
	}()

	inputs := make(chan []byte, cap(out))
	errChan := gogo(func() error {
		return trans.Subscribe(ctx, inputs, "newHeads")
	})

	for input := range inputs {
		var value BlockHead
		err := json.Unmarshal(input, &value)
		if err != nil {
			return errors.WithStack(err)
		}
		out <- value
	}
	return <-errChan
}

/*
Shortcut for deploying a contract via "PersonalSendAndWaitForTx", waiting for
the transaction to be confirmed, and retrieving the deployed contract address.
*/
func PersonalDeployContract(ctx context.Context, trans Trans, code []byte, sender Address, pass string) (
	Hash, Address, error,
) {
	msg, err := ContractDeploymentTxMsg(code, sender)
	if err != nil {
		return Hash{}, Address{}, err
	}

	hash, err := PersonalSendAndWaitForTx(ctx, trans, msg, pass)
	if err != nil {
		return hash, Address{}, err
	}

	addr, err := EthContractAddress(ctx, trans, hash)
	return hash, addr, err
}

/*
Formulates a TxMsg that will deploy a contract with the provided code. Exists
mainly for convenience and validation. Returns an error if any of the inputs
appear to be invalid.
*/
func ContractDeploymentTxMsg(code []byte, sender Address) (TxMsg, error) {
	if sender == ZeroAddress {
		return TxMsg{}, errors.New("contract deployment requires a sender address")
	}
	if len(code) == 0 {
		return TxMsg{}, errors.New("contract deployment requires contract code")
	}
	return TxMsg{
		From: sender,
		Data: HexBytes(code),
	}, nil
}

/*
Retrieves the address of the contract found at the given transaction. Returns
an error if the transaction doesn't appear to be a contract deployment.
*/
func EthContractAddress(ctx context.Context, trans Trans, hash Hash) (Address, error) {
	receipt, err := EthGetTxReceipt(ctx, trans, hash)
	if err != nil {
		err = errors.Wrapf(err, `failed to retrieve contract address for transaction %v`, hash)
	} else if receipt.ContractAddress == ZeroAddress {
		err = errors.Errorf(`no contract address found at transaction %v`, hash)
	}
	return receipt.ContractAddress, err
}

/*
Strongly-typed version of the "eth_call" RPC method.

Invokes a "view" or "pure" contract method. In other words, a read-only method
that doesn't create a new transaction. The caller must ABI-pack the "TxMsg.Data"
payload and ABI-unpack the output.
*/
func EthCall(ctx context.Context, trans Trans, msg TxMsg, blockNumber BlockNumber) ([]byte, error) {
	var out HexBytes
	err := trans.Call(ctx, &out, "eth_call", msg, blockNumber)
	return out, errors.Wrap(err, `error in "eth_call"`)
}

// Same as "EthCall", but always uses the latest block number.
func EthCallLatest(ctx context.Context, trans Trans, msg TxMsg) ([]byte, error) {
	return EthCall(ctx, trans, msg, BlockNumberLatest)
}
