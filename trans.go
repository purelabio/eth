package eth

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

const jsonRpcVersion = "2.0"

/*
Common interface implemented by RPC transports. Obtained via "Dial" and passed
to the various RPC functions.
*/
type Trans interface {
	/**
	Should make an RPC request and decode the response body into `out`, which
	must be a pointer. Returns a request error or a decoding error.
	*/
	Call(ctx context.Context, out interface{}, method string, params ...interface{}) error

	/**
	Should register a subscription and block until it's finished, sending values
	over the provided channel and returning the error that interrupted it, if
	any. Before returning, should always close the output channel and, if
	possible, send an unsubscribe command to the server.

	In case of non-cancelation error, the caller is expected to wait via
	`.Connected()`, then retry.

	If the channel is full, new values may be dropped. The caller is responsible
	for ensuring the channel has enough space.
	*/
	Subscribe(ctx context.Context, out chan []byte, params ...interface{}) error

	/**
	Should return a channel that becomes closed when the transport is connected.
	Stateless transports such as HTTP should always return a closed channel.
	Persistent transports such as websocket, IPC, TCP: when connected, should
	return a closed channel; when not connected, should return an open channel
	and close it when connected.
	*/
	Connected() chan struct{}
}

/*
Chooses the appropriate transport for the given URL/path. Waits until connected,
if possible. The optional logger is used for background logging, if that's
relevant for the chosen transport.
*/
func Dial(rpcPath string, logger *log.Logger) (Trans, error) {
	rpcUrl, err := url.Parse(rpcPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if rpcUrl.Scheme == "ws" || rpcUrl.Scheme == "wss" {
		return DialWs(*rpcUrl, logger)
	}

	if rpcUrl.Scheme == "http" || rpcUrl.Scheme == "https" {
		return HttpTrans{Url: *rpcUrl}, nil
	}

	return nil, errors.Errorf("unsupported RPC path: %v", rpcPath)
}

// Stateless HTTP transport. Doesn't support subscriptions.
type HttpTrans struct {
	Url url.URL
}

// Since an HTTP transport is "always connected", this returns a channel that's
// always closed.
func (self HttpTrans) Connected() chan struct{} { return alwaysConnected }

var alwaysConnected = func() chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}()

// Makes an RPC call.
func (self HttpTrans) Call(ctx context.Context, out interface{}, method string, params ...interface{}) error {
	var body bytes.Buffer
	err := json.NewEncoder(&body).Encode(rpcRequest{
		Jsonrpc: jsonRpcVersion,
		Id:      randomId(),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	res, err := http.Post(self.Url.String(), "application/json", &body)
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		bytes, _ := ioutil.ReadAll(res.Body)
		return errors.Errorf("RPC error: %s\n%s", res.Status, bytes)
	}

	rpcRes := rpcResponse{Result: out}
	err = json.NewDecoder(res.Body).Decode(&rpcRes)
	if err != nil {
		return errors.Wrap(err, "failed to decode RPC response")
	}
	// Note: `error((*RpcError)(nil)) != nil` !!!
	if rpcRes.Error != nil {
		return errors.WithStack(rpcRes.Error)
	}
	return nil
}

// Not implemented for the HTTP transport. Always returns an error.
func (self HttpTrans) Subscribe(context.Context, chan []byte, ...interface{}) error {
	return errors.New("HTTP RPC transport doesn't support streaming")
}

/*
Stateful websocket transport. Supports RPC calls, subscriptions, and automatic
reconnect. The ".ReconnectInterval" property defaults to 1s, can be modified.
*/
type WsTrans struct {
	Url               url.URL
	Logger            *log.Logger
	ReconnectInterval time.Duration

	connected chan struct{}

	// Unavoidable bottleneck
	writeLock sync.Mutex
	Conn      *websocket.Conn

	// Possibly avoidable bottleneck, TODO revise.
	subLock sync.Mutex
	subs    map[string]chan either
}

/*
Attempts to establish a websocket connection to the RPC node at the given URL.
Waits until the connection is established. Note: this starts a persistent
background loop; for now, there's no way to stop an active websocket transport;
don't make more than you need.
*/
func DialWs(url url.URL, logger *log.Logger) (*WsTrans, error) {
	transport := &WsTrans{
		Url:               url,
		Logger:            logger,
		ReconnectInterval: defaultReconnectInterval,
		connected:         make(chan struct{}),
		subs:              map[string]chan either{},
	}

	err := transport.connect()
	if err != nil {
		return nil, err
	}

	go transport.run()
	return transport, nil
}

func (self *WsTrans) run() {
	for {
		err := self.receiveLoop()
		maybePrintf(self.Logger, "disconnected from %v: %v", self.Url.String(), err)

		for {
			maybePrintf(self.Logger, "waiting before reconnecting to %v", self.Url.String())

			time.Sleep(self.ReconnectInterval)
			err := self.connect()
			if err == nil {
				break
			}

			maybePrintf(self.Logger, "failed to connect to %v: %v", self.Url.String(), err)
		}
	}
}

func (self *WsTrans) connect() error {
	conn, _, err := websocket.DefaultDialer.Dial(self.Url.String(), nil)
	if err != nil {
		return errors.WithStack(err)
	}

	self.Conn = conn
	close(self.connected)

	return nil
}

func (self *WsTrans) receiveLoop() error {
	conn := self.Conn

	defer func() {
		self.connected = make(chan struct{})
		conn.Close()
		self.clearSubs(errors.New("disconnected from RPC server"))
	}()

	/**
	Note: we receive and unmarshal separately. A receiving failure indicates
	a disconnect. An unmarshaling error indicates a malformed message, but
	not necessarily a connection problem.
	*/
	for {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var head struct{ Id string }
		err = json.Unmarshal(payload, &head)
		if err != nil {
			maybePrintf(self.Logger, "failed to decode RPC message from %v: %v", self.Url.String(), err)
			continue
		}

		if len(head.Id) != 0 {
			var body json.RawMessage
			res := rpcResponse{Result: &body}
			err = json.Unmarshal(payload, &res)
			if err != nil {
				maybePrintf(self.Logger, "failed to decode RPC message from %v as a response: %v",
					self.Url.String(), err)
				continue
			}

			// Note: `error((*RpcError)(nil)) != nil` !!!
			if res.Error != nil {
				err = errors.WithStack(res.Error)
			}

			self.dispatchToSub(head.Id, []byte(body), err)
			continue
		}

		// When ID is missing, assume it's a notification:
		// https://www.jsonrpc.org/specification#notification
		var notification rpcNotification
		err = json.Unmarshal(payload, &notification)
		if err != nil {
			maybePrintf(self.Logger, "failed to decode RPC message from %v as a notification: %v",
				self.Url.String(), err)
			continue
		}
		id := notification.Params.Subscription
		val := notification.Params.Result
		self.dispatchToSub(id, val, nil)
	}
}

/*
Returns a channel that becomes closed when the transport is connected. If the
transport is currently connected, the channel is closed.
*/
func (self *WsTrans) Connected() chan struct{} {
	return self.connected
}

// Makes an RPC call.
func (self *WsTrans) Call(ctx context.Context, out interface{}, method string, params ...interface{}) error {
	id := randomId()
	sub := make(chan either, 1)
	self.registerSub(id, sub)
	defer self.unregisterSub(id)

	err := self.send(id, method, params...)
	if err != nil {
		return errors.WithStack(err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case either, _ := <-sub:
		if either.err != nil {
			return either.err
		}
		if either.val == nil {
			return nil
		}
		err := json.Unmarshal(either.val, out)
		return errors.WithStack(err)
	}
}

func (self *WsTrans) send(id string, method string, params ...interface{}) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	err := self.Conn.WriteJSON(rpcRequest{
		Jsonrpc: jsonRpcVersion,
		Id:      id,
		Method:  method,
		Params:  params,
	})
	return errors.WithStack(err)
}

/*
Creates a subscription with the given params, sending raw messages over the
provided channel. The caller is expected to handle decoding on their own.

See https://wiki.parity.io/JSONRPC-eth_pubsub-module.html for details on the
Ethereum subscriptions API.

Returns an error when the context is canceled, or when the connection is
interrupted. Does NOT automatically resubscribe.
*/
func (self *WsTrans) Subscribe(ctx context.Context, out chan []byte, params ...interface{}) error {
	defer close(out)

	var subId string
	err := self.Call(ctx, &subId, "eth_subscribe", params...)
	if err != nil {
		return err
	}
	if subId == "" {
		return errors.New("failed to subscribe: received empty subscription ID")
	}
	defer func() {
		go self.send(randomId(), "eth_unsubscribe", subId)
	}()

	sub := make(chan either, cap(out))
	self.registerSub(subId, sub)
	defer self.unregisterSub(subId)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case either, ok := <-sub:
			if !ok {
				return nil
			}
			if either.err != nil {
				return either.err
			}
			out <- either.val
		}
	}
}

func (self *WsTrans) registerSub(id string, sub chan either) {
	self.subLock.Lock()
	self.subs[id] = sub
	self.subLock.Unlock()
}

func (self *WsTrans) unregisterSub(id string) {
	self.subLock.Lock()
	delete(self.subs, id)
	self.subLock.Unlock()
}

func (self *WsTrans) dispatchToSub(id string, val []byte, err error) {
	self.subLock.Lock()
	sub := self.subs[id]
	self.subLock.Unlock()

	if sub != nil {
		select {
		case sub <- either{val: val, err: err}:
		default:
		}
	}
}

func (self *WsTrans) clearSubs(err error) {
	self.subLock.Lock()
	defer self.subLock.Unlock()

	for _, sub := range self.subs {
		if err != nil {
			select {
			case sub <- either{err: err}:
			default:
			}
		}
		close(sub)
	}
	self.subs = map[string]chan either{}
}

var (
	rnd     = rand.New(rand.NewSource(time.Now().UnixNano()))
	rndLock sync.Mutex
)

// Tens of times faster than "crypto/rand". Is this sufficiently random?
func randomId() string {
	var buf Word
	rndLock.Lock()
	rnd.Read(buf[:])
	rndLock.Unlock()
	return buf.String()
}

func maybePrintf(log *log.Logger, fmt string, args ...interface{}) {
	if log != nil {
		log.Printf(fmt, args...)
	}
}
