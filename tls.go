package tls

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/libs4go/bcf4go/key"
	"github.com/overlaynetwork/onet-go"
	"github.com/pkg/errors"
)

// Peer .
type Peer struct {
	LocalKey        key.Key
	RemotePublicKey []byte
}

// Transport .
type Transport interface {
	ServerPeer(conn onet.Conn) (*Peer, error)
	ClientPeer(conn onet.Conn) (*Peer, error)
}

type tlsTransport struct {
	sync.RWMutex
	remote   map[string]*Peer
	protocol string
}

func NewTLSTransport(protocol string) *tlsTransport {
	return &tlsTransport{
		remote:   make(map[string]*Peer),
		protocol: protocol,
	}
}

func (transport *tlsTransport) String() string {
	return transport.Protocol()
}

func (transport *tlsTransport) Protocol() string {
	return transport.protocol
}

func (transport *tlsTransport) ServerPeer(conn onet.Conn) (*Peer, error) {

	netAddr, _, err := conn.LocalAddr().ResolveNetAddr()

	if err != nil {
		return nil, err
	}

	transport.RLock()
	defer transport.RUnlock()

	return transport.remote[netAddr.String()], nil
}
func (transport *tlsTransport) ClientPeer(conn onet.Conn) (*Peer, error) {

	netAddr, _, err := conn.RemoteAddr().ResolveNetAddr()

	if err != nil {
		return nil, err
	}

	transport.RLock()
	defer transport.RUnlock()

	return transport.remote[netAddr.String()], nil
}

func (transport *tlsTransport) Client(ctx context.Context, network *onet.OverlayNetwork, addr *onet.Addr, next onet.Next) (onet.Conn, error) {

	var key key.Key

	if !network.Config.Get("tls.key", &key) {
		return nil, errors.Wrap(onet.ErrNotFound, "tls.key config must set")
	}

	tlsConfig, remoteKey, err := newTLSConfig(key)

	if err != nil {
		return nil, err
	}

	underlyConn, err := next()

	if err != nil {
		return nil, err
	}

	netConn, err := onet.FromOnetConn(underlyConn)

	if err != nil {
		return nil, err
	}

	session := tls.Client(netConn, tlsConfig)

	if err := session.Handshake(); err != nil {
		return nil, errors.Wrap(err, "tls handshake error")
	}

	remotePublicKey := <-remoteKey

	transport.Lock()
	defer transport.Unlock()

	transport.remote[addr.String()] = &Peer{
		LocalKey:        key,
		RemotePublicKey: remotePublicKey,
	}

	return onet.ToOnetConn(session, network, addr)
}

func (transport *tlsTransport) Server(ctx context.Context, network *onet.OverlayNetwork, addr *onet.Addr, next onet.Next) (onet.Conn, error) {

	var key key.Key

	if !network.Config.Get("tls.key", &key) {
		return nil, errors.Wrap(onet.ErrNotFound, "tls.key config must set")
	}

	tlsConfig, remoteKey, err := newTLSConfig(key)

	if err != nil {
		return nil, err
	}

	underlyConn, err := next()

	if err != nil {
		return nil, err
	}

	netConn, err := onet.FromOnetConn(underlyConn)

	if err != nil {
		return nil, err
	}

	session := tls.Server(netConn, tlsConfig)

	if err := session.Handshake(); err != nil {
		return nil, errors.Wrap(err, "tls handshake error")
	}

	remotePublicKey := <-remoteKey

	transport.Lock()
	defer transport.Unlock()

	transport.remote[addr.String()] = &Peer{
		LocalKey:        key,
		RemotePublicKey: remotePublicKey,
	}

	return onet.ToOnetConn(session, network, addr)
}

func (transport *tlsTransport) Close(network *onet.OverlayNetwork, addr *onet.Addr, next onet.NextClose) error {
	transport.Lock()
	delete(transport.remote, addr.String())
	transport.Unlock()

	return next()

}

var protocol = &onet.Protocol{Name: "tls"}

func init() {

	if err := onet.RegisterProtocol(protocol); err != nil {
		panic(err)
	}

	if err := onet.RegisterTransport(NewTLSTransport("tls")); err != nil {
		panic(err)
	}
}

// WithKey .
func WithKey(k key.Key) onet.Option {
	return func(config *onet.Config) error {
		return config.Bind("tls.key", k)
	}
}
