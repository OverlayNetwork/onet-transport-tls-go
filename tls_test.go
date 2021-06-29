package tls

import (
	"context"
	"testing"

	"github.com/libs4go/bcf4go/key"
	_ "github.com/libs4go/bcf4go/key/provider" //
	"github.com/overlaynetwork/onet-go"
	_ "github.com/overlaynetwork/onet-transport-kcp-go" //
	_ "github.com/overlaynetwork/onet-transport-mux-go" //
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {

	laddr, err := onet.NewAddr("/ip/127.0.0.1/udp/1812/kcp/tls/mux")

	require.NoError(t, err)

	k, err := key.RandomKey("eth")

	require.NoError(t, err)

	listener, err := onet.Listen(laddr, WithKey(k))

	require.NoError(t, err)

	go func() {

		k, err := key.RandomKey("eth")

		require.NoError(t, err)

		conn, err := onet.Dial(context.Background(), laddr, WithKey(k))

		require.NoError(t, err)

		_, err = conn.Write([]byte("hello"))

		require.NoError(t, err)

		conn, err = onet.Dial(context.Background(), laddr)

		require.NoError(t, err)

		_, err = conn.Write([]byte("world"))

		require.NoError(t, err)
	}()

	conn, err := listener.Accept()

	require.NoError(t, err)

	var buff [10]byte

	n, err := conn.Read(buff[:])

	require.NoError(t, err)

	require.Equal(t, string(buff[:n]), "hello")

	conn, err = listener.Accept()

	require.NoError(t, err)

	require.NotNil(t, conn)

	n, err = conn.Read(buff[:])

	require.NoError(t, err)

	require.Equal(t, string(buff[:n]), "world")

	println(conn.LocalAddr().String(), conn.RemoteAddr().String())
}
