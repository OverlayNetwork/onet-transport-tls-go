module github.com/overlaynetwork/onet-transport-tls-go

go 1.14

require (
	github.com/libs4go/bcf4go v0.0.13
	github.com/overlaynetwork/onet-go v0.0.4
	github.com/overlaynetwork/onet-transport-kcp-go v0.0.0-20200914143241-31fabd85b0df
	github.com/overlaynetwork/onet-transport-mux-go v0.0.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	golang.org/x/sys v0.0.0-20200915050820-6d893a6b696e
)

replace github.com/overlaynetwork/onet-go v0.0.4 => ../onet-go

replace github.com/overlaynetwork/onet-transport-kcp-go => ../onet-transport-kcp-go

replace github.com/overlaynetwork/onet-transport-mux-go => ../onet-transport-mux-go
