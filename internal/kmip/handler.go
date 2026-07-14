package kmip

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

// handler wires KMIP operations onto a KeyManager. It is a thin adapter — the
// wire-level dispatch is handled by kmipserver.BatchExecutor.
type handler struct {
	keyManager KeyManager
}

// newHandler returns a kmipserver.RequestHandler that dispatches the Get
// and GetAttributes operations to the given KeyManager.
func newHandler(km KeyManager) kmipserver.RequestHandler {
	h := &handler{keyManager: km}
	exec := kmipserver.NewBatchExecutor()
	exec.Route(kmip.OperationGet, kmipserver.HandleFunc(h.handleGet))
	exec.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(h.handleGetAttributes))
	return exec
}
