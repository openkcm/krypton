package securemem

import "runtime"

var NewHandlerRequest = newHandlerRequest

func NewDataCleanupRef(name string, data SecureBytes) *dataCleanupRef {
	return &dataCleanupRef{name: name, data: data}
}

func CleanUpFunc(d *Data) runtime.Cleanup {
	return d.cleanup
}
