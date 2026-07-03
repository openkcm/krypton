package securemem

var NewHandlerRequest = newHandlerRequest

func NewDataCleanupRef(name string, data SecureBytes) *dataCleanupRef {
	return &dataCleanupRef{name: name, data: data}
}
