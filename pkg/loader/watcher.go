package loader

type KvPair struct {
	Key   map[string]string
	Value string
	Hash  uint64
}

type MapEntry struct {
	Name  string
	Entry KvPair
}

type MapWatcher interface {
	NewRingBuf(name string, keys []string)
	NewHashMap(name string, keys []string)
	SendEntry(entry MapEntry)
	Close()
}

type noopWatcher struct{}

func (w *noopWatcher) NewRingBuf(name string, keys []string) {
	// noop
}
func (w *noopWatcher) NewHashMap(name string, keys []string) {
	// noop
}
func (w *noopWatcher) SendEntry(entry MapEntry) {
	// noop
}
func (w *noopWatcher) Close() {
	// noop
}

func NewNoopWatcher() *noopWatcher {
	return &noopWatcher{}
}
