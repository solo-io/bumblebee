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
}

type NoopWatcher struct{}

func (w *NoopWatcher) NewRingBuf(name string, keys []string) {
	// noop
}
func (w *NoopWatcher) NewHashMap(name string, keys []string) {
	// noop
}
func (w *NoopWatcher) SendEntry(entry MapEntry) {
	// noop
}
