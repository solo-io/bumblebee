package mapwatcher

type KvPair struct {
	Key   map[string]string
	Value string
	Hash  uint64
}

type MapEntry struct {
	Name  string
	Entry KvPair
}

// MapEventReceiver provides a receiver that handles various map events.
type MapEventReceiver interface {
	NewRingBuf(name string, keys []string)
	NewHashMap(name string, keys []string)
	SendEntry(entry MapEntry)
	Close()
}
