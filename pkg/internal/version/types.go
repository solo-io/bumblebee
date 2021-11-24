package version

type KvPair struct {
	Key   map[string]string `json:"key"`
	Value string            `json:"value"`
	Hash  uint64
}

type MapEntries struct {
	Name    string
	Entries []KvPair
}

type MapEntry struct {
	Name  string
	Entry KvPair
}
