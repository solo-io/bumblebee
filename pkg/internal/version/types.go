package version

type KvPair struct {
	Key   map[string]string `json:"key"`
	Value string            `json:"value"`
}

type MapEntries struct {
	Name    string
	Entries []KvPair
}
