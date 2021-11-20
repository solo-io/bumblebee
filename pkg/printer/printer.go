package printer

import (
	"encoding/json"
	"fmt"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/solo-io/ebpf/pkg/internal/version"
)

type MapValue struct {
	Hash    uint64
	Entries []version.KvPair
}

var mapOfMaps = make(map[string]MapValue)

type Monitor struct {
	MyChan chan version.MapEntries
}

func NewMonitor() Monitor {
	return Monitor{
		MyChan: make(chan version.MapEntries),
	}
}

func (m *Monitor) Watch(_ string) {
	for r := range m.MyChan {
		current := mapOfMaps[r.Name]
		newPrintHash, _ := hashstructure.Hash(r.Entries, hashstructure.FormatV2, nil)
		// Do not print if the data has not changed
		if current.Hash == newPrintHash {
			continue
		}

		// we have new entries, let's track them
		newMapVal := MapValue{
			Entries: r.Entries,
			Hash:    newPrintHash,
		}
		mapOfMaps[r.Name] = newMapVal

		// print
		printMap := map[string]interface{}{
			"mapName": r.Name,
			"entries": r.Entries,
		}
		byt, err := json.Marshal(printMap)
		if err != nil {
			fmt.Printf("error marshalling map data, this should never happen, %s\n", err)
			continue
		}
		fmt.Printf("%s\n", byt)
	}
}
