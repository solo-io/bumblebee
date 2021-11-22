package printer

import (
	"fmt"
	"sort"

	"github.com/gdamore/tcell/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rivo/tview"
	"github.com/solo-io/ebpf/pkg/internal/version"
)

const titleText = ` ______     ______     ______   ______   ______     ______   __        
/\  ___\   /\  == \   /\  == \ /\  ___\ /\  ___\   /\__  _\ /\ \       
\ \  __\   \ \  __<   \ \  _-/ \ \  __\ \ \ \____  \/_/\ \/ \ \ \____  
 \ \_____\  \ \_____\  \ \_\    \ \_\    \ \_____\    \ \_\  \ \_____\ 
  \/_____/   \/_____/   \/_/     \/_/     \/_____/     \/_/   \/_____/ 

                              					(powered by solo.io)  `

type MapValue struct {
	Hash    uint64
	Entries []version.KvPair
	Table   *tview.Table
}

var mapOfMaps = make(map[string]MapValue)

type Monitor struct {
	MyChan chan version.MapEntries
	App    *tview.Application
	Flex   *tview.Flex
}

func NewMonitor() Monitor {
	app := tview.NewApplication()
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	go func() {
		if err := app.SetRoot(flex, true).Run(); err != nil {
			panic(err)
		}
		// ticker := time.NewTicker(1 * time.Second)
		// for range ticker.C {
		// 	app.Draw()
		// }
	}()
	title := tview.NewTextView()
	fmt.Fprint(title, titleText)
	flex.AddItem(title, 10, 0, false)
	return Monitor{
		MyChan: make(chan version.MapEntries),
		App:    app,
		Flex:   flex,
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
		newMapVal := current
		newMapVal.Entries = r.Entries
		newMapVal.Hash = newPrintHash
		mapOfMaps[r.Name] = newMapVal

		entry := r.Entries[0]
		theekMap := entry.Key
		keyStructKeys := []string{}
		for kk := range theekMap {
			keyStructKeys = append(keyStructKeys, kk)
		}
		sort.Strings(keyStructKeys)

		table := newMapVal.Table
		table.ScrollToBeginning().Clear()
		c := 0
		for i, k := range keyStructKeys {
			cell := tview.NewTableCell(k).SetExpansion(1).SetTextColor(tcell.ColorYellow)
			// table.SetCellSimple(0, i, k)
			table.SetCell(0, i, cell)
			c++
		}
		cell := tview.NewTableCell("value").SetExpansion(1).SetTextColor(tcell.ColorYellow)
		table.SetCell(0, c, cell)
		for r, entry := range newMapVal.Entries {
			r++
			ekMap := entry.Key
			eVal := entry.Value
			c := 0
			for kk, kv := range keyStructKeys {
				cell := tview.NewTableCell(ekMap[kv]).SetExpansion(1)
				table.SetCell(r, kk, cell)
				c++
			}
			cell := tview.NewTableCell(eVal).SetExpansion(1)
			table.SetCell(r, c, cell)
		}
		m.App.Draw()

		// print logic
		// printMap := map[string]interface{}{
		// 	"mapName": r.Name,
		// 	"entries": r.Entries,
		// }
		// byt, err := json.Marshal(printMap)
		// if err != nil {
		// 	fmt.Printf("error marshalling map data, this should never happen, %s\n", err)
		// 	continue
		// }
		// fmt.Printf("%s\n", byt)
	}
	fmt.Println("no more entries, closing")
}

func (m *Monitor) NewHashMap(name string) *tview.Table {
	table := tview.NewTable().SetFixed(1, 0)
	table.SetBorder(true).SetTitle(name)
	m.Flex.AddItem(table, 0, 1, false)
	entry := mapOfMaps[name]
	entry.Table = table
	mapOfMaps[name] = entry
	return table
}
