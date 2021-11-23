package printer

import (
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/gdamore/tcell/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rivo/tview"
	"github.com/solo-io/ebpf/pkg/internal/version"
)

const titleText = `[aqua]
 ______     ______     ______   ______   ______     ______   __        
/\  ___\   /\  == \   /\  == \ /\  ___\ /\  ___\   /\__  _\ /\ \       
\ \  __\   \ \  __<   \ \  _-/ \ \  __\ \ \ \____  \/_/\ \/ \ \ \____  
 \ \_____\  \ \_____\  \ \_\    \ \_\    \ \_____\    \ \_\  \ \_____\ 
  \/_____/   \/_____/   \/_/     \/_/     \/_____/     \/_/   \/_____/ 

                              					 [aquamarine](powered by solo.io) `

const helpText = `

[crimson]version:   [white]1337
[crimson]Lorem:     [white]Ipsum
[chartreuse]<ctrl-n>   [white]Cycle through tables


`

type MapValue struct {
	Hash    uint64
	Entries []version.KvPair
	Table   *tview.Table
	Index   int
	Type    ebpf.MapType
	Keys    []string
}

var mapOfMaps = make(map[string]MapValue)
var mapMutex = sync.RWMutex{}
var currentIndex int

type Monitor struct {
	MyChan chan version.MapEntries
	App    *tview.Application
	Flex   *tview.Flex
}

func nextSlide(app *tview.Application) {
	if len(mapOfMaps) <= 1 {
		return
	}
	if currentIndex+1 == len(mapOfMaps) {
		currentIndex = 0
	} else {
		currentIndex++
	}
	mapMutex.RLock()
	for _, v := range mapOfMaps {
		if v.Index == currentIndex {
			app.SetFocus(v.Table)
			return
		}
	}
	mapMutex.RUnlock()
}

func NewMonitor() Monitor {
	app := tview.NewApplication()
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlN {
			nextSlide(app)
			return nil
		}
		// } else if event.Key() == tcell.KeyCtrlP {
		// 	previousSlide()
		// 	return nil
		// }
		return event
	})
	title := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	// SetTextColor(tcell.ColorLightCyan)
	// title.SetBorder(true)
	help := tview.NewTextView().
		SetTextAlign(tview.AlignLeft).SetDynamicColors(true)
	// SetTextColor(tcell.ColorWhite)
	// help.SetBorder(true)
	fmt.Fprint(title, titleText)
	fmt.Fprint(help, helpText)
	flex.AddItem(tview.NewFlex().
		AddItem(title, 0, 1, false).
		AddItem(help, 0, 1, false), 9, 0, false)
	m := Monitor{
		MyChan: make(chan version.MapEntries),
		App:    app,
		Flex:   flex,
	}
	return m
}

func (m *Monitor) Start() {
	go func() {
		if err := m.App.SetRoot(m.Flex, true).Run(); err != nil {
			panic(err)
		}
	}()
	// goroutine for updating the TUI data based on updates from loader watching maps
	go m.Watch()
}

func (m *Monitor) Watch() {
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

		// get the instance of Table we will update
		table := newMapVal.Table
		// render the first row containing the keys
		c := 0
		for i, k := range current.Keys {
			cell := tview.NewTableCell(k).SetExpansion(1).SetTextColor(tcell.ColorYellow)
			table.SetCell(0, i, cell)
			c++
		}
		// last column in first row is value of the map (i.e. the counter/gauge/etc.)
		cell := tview.NewTableCell("value").SetExpansion(1).SetTextColor(tcell.ColorYellow)
		table.SetCell(0, c, cell)

		// now render each row according to the Entries we were sent by the loader
		// TODO: should we sort/order this in any specific way? right now they are
		// simply in iteration order of the underlying BTF map
		for r, entry := range newMapVal.Entries {
			r++ // increment the row index as the 0-th row is taken by the header
			ekMap := entry.Key
			eVal := entry.Value
			c := 0
			for kk, kv := range current.Keys {
				cell := tview.NewTableCell(ekMap[kv]).SetExpansion(1)
				table.SetCell(r, kk, cell)
				c++
			}
			cell := tview.NewTableCell(eVal).SetExpansion(1)
			table.SetCell(r, c, cell)
		}
		// m.App.SetFocus(table)
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

func (m *Monitor) NewRingBuf(name string) *tview.Table {
	mapMutex.Lock()
	table := tview.NewTable().SetFixed(1, 0)
	table.SetBorder(true).SetTitle(name)
	m.Flex.AddItem(table, 0, 1, false)
	i := len(mapOfMaps)
	entry := MapValue{
		Table: table,
		Index: i,
		Type:  ebpf.RingBuf,
	}
	mapOfMaps[name] = entry
	mapMutex.Unlock()
	if i == 0 {
		m.App.SetFocus(table)
	}
	return table
}

func (m *Monitor) NewHashMap(name string, keys []string) *tview.Table {
	keysCopy := make([]string, len(keys))
	copy(keysCopy, keys)
	sort.Strings(keysCopy)
	mapMutex.Lock()
	table := tview.NewTable().SetFixed(1, 0)
	table.SetBorder(true).SetTitle(name)
	m.Flex.AddItem(table, 0, 1, false)
	i := len(mapOfMaps)
	entry := MapValue{
		Table: table,
		Index: i,
		Type:  ebpf.Hash,
		Keys:  keysCopy,
	}
	mapOfMaps[name] = entry
	mapMutex.Unlock()
	if i == 0 {
		m.App.SetFocus(table)
	}
	return table
}
