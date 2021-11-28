package printer

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/gdamore/tcell/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rivo/tview"
)

const titleText = `[aqua]
 ______     ______     ______   ______   ______     ______   __        
/\  ___\   /\  == \   /\  == \ /\  ___\ /\  ___\   /\__  _\ /\ \       
\ \  __\   \ \  __<   \ \  _-/ \ \  __\ \ \ \____  \/_/\ \/ \ \ \____  
 \ \_____\  \ \_____\  \ \_\    \ \_\    \ \_____\    \ \_\  \ \_____\ 
  \/_____/   \/_____/   \/_/     \/_/     \/_____/     \/_/   \/_____/ 

                              					 [aquamarine](powered by solo.io) `

const helpText = `

[chartreuse]<ctrl-n>   [white]Select next table
[chartreuse]<ctrl-p>   [white]Select previous table
[chartreuse]<ctrl-c>   [white]Quit


`

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

type MapValue struct {
	Hash    uint64
	Entries []KvPair
	Table   *tview.Table
	Index   int
	Type    ebpf.MapType
	Keys    []string
}

var mapOfMaps = make(map[string]MapValue)
var mapMutex = sync.RWMutex{}
var currentIndex int
var running bool
var fetchTextPlaceholder = tview.NewBox()
var fetchText *tview.TextView
var loadTextPlaceholder = tview.NewBox()
var loadText *tview.TextView
var linkTextPlaceholder = tview.NewBox()
var linkText *tview.TextView

type Monitor struct {
	MyChan    chan MapEntry
	App       *tview.Application
	Flex      *tview.Flex
	InfoPanel *tview.Grid
}

func (m *Monitor) SetLinkText(text string) {
	if linkText == nil {
		m.InfoPanel.RemoveItem(linkTextPlaceholder)
		linkText = tview.NewTextView().SetChangedFunc(func() { m.App.Draw() })
		m.InfoPanel.AddItem(linkText, 4, 0, 1, 1, 0, 0, false)
	} else {
		linkText.Clear()
	}
	fmt.Fprint(linkText, text)
}

func (m *Monitor) SetLoadText(text string) {
	if loadText == nil {
		m.InfoPanel.RemoveItem(loadTextPlaceholder)
		loadText = tview.NewTextView().SetChangedFunc(func() { m.App.Draw() })
		m.InfoPanel.AddItem(loadText, 3, 0, 1, 1, 0, 0, false)
	} else {
		loadText.Clear()
	}
	fmt.Fprint(loadText, text)
}

func (m *Monitor) SetFetchText(text string) {
	if fetchText == nil {
		m.InfoPanel.RemoveItem(fetchTextPlaceholder)
		fetchText = tview.NewTextView().SetChangedFunc(func() { m.App.Draw() })
		m.InfoPanel.AddItem(fetchText, 2, 0, 1, 1, 0, 0, false)
	} else {
		fetchText.Clear()
	}
	fmt.Fprint(fetchText, text)
}

func fillInfoPanel(infoPanel *tview.Grid) {
	empty0 := tview.NewBox()
	empty1 := tview.NewBox()
	empty5 := tview.NewBox()
	empty6 := tview.NewBox()
	empty7 := tview.NewBox()
	empty8 := tview.NewBox()
	infoPanel.AddItem(empty0, 0, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty1, 1, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty5, 5, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty6, 6, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty7, 7, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty8, 8, 0, 1, 1, 0, 0, false)
}

func NewMonitor(cancel context.CancelFunc) Monitor {
	app := tview.NewApplication()
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			cancel()
		}
		return event
	})
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlN {
			nextTable(app)
			return nil
		} else if event.Key() == tcell.KeyCtrlP {
			prevTable(app)
			return nil
		}
		return event
	})

	header := tview.NewGrid().SetRows(0).SetColumns(0, 0, 0)
	title := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	fmt.Fprint(title, titleText)

	// infoPanel := tview.NewFlex().SetDirection(tview.FlexRow)
	infoPanel := tview.NewGrid().SetRows(0, 0, 0, 0, 0, 0, 0, 0, 0).SetColumns(0)
	fillInfoPanel(infoPanel)
	infoPanel.AddItem(fetchTextPlaceholder, 2, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(loadTextPlaceholder, 3, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(linkTextPlaceholder, 4, 0, 1, 1, 0, 0, false)

	help := tview.NewTextView().
		SetTextAlign(tview.AlignLeft).SetDynamicColors(true)
	fmt.Fprint(help, helpText)

	header.AddItem(title, 0, 0, 1, 1, 0, 0, false)
	header.AddItem(infoPanel, 0, 1, 1, 1, 0, 0, false)
	header.AddItem(help, 0, 2, 1, 1, 0, 0, false)

	flex.AddItem(header, 9, 0, false)
	// flex.AddItem(tview.NewFlex().
	// 	AddItem(title, 0, 1, false).
	// 	AddItem(tview.NewFlex().
	// 		AddItem(infoPanel, 0, 1, false).
	// 		AddItem(help, 0, 1, false), 0, 1, false), 9, 0, false)

	m := Monitor{
		MyChan:    make(chan MapEntry),
		App:       app,
		Flex:      flex,
		InfoPanel: infoPanel,
	}
	return m
}

func (m *Monitor) Start() {
	go func() {
		running = true
		if err := m.App.SetRoot(m.Flex, true).Run(); err != nil {
			panic(err)
		}
		fmt.Println("stopped app")
		running = false
	}()
	// goroutine for updating the TUI data based on updates from loader watching maps
	go m.Watch()
}

func (m *Monitor) Watch() {
	f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println("This is a test log entry")
	for r := range m.MyChan {
		if mapOfMaps[r.Name].Type == ebpf.Hash {
			m.renderHash(r)
		} else if mapOfMaps[r.Name].Type == ebpf.RingBuf {
			m.renderRingBuf(r)
		}
		// update the screen if the UI is still running
		if running {
			m.App.Draw()
		}
	}
	fmt.Println("no more entries, closing")
}

func (m *Monitor) renderRingBuf(incoming MapEntry) {
	current := mapOfMaps[incoming.Name]
	current.Entries = append(current.Entries, incoming.Entry)

	// update
	mapOfMaps[incoming.Name] = current

	// get the instance of Table we will update
	table := current.Table
	// render the first row containing the keys
	c := 0
	for i, k := range current.Keys {
		cell := tview.NewTableCell(k).SetExpansion(1).SetTextColor(tcell.ColorYellow)
		table.SetCell(0, i, cell)
		c++
	}

	for r, entry := range current.Entries {
		r++ // increment the row index as the 0-th row is taken by the header
		ekMap := entry.Key
		c := 0
		for kk, kv := range current.Keys {
			cell := tview.NewTableCell(ekMap[kv]).SetExpansion(1)
			table.SetCell(r, kk, cell)
			c++
		}
	}
}

func (m *Monitor) renderHash(incoming MapEntry) {
	current := mapOfMaps[incoming.Name]
	if len(current.Entries) == 0 {
		newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		log.Printf("empty list, no entries for %v, generated new hash: %v\n", incoming.Entry.Key, newHash)
		incoming.Entry.Hash = newHash
		current.Entries = append(current.Entries, incoming.Entry)
	} else {
		incomingHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		var idx int
		var found = false
		for idx = range current.Entries {
			if current.Entries[idx].Hash == incomingHash {
				log.Printf("found existing entry for %v at index '%v' with hash: %v\n", incoming.Entry.Key, idx, incomingHash)
				found = true
				break
			}
		}
		if found {
			if incoming.Entry.Value == current.Entries[idx].Value {
				log.Printf("for key %v, current value '%v' at index '%v' matches incoming val '%v', continuing...\n", incoming.Entry.Key, current.Entries[idx].Value, idx, incoming.Entry.Value)
				return
			}
			log.Printf("for existing entry for %v at index '%v' updating val to: %v\n", incoming.Entry.Key, idx, incoming.Entry.Value)
			current.Entries[idx].Value = incoming.Entry.Value
		} else {
			newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
			incoming.Entry.Hash = newHash
			log.Printf("since no existing entry for %v, appending with hash: %v\n", incoming.Entry.Key, newHash)
			current.Entries = append(current.Entries, incoming.Entry)
		}
	}

	// update
	mapOfMaps[incoming.Name] = current

	// get the instance of Table we will update
	table := current.Table
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
	for r, entry := range current.Entries {
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
}

func (m *Monitor) NewRingBuf(name string, keys []string) *tview.Table {
	return m.makeMapValue(name, keys, ebpf.RingBuf)
}

func (m *Monitor) NewHashMap(name string, keys []string) *tview.Table {
	return m.makeMapValue(name, keys, ebpf.Hash)
}

func (m *Monitor) makeMapValue(name string, keys []string, mapType ebpf.MapType) *tview.Table {
	// get a copy of keys, sort for consistent key/label ordering
	keysCopy := make([]string, len(keys))
	copy(keysCopy, keys)
	sort.Strings(keysCopy)

	// create the array for containing the entries
	entries := make([]KvPair, 0, 10)

	table := tview.NewTable().SetFixed(1, 0)
	table.SetBorder(true).SetTitle(name)

	mapMutex.Lock()
	i := len(mapOfMaps)
	entry := MapValue{
		Table:   table,
		Index:   i,
		Type:    mapType,
		Keys:    keysCopy,
		Entries: entries,
	}
	mapOfMaps[name] = entry
	mapMutex.Unlock()

	m.App.QueueUpdateDraw(func() {
		m.Flex.AddItem(table, 0, 1, false)
		if i == 0 {
			m.App.SetFocus(table)
		}
	})
	return table
}

func nextTable(app *tview.Application) {
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

func prevTable(app *tview.Application) {
	if len(mapOfMaps) <= 1 {
		return
	}
	if currentIndex == 0 {
		currentIndex = len(mapOfMaps) - 1
	} else {
		currentIndex--
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
