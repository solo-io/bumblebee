package tui

import (
	"context"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/gdamore/tcell/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/pterm/pterm"
	"github.com/rivo/tview"
	"github.com/solo-io/ebpf/pkg/loader"
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

type MapValue struct {
	Hash    uint64
	Entries []loader.KvPair
	Table   *tview.Table
	Index   int
	Type    ebpf.MapType
	Keys    []string
}

var mapOfMaps = make(map[string]MapValue)
var mapMutex = sync.RWMutex{}
var currentIndex int

type App struct {
	Entries   chan loader.MapEntry
	CloseChan chan error

	debug        bool
	tviewApp     *tview.Application
	flex         *tview.Flex
	loader       loader.Loader
	progLocation string
}

func NewApp(debug bool, progLocation string, l loader.Loader) App {
	a := App{
		debug:        debug,
		loader:       l,
		progLocation: progLocation,
	}
	return a
}

var preWatchChan = make(chan struct{})

func (m *App) Run(ctx context.Context, progReader io.ReaderAt) error {
	ctx, cancel := context.WithCancel(ctx)

	var errToReturn error
	closeChan := make(chan error)
	app := tview.NewApplication()
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			cancel()
			errToReturn = <-closeChan
			close(closeChan)
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

	header := tview.NewGrid().SetRows(0).SetColumns(0, 0)

	title := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).SetDynamicColors(true)
	fmt.Fprint(title, titleText)

	infoPanel := tview.NewGrid().SetRows(0, 0, 0, 0, 0, 0, 0, 0, 0).SetColumns(0)
	fillInfoPanel(infoPanel)

	fetchText := tview.NewTextView().SetDynamicColors(true)
	fmt.Fprintf(fetchText, "Program location: [aqua]%s", m.progLocation)
	infoPanel.AddItem(fetchText, 2, 0, 1, 1, 0, 0, false)

	help := tview.NewTextView().SetTextAlign(tview.AlignLeft).SetDynamicColors(true)
	fmt.Fprint(help, helpText)

	rightMenu := tview.NewFlex().SetDirection(tview.FlexColumn)
	rightMenu.AddItem(infoPanel, 0, 1, false)
	rightMenu.AddItem(help, 0, 1, false)

	header.AddItem(title, 0, 0, 1, 1, 0, 0, false)
	header.AddItem(rightMenu, 0, 1, 1, 1, 0, 0, false)

	flex.AddItem(header, 9, 0, false)
	m.Entries = make(chan loader.MapEntry, 20)
	m.tviewApp = app
	m.flex = flex
	m.CloseChan = closeChan

	progOptions := &loader.LoadOptions{
		EbpfProg: progReader,
		Debug:    m.debug,
		Watcher:  m,
	}
	go func() {
		err := m.loader.Load(ctx, progOptions)
		close(m.Entries)
		m.CloseChan <- err
	}()
	<-preWatchChan
	pterm.Info.Println("Rendering TUI...")
	// goroutine for updating the TUI data based on updates from loader watching maps
	go m.Watch()
	// begin rendering the TUI
	if err := m.tviewApp.SetRoot(m.flex, true).Run(); err != nil {
		return err
	}
	m.debugLog("stopped app\n")
	return errToReturn
}

func (a *App) PreWatchHandler() {
	preWatchChan <- struct{}{}
}

func (m *App) Watch() {
	for r := range m.Entries {
		if mapOfMaps[r.Name].Type == ebpf.Hash {
			m.renderHash(r)
		} else if mapOfMaps[r.Name].Type == ebpf.RingBuf {
			m.renderRingBuf(r)
		}
		// update the screen if the UI is still running
		m.tviewApp.Draw()
	}
	fmt.Println("no more entries, closing")
}

func (m *App) renderRingBuf(incoming loader.MapEntry) {
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

func (m *App) renderHash(incoming loader.MapEntry) {
	current := mapOfMaps[incoming.Name]
	if len(current.Entries) == 0 {
		newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		m.debugLog(fmt.Sprintf("empty list, no entries for %v, generated new hash: %v\n", incoming.Entry.Key, newHash))
		incoming.Entry.Hash = newHash
		current.Entries = append(current.Entries, incoming.Entry)
	} else {
		incomingHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		var idx int
		var found = false
		for idx = range current.Entries {
			if current.Entries[idx].Hash == incomingHash {
				m.debugLog(fmt.Sprintf("found existing entry for %v at index '%v' with hash: %v\n", incoming.Entry.Key, idx, incomingHash))
				found = true
				break
			}
		}
		if found {
			if incoming.Entry.Value == current.Entries[idx].Value {
				m.debugLog(fmt.Sprintf("for key %v, current value '%v' at index '%v' matches incoming val '%v', continuing...\n", incoming.Entry.Key, current.Entries[idx].Value, idx, incoming.Entry.Value))
				return
			}
			m.debugLog(fmt.Sprintf("for existing entry for %v at index '%v' updating val to: %v\n", incoming.Entry.Key, idx, incoming.Entry.Value))
			current.Entries[idx].Value = incoming.Entry.Value
		} else {
			newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
			incoming.Entry.Hash = newHash
			m.debugLog(fmt.Sprintf("since no existing entry for %v, appending with hash: %v\n", incoming.Entry.Key, newHash))
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

func (m *App) NewRingBuf(name string, keys []string) {
	m.makeMapValue(name, keys, ebpf.RingBuf)
}

func (m *App) NewHashMap(name string, keys []string) {
	m.makeMapValue(name, keys, ebpf.Hash)
}

func (m *App) SendEntry(entry loader.MapEntry) {
	m.Entries <- entry
}

func (m *App) makeMapValue(name string, keys []string, mapType ebpf.MapType) {
	// get a copy of keys, sort for consistent key/label ordering
	keysCopy := make([]string, len(keys))
	copy(keysCopy, keys)
	sort.Strings(keysCopy)

	// create the array for containing the entries
	entries := make([]loader.KvPair, 0, 10)

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

	m.tviewApp.QueueUpdateDraw(func() {
		m.flex.AddItem(table, 0, 1, false)
		if i == 0 {
			m.tviewApp.SetFocus(table)
		}
	})
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

func fillInfoPanel(infoPanel *tview.Grid) {
	empty0 := tview.NewBox()
	empty1 := tview.NewBox()
	empty3 := tview.NewBox()
	empty4 := tview.NewBox()
	empty5 := tview.NewBox()
	empty6 := tview.NewBox()
	empty7 := tview.NewBox()
	empty8 := tview.NewBox()
	infoPanel.AddItem(empty0, 0, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty1, 1, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty3, 3, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty4, 4, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty5, 5, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty6, 6, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty7, 7, 0, 1, 1, 0, 0, false)
	infoPanel.AddItem(empty8, 8, 0, 1, 1, 0, 0, false)
}

func (m *App) debugLog(text string) {
	if m.debug {
		log.Print(text)
	}
}
