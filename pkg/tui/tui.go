package tui

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/gdamore/tcell/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rivo/tview"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
)

const titleText = `[aqua] __                                                   
/\ \                                                  
\ \ \____     __     __                               
 \ \ '__'\  /'__'\ /'__'\                      // \   
  \ \ \L\ \/\  __//\  __/                      \\_/ //
   \ \_,__/\ \____\ \____\   ''-.._.-''-.._.. -(||)(')
    \/___/  \/____/\/____/                     '''    

                                  [aquamarine](powered by solo.io)`

const helpText = `[chartreuse]<ctrl-n>   [white]Select next table
[chartreuse]<ctrl-p>   [white]Select previous table
[chartreuse]<ctrl-c>   [white]Quit`

type Filter struct {
	MapName  string
	KeyField string
	Regex    *regexp.Regexp
}

type MapValue struct {
	Hash    uint64
	Entries []loader.KvPair
	Table   *tview.Table
	Index   int
	Type    ebpf.MapType
	Keys    []string
}

type AppOpts struct {
	Loader         loader.Loader
	ProgLocation   string
	Filter         map[string]Filter
	ParsedELF      *loader.ParsedELF
	PrinterFactory loader.PrinterFactory
}

type App struct {
	Entries   chan loader.MapEntry
	CloseChan chan struct{}

	tviewApp       *tview.Application
	flex           *tview.Flex
	loader         loader.Loader
	progLocation   string
	filter         map[string]Filter
	parsedELF      *loader.ParsedELF
	printerFactory loader.PrinterFactory
}

func NewApp(opts *AppOpts) App {
	a := App{
		loader:         opts.Loader,
		progLocation:   opts.ProgLocation,
		filter:         opts.Filter,
		parsedELF:      opts.ParsedELF,
		printerFactory: opts.PrinterFactory,
	}
	return a
}

var mapOfMaps = make(map[string]MapValue)
var mapMutex = sync.RWMutex{}
var currentIndex int
var preWatchChan = make(chan error, 1)

func buildTView(logger *zap.SugaredLogger, cancel context.CancelFunc, closeChan chan struct{}, progLocation string) (*tview.Application, *tview.Flex) {
	app := tview.NewApplication()
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || (event.Key() == tcell.KeyRune && event.Rune() == 'q') {
			logger.Info("captured ctrl-c")
			cancel()
			logger.Info("called cancel()")
			// need to block here until the map watches from Load() are complete
			// so that tview.App doesn't stop before they do, otherwise we get in a deadlock
			// when Watch() attempts to Draw() to a stopped tview.App
			<-closeChan
			logger.Info("received from closeChan")
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

	fetchText := tview.NewTextView().SetDynamicColors(true)
	fmt.Fprintf(fetchText, "Program location: [aqua]%s", progLocation)

	help := tview.NewTextView().SetTextAlign(tview.AlignLeft).SetDynamicColors(true)
	fmt.Fprint(help, helpText)

	rightMenu := tview.NewFlex().SetDirection(tview.FlexRow)
	fetchMenu := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewBox(), 0, 1, false).
		AddItem(fetchText, 0, 1, false).
		AddItem(tview.NewBox(), 0, 1, false)
	fetchMenu.SetBackgroundColor(tcell.ColorBlack)
	rightMenu.AddItem(fetchMenu, 0, 1, false)
	rightMenu.AddItem(help, 0, 1, false)

	header.AddItem(title, 0, 0, 1, 1, 0, 0, false)
	header.AddItem(rightMenu, 0, 1, 1, 1, 0, 0, false)

	flex.AddItem(header, 10, 0, false)

	return app, flex
}

func (a *App) Run(ctx context.Context, progReader io.ReaderAt) error {
	logger := contextutils.LoggerFrom(ctx)
	ctx, cancel := context.WithCancel(ctx)

	var errToReturn error
	closeChan := make(chan struct{}, 1)

	app, flex := buildTView(logger, cancel, closeChan, a.progLocation)
	a.Entries = make(chan loader.MapEntry, 20)
	a.tviewApp = app
	a.flex = flex
	a.CloseChan = closeChan

	loaderOptions := loader.LoadOptions{
		ParsedELF: a.parsedELF,
		Watcher:   a,
	}

	go func() {
		logger.Info("calling loader.Load()")
		errToReturn = a.loader.Load(ctx, &loaderOptions)
		logger.Infof("returned from Load() with err: %s", errToReturn)
		// we have returned from Load(...) so we know the waitgroups on the map watches have completed
		// let's close the Entries chan so a.Watch(...) will return and we will no longer call Draw() on
		// the tview.App
		close(a.Entries)
		logger.Info("closed entries")
		// send to the closeChan to signal in the case the TUI was closed via CtrlC that Load()
		// has returned and no new updates will be sent to the tview.App
		a.CloseChan <- struct{}{}
		// send to the preWatchChan in case Load() returned from an error in the Load/Link phase
		// i.e. not the Watch phase, so we don't block when loader.PreWatchHandler() hasn't been called
		preWatchChan <- errToReturn
		// call Stop() on the tview.App to handle the case where Load() returned with an error
		// safe to call this more than once, i.e. it's ok that CtrlC handler will also Stop() the tview.App
		a.tviewApp.Stop()
		logger.Info("called stop")
	}()

	err := <-preWatchChan
	logger.Infof("received from preWatchChan with err: %s", err)
	if err != nil {
		return err
	}

	// goroutine for updating the TUI data based on updates from loader watching maps
	logger.Info("starting Watch()")
	go a.watch(ctx)

	if a.printerFactory != nil {
		printer, _ := a.printerFactory.NewPrinter()
		printer.Start("Rendering TUI...")
	}
	logger.Info("render tui")
	// begin rendering the TUI
	if err := a.tviewApp.SetRoot(a.flex, true).Run(); err != nil {
		return err
	}

	logger.Infof("stopped app, errToReturn: %s", errToReturn)
	return errToReturn
}

func (a *App) PreWatchHandler() {
	preWatchChan <- nil
}

func (a *App) watch(ctx context.Context) {
	logger := contextutils.LoggerFrom(ctx)
	logger.Info("beginning Watch() loop")
	for r := range a.Entries {
		if mapOfMaps[r.Name].Type == ebpf.Hash {
			a.renderHash(ctx, r)
		} else if mapOfMaps[r.Name].Type == ebpf.RingBuf {
			a.renderRingBuf(ctx, r)
		}
		// update the screen if the UI is still running
		// don't block here as we still want to process entries as they come in,
		// let the tview.App handle the synchronization of updates
		go a.tviewApp.QueueUpdateDraw(func() {})
	}
	logger.Info("no more entries, returning from Watch()")
}

func (a *App) renderRingBuf(ctx context.Context, incoming loader.MapEntry) {
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

func (a *App) renderHash(ctx context.Context, incoming loader.MapEntry) {
	logger := contextutils.LoggerFrom(ctx)
	current := mapOfMaps[incoming.Name]
	if len(current.Entries) == 0 {
		newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		logger.Infof("empty list, no entries for %v, generated new hash: %v\n", incoming.Entry.Key, newHash)
		incoming.Entry.Hash = newHash
		current.Entries = append(current.Entries, incoming.Entry)
	} else {
		incomingHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
		var idx int
		var found = false
		for idx = range current.Entries {
			if current.Entries[idx].Hash == incomingHash {
				logger.Infof("found existing entry for %v at index '%v' with hash: %v\n", incoming.Entry.Key, idx, incomingHash)
				found = true
				break
			}
		}
		if found {
			if incoming.Entry.Value == current.Entries[idx].Value {
				logger.Infof("for key %v, current value '%v' at index '%v' matches incoming val '%v', continuing...\n", incoming.Entry.Key, current.Entries[idx].Value, idx, incoming.Entry.Value)
				return
			}
			logger.Infof("for existing entry for %v at index '%v' updating val to: %v\n", incoming.Entry.Key, idx, incoming.Entry.Value)
			current.Entries[idx].Value = incoming.Entry.Value
		} else {
			newHash, _ := hashstructure.Hash(incoming.Entry.Key, hashstructure.FormatV2, nil)
			incoming.Entry.Hash = newHash
			logger.Infof("since no existing entry for %v, appending with hash: %v\n", incoming.Entry.Key, newHash)
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

func (a *App) NewRingBuf(name string, keys []string) {
	a.makeMapValue(name, keys, ebpf.RingBuf)
}

func (a *App) NewHashMap(name string, keys []string) {
	a.makeMapValue(name, keys, ebpf.Hash)
}

func (a *App) SendEntry(entry loader.MapEntry) {
	if a.filterMatch(entry) {
		a.Entries <- entry
	}
}

func (a *App) makeMapValue(name string, keys []string, mapType ebpf.MapType) {
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

	a.tviewApp.QueueUpdateDraw(func() {
		a.flex.AddItem(table, 0, 1, false)
		if i == 0 {
			a.tviewApp.SetFocus(table)
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
