package tui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Column represents a single column in a table.
type Column interface {
	// Header returns the header for this column.
	Header() string
	// GetRowValue returns the current value for the given row.
	GetRowValue(row int) string
	// SetRowValue sets the value for the given row.
	SetRowValue(row int, value string)
	// NumRows returns the number of rows for this column.
	NumRows() int
}

// Table takes a set of columns and renders them in the table, leaving empty cells for columns that have fewer rows than
// others.
func Table(columns ...Column) {
	app := tview.NewApplication()
	table := tview.NewTable().
		SetBorders(true)

	// Get our max number of rows.
	maxRows := 0
	for _, col := range columns {
		if col.NumRows() > maxRows {
			maxRows = col.NumRows()
		}
	}

	for r := 0; r < maxRows; r++ {
		for c, col := range columns {
			var cellValue string

			color := tcell.ColorWhite
			if r == 0 {
				color = tcell.ColorYellow
				cellValue = col.Header()

			} else {
				// Minus 1 to account for header value.
				cellValue = col.GetRowValue(r - 1)
			}

			table.SetCell(r, c,
				tview.NewTableCell(cellValue).
					SetTextColor(color).
					SetAlign(tview.AlignCenter))
		}
	}

	var textBak string
	var selectedText string
	var selectedCell *tview.TableCell
	defaultSelectionFunc := func(row int, column int) {
		// We cannot select the header row.
		if row == 0 {
			return
		}

		selectedText = ""
		selectedCell = table.GetCell(row, column)
		textBak = selectedCell.Text
		selectedCell.SetText("")
		selectedCell.SetTextColor(tcell.ColorRed)
		table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			curText := selectedCell.Text

			if event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2 {
				selectedText = curText[:len(curText)-1]
			}

			if event.Key() == tcell.KeyRune {
				selectedText = curText + string(event.Rune())
			}

			 selectedCell.SetText(selectedText)

			return event
		})
		table.SetSelectedFunc(func(row int, column int) {
			// Reset input capture for typing.
			table.SetInputCapture(nil)
			columns[column].SetRowValue(row - 1, selectedText)
			textBak = ""
			selectedCell.SetText(selectedText)
			selectedCell.SetTextColor(tcell.ColorGreen)
		})
	}

	table.Select(0, 0).
		SetFixed(1, 1).
		SetSelectable(true, true).
		SetSelectedFunc(defaultSelectionFunc).
		SetSelectionChangedFunc(func(row int, column int) {
			if selectedCell == nil {
				return
			}
			selectedText = ""
			// Reset input capture for typing.
			table.SetInputCapture(nil)

			if textBak != "" {
				selectedCell.SetText(textBak)
			}
			table.SetSelectedFunc(defaultSelectionFunc)
			selectedCell.SetTextColor(tcell.ColorBlue)

			selectedCell = nil
		})

	if err := app.SetRoot(table, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
