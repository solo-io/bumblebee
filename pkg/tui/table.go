package tui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Column represents a single column in a table.
type Column interface {
	// Header returns the header for this column.
	Header() string
	// SetRow sets the row for this column.
	SetRow(row int) string
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
			if c == 0 || r == 0 {
				color = tcell.ColorYellow
				cellValue = col.Header()
			} else {
				// Minus 1 to account for header value.
				cellValue = col.SetRow(r - 1)
			}

			table.SetCell(r, c,
				tview.NewTableCell(cellValue).
					SetTextColor(color).
					SetAlign(tview.AlignCenter))
		}
	}

	table.Select(0, 0).
		SetFixed(1, 1).
		SetSelectable(true, true).
		SetSelectedFunc(func(row int, column int) {
			// textBak := table.GetCell(row, column).Text
			table.GetCell(row, column).SetText("")
		})

	// table.Select(0, 0).SetFixed(1, 1).SetDoneFunc(func(key tcell.Key) {
	// 	if key == tcell.KeyEscape {
	// 		app.Stop()
	// 	}
	// 	if key == tcell.KeyEnter {
	// 		table.SetSelectable(true, true)
	// 	}
	// }).SetSelectedFunc(func(row int, column int) {
	// 	table.GetCell(row, column).SetTextColor(tcell.ColorRed)
	// 	table.SetSelectable(false, false)
	// })
	if err := app.SetRoot(table, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
