package loader

import (
	"log"

	"github.com/pterm/pterm"
)

type Printer interface {
	Start(text string)
	Success()
	Fail()
	Info(text string)
}

type PrinterFactory interface {
	NewPrinter() (Printer, error)
}

type PTermFactory struct{}

func (f PTermFactory) NewPrinter() (Printer, error) {
	return &ptermPrinter{}, nil
}

type ptermPrinter struct {
	spinner *pterm.SpinnerPrinter
}

func (p *ptermPrinter) Start(text string) {
	spinner, _ := pterm.DefaultSpinner.Start(text)
	p.spinner = spinner
}

func (p *ptermPrinter) Success() {
	p.spinner.Success()
}

func (p *ptermPrinter) Fail() {
	p.spinner.Fail()
}

func (p *ptermPrinter) Info(text string) {
	pterm.Info.Println(text)
}

type LogFactory struct{}

func (f LogFactory) NewPrinter() (Printer, error) {
	return &logPrinter{}, nil
}

type logPrinter struct {
	text string
}

func (p *logPrinter) Start(text string) {
	p.text = text
	log.Println(text)
}

func (p *logPrinter) Success() {
	log.Printf("SUCCESS: %s", p.text)
}

func (p *logPrinter) Fail() {
	log.Printf("FAILURE: %s", p.text)
}

func (p *logPrinter) Info(text string) {
	log.Println(text)
}
