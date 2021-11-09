package initialize // Can't name init because it's a hardcoded const in golang

import (
	"embed"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

//go:embed progs/*
var progs embed.FS

func InitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a sample BPF program",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := selectLanguageInteractive()
			if err != nil {
				return err
			}

			_, err = selectMapTypeInteractive()
			if err != nil {
				return err
			}

			fn, err := os.Create("bpf/example.bpf.c")
			if err != nil {
				return err
			}

			ringBufByt, err := progs.ReadFile("progs/ringbuf.c")
			if err != nil {
				return err
			}

			_, err = fn.Write(ringBufByt)
			if err != nil {
				return err
			}

			pterm.Info.Printfln("Successfully wrote skeleton BPF program to %s:", "bpf/example.bpf.c")

			return nil
		},
		SilenceUsage: true,
	}

	return cmd
}

const (
	languageC = "C"
)

// map of language name to description
var supportedLanguages = []string{
	languageC,
}

var supportedMapTypes = []string{
	"RingBuffer",
}

func selectLanguageInteractive() (string, error) {
	return selectValueInteractive(
		"What language do you wish to use for the filter",
		supportedLanguages,
	)
}

func selectMapTypeInteractive() (string, error) {
	return selectValueInteractive(
		"What type of map should we initialize",
		supportedMapTypes,
	)
}

func selectValueInteractive(message string, options interface{}) (string, error) {
	prompt := promptui.Select{
		Label: message,
		Items: options,
	}
	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return result, nil
}
