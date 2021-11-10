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
			return initialize()
		},
		SilenceUsage: true,
	}

	return cmd
}

func initialize() error {
	_, err := selectLanguageInteractive()
	if err != nil {
		return err
	}

	_, err = selectMapTypeInteractive()
	if err != nil {
		return err
	}

	fileLocation, err := getFileLocation()
	if err != nil {
		return err
	}

	fn, err := os.Create(fileLocation)
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

	pterm.Success.Println("Successfully wrote skeleton BPF program")
	return nil
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
		"Selected Language:",
		supportedLanguages,
	)
}

func selectMapTypeInteractive() (string, error) {
	return selectValueInteractive(
		"What type of map should we initialize",
		"Selected Map Type:",
		supportedMapTypes,
	)
}

func selectValueInteractive(question, success string, options interface{}) (string, error) {
	// Add our info func to the promptui FuncMap
	promptui.FuncMap["info"] = func(data string) string {
		return pterm.Info.Sprintf("%s %s", success, data)
	}

	templates := &promptui.SelectTemplates{
		Selected: "{{ . | info }}",
	}

	prompt := promptui.Select{
		Label:     question,
		Items:     options,
		Templates: templates,
	}
	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return result, nil
}

func getFileLocation() (string, error) {
	templates := &promptui.PromptTemplates{
		Prompt:  "{{ . }} ",
		Success: "{{ . | info }} ",
	}
	prompt := promptui.Prompt{
		Label: "BPF Program File Location",
		// Validate: validate,
		Templates: templates,
	}
	return prompt.Run()

}
