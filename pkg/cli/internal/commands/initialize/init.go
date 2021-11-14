package initialize // Can't name init because it's a hardcoded const in golang

import (
	"bytes"
	"os"
	"text/template"

	"github.com/manifoldco/promptui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type InitOptions struct {
	Language   string
	MapType    string
	FilePath   string
	OutputType string
}

func addToFlags(flags *pflag.FlagSet, opts *InitOptions) {
	flags.StringVarP(&opts.Language, "languague", "l", "", "Language to use for the bpf program")
	flags.StringVarP(&opts.MapType, "map", "m", "", "Map type to initialize")
	flags.StringVarP(&opts.FilePath, "file", "f", "", "File to create skeleton in")
	flags.StringVarP(&opts.OutputType, "output-type", "o", "", "The output type for your map")

}
func Command() *cobra.Command {
	opts := &InitOptions{}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a sample BPF program",
		RunE: func(cmd *cobra.Command, args []string) error {
			return initialize(opts)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), opts)

	return cmd
}

func initialize(opts *InitOptions) error {
	var err error
	if opts.Language == "" {
		_, err = selectLanguageInteractive()
		if err != nil {
			return err
		}
	}

	mapType := opts.MapType
	if mapType == "" {
		mapType, err = selectMapTypeInteractive()
		if err != nil {
			return err
		}
	}

	mapTemplate := mapTypeToTemplateData[mapType]

	outputType := opts.OutputType
	if outputType == "" {
		outputType, err = selectOutputTypeInteractive()
		if err != nil {
			return err
		}
	}
	mapTemplate.MapData.OutputType = mapOutputTypeToTemplateData[outputType]

	mapTmpl := template.Must(template.New("map-tmpl").Parse(mapTemplate.MapData.MapTemplate))
	mapBuf := &bytes.Buffer{}
	if err := mapTmpl.Execute(mapBuf, mapTemplate.MapData); err != nil {
		return err
	}
	mapTemplate.RenderedMap = mapBuf.String()

	tmpl := template.Must(template.New("c-file-template").Parse(fileTemplate))

	fileBuf := &bytes.Buffer{}
	if err := tmpl.Execute(fileBuf, mapTemplate); err != nil {
		return err
	}

	fileLocation := opts.FilePath
	if fileLocation == "" {
		fileLocation, err = getFileLocation()
		if err != nil {
			return err
		}
	}

	fn, err := os.Create(fileLocation)
	if err != nil {
		return err
	}

	_, err = fn.Write(fileBuf.Bytes())
	if err != nil {
		return err
	}

	pterm.Success.Println("Successfully wrote skeleton BPF program")
	return nil
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

func selectOutputTypeInteractive() (string, error) {
	return selectValueInteractive(
		"What type of output would you like from your map",
		"Selected Output Type:",
		supportedOutputTypes,
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
