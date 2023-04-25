package initialize // Can't name init because it's a hardcoded const in golang

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"text/template"

	"github.com/manifoldco/promptui"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type InitOptions struct {
	Language    string
	MapType     string
	FilePath    string
	OutputType  string
	ProgramType string
}

func addToFlags(flags *pflag.FlagSet, opts *InitOptions) {
	flags.StringVarP(&opts.Language, "language", "l", "", "Language to use for the bpf program")
	flags.StringVarP(&opts.MapType, "map", "m", "", "Map type to initialize")
	flags.StringVarP(&opts.FilePath, "file", "f", "", "File to create skeleton in")
	flags.StringVarP(&opts.OutputType, "output-type", "o", "", "The output type for your map")
	flags.StringVar(&opts.ProgramType, "program-type", "", "The type of program to create (e.g. network, file-system)")
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
	var languageType string
	if opts.Language == "" {
		languageType, err = selectLanguage()
		if err != nil {
			return err
		}
	} else {
		err = validateLanguage(opts.Language)
		if err != nil {
			return err
		}
	}

	programType := opts.ProgramType
	if programType == "" {
		programType, err = selectProgramType()
		if err != nil {
			return err
		}
	}
	var mapTemplate *templateData
	if programType == network {
		mapTemplate, err = handleNetworkProgram(opts)
		if err != nil {
			return err
		}
	} else if programType == fileSystem {
		if opts.MapType != "" || opts.OutputType != "" {
			return errors.New("initializing a file system type program with custom map types or output type is not currently supported. Please remove overrides for map type and output type to continue")
		}
		mapTemplate = &templateData{
			StructData:   openAtStruct,
			FunctionBody: openAtBody,
			RenderedMap:  openAtMap,
		}
	} else {
		return fmt.Errorf("%s is not a valid program type", programType)
	}

	tmpl := template.Must(template.New("c-file-template").Parse(fileTemplate))

	fileBuf := &bytes.Buffer{}
	if err := tmpl.Execute(fileBuf, mapTemplate); err != nil {
		return err
	}

	fileLocation := opts.FilePath
	if fileLocation == "" {
		fileLocation, err = getFileLocation()
		if fileLocation == "" && languageType == "C" {
			fileLocation = "bee.c"
		}
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

func handleNetworkProgram(opts *InitOptions) (*templateData, error) {
	var err error
	mapType := opts.MapType
	if mapType == "" {
		mapType, err = selectMapType()
		if err != nil {
			return nil, err
		}
	} else {
		err = validateMapType(mapType)
		if err != nil {
			return nil, err
		}
	}

	mapTemplate := mapTypeToTemplateData[mapType]

	outputType := opts.OutputType
	if outputType == "" {
		outputType, err = selectOutputType()
		if err != nil {
			return nil, err
		}
	} else {
		err = validateOutputType(outputType)
		if err != nil {
			return nil, err
		}
	}

	mapTemplate.MapData.OutputType = mapOutputTypeToTemplateData[outputType]

	mapTmpl := template.Must(template.New("map-tmpl").Parse(mapTemplate.MapData.MapTemplate))
	mapBuf := &bytes.Buffer{}
	if err := mapTmpl.Execute(mapBuf, mapTemplate.MapData); err != nil {
		return nil, err
	}
	mapTemplate.RenderedMap = mapBuf.String()

	return mapTemplate, nil
}

func selectLanguage() (string, error) {
	return selectValue(
		"What language do you wish to use for the filter",
		"Selected Language:",
		supportedLanguages,
	)
}

func validateLanguage(lang string) error {
	if contains(lang, supportedLanguages) {
		return nil
	}
	return fmt.Errorf("%s is not a valid language type", lang)
}

func selectProgramType() (string, error) {
	return selectValue(
		"What type of program to initialize",
		"Selected Program Type:",
		supportedProgramTypes,
	)
}

func selectMapType() (string, error) {
	return selectValue(
		"What type of map should we initialize",
		"Selected Map Type:",
		supportedMapTypes,
	)
}

func validateMapType(typ string) error {
	if contains(typ, supportedMapTypes) {
		return nil
	}
	return fmt.Errorf("%s is not a valid map type", typ)
}

func selectOutputType() (string, error) {
	return selectValue(
		"What type of output would you like from your map",
		"Selected Output Type:",
		supportedOutputTypes,
	)
}

func validateOutputType(typ string) error {
	if contains(typ, supportedOutputTypes) {
		return nil
	}
	return fmt.Errorf("%s is not a valid output type", typ)
}

func selectValue(question, success string, options interface{}) (string, error) {
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

func contains(s string, slice []string) bool {
	for _, v := range slice {
		if s == v {
			return true
		}
	}
	return false
}
