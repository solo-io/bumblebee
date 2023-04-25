package build

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"

	"github.com/solo-io/bumblebee/builder"
	"github.com/solo-io/bumblebee/internal/version"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/spec"
)

type buildOptions struct {
	BuildImage        string
	Builder           string
	OutputFile        string
	Local             bool
	BinaryOnly        bool
	CFlags            []string
	BuildScript       string
	BuildScriptOutput bool

	general *options.GeneralOptions
}

func (opts *buildOptions) validate() error {
	if !opts.Local {
		if opts.BuildScript != "" {
			fmt.Println("ignoring specified build script for docker build")
		}
		if opts.BuildScriptOutput {
			return fmt.Errorf("cannot write build script output for docker build")
		}
	}

	return nil
}

func addToFlags(flags *pflag.FlagSet, opts *buildOptions) {
	flags.StringVarP(&opts.BuildImage, "build-image", "i", fmt.Sprintf("ghcr.io/solo-io/bumblebee/builder:%s", version.Version), "Build image to use when compiling BPF program")
	flags.StringVarP(&opts.Builder, "builder", "b", "docker", "Executable to use for docker build command, default: `docker`")
	flags.StringVarP(&opts.OutputFile, "output-file", "o", "", "Output file for BPF ELF. If left blank will default to <inputfile.o>")
	flags.BoolVarP(&opts.Local, "local", "l", false, "Build the output binary using local tools")
	flags.StringVar(&opts.BuildScript, "build-script", "", "Optional path to a build script for building BPF program locally")
	flags.BoolVar(&opts.BuildScriptOutput, "build-script-out", false, "Print local script bee will use to build the BPF program")
	flags.BoolVar(&opts.BinaryOnly, "binary-only", false, "Only create output binary and do not package it into an OCI image")
	flags.StringArrayVar(&opts.CFlags, "cflags", nil, "cflags to be used when compiling the BPF program, passed as environment variable 'CFLAGS'")
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	buildOpts := &buildOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "build INPUT_FILE REGISTRY_REF",
		Short: "Build a BPF program, and save it to an OCI image representation.",
		Long: `
The bee build command has 2 main parts
1. Compiling the BPF C program using clang.
2. Saving the compiled program in the OCI format.

By default building is done in a docker container, however, this can be switched to local by adding the local flag:
$ build INPUT_FILE REGISTRY_REF --local

If you would prefer to build only the object file, you can include the '--binary-only' flag,
in which case you do not need to specify a registry:
$ build INPUT_FILE --binary-only

Examples:
You can specify multiple cflags with either a space separated string, or with multiple instances:
$ build INPUT_FILE REGISTRY_REF --cflags="-DDEBUG -DDEBUG2"
$ build INPUT_FILE REGISTRY_REF --cflags=-DDEBUG --cflags=-DDEBUG2

You can specify your own build script for building the BPF program locally.
the input file will be passed as argument '$1' and the output filename as '$2'.
Use the '--build-script-out' flag to see the default build script bee uses:
$ build INPUT_FILE REGISTRY_REF --local --build-script-out
$ build INPUT_FILE REGISTRY_REF --local --build-script=build.sh
`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return build(cmd.Context(), args, buildOpts)
		},
		SilenceUsage: true, // Usage on error is bad
	}

	cmd.OutOrStdout()

	// Init flags
	addToFlags(cmd.PersistentFlags(), buildOpts)

	return cmd
}

func build(ctx context.Context, args []string, opts *buildOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	inputFile := args[0]
	outputFile := opts.OutputFile

	var outputFd *os.File
	if outputFile == "" {
		ext := filepath.Ext(inputFile)

		filePath := strings.TrimSuffix(inputFile, ext)
		filePath += ".o"

		fn, err := os.Create(filePath)
		if err != nil {
			return err
		}
		// Remove if temp
		outputFd = fn
		outputFile = fn.Name()
	} else {
		fn, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		outputFd = fn
		outputFile = fn.Name()
	}

	// Create and start a fork of the default spinner.
	var buildSpinner *pterm.SpinnerPrinter
	if opts.Local {
		buildScript, err := getBuildScript(opts.BuildScript)
		if err != nil {
			return fmt.Errorf("could not load build script: %v", err)
		}
		if opts.BuildScriptOutput {
			fmt.Printf("%s\n", buildScript)
			return nil
		}

		buildSpinner, _ = pterm.DefaultSpinner.Start("Compiling BPF program locally")
		if err := buildLocal(ctx, opts, buildScript, inputFile, outputFile); err != nil {
			buildSpinner.UpdateText("Failed to compile BPF program locally")
			buildSpinner.Fail()
			return err
		}
	} else {
		buildSpinner, _ = pterm.DefaultSpinner.Start("Compiling BPF program")
		if err := buildDocker(ctx, opts, inputFile, outputFile); err != nil {
			buildSpinner.UpdateText("Failed to compile BPF program")
			buildSpinner.Fail()
			return err
		}
	}
	buildSpinner.UpdateText(fmt.Sprintf("Successfully compiled \"%s\" and wrote it to \"%s\"", inputFile, outputFile))
	buildSpinner.Success() // Resolve spinner with success message.

	if opts.BinaryOnly {
		return nil
	}

	if len(args) == 1 {
		return fmt.Errorf("must specify a registry to package the output or run with '--binary-only'")
	}

	// TODO: Figure out this hack, file.Seek() didn't seem to work
	outputFd.Close()
	reopened, err := os.Open(outputFile)
	if err != nil {
		return err
	}

	elfBytes, err := ioutil.ReadAll(reopened)
	if err != nil {
		return err
	}

	registrySpinner, _ := pterm.DefaultSpinner.Start("Packaging BPF program")

	reg, err := content.NewOCI(opts.general.OCIStorageDir)
	if err != nil {
		registrySpinner.UpdateText("Failed to initialize registry")
		registrySpinner.Fail()
		return err
	}
	registryRef := args[1]
	ebpfReg := spec.NewEbpfOCICLient()

	pkg := &spec.EbpfPackage{
		ProgramFileBytes: elfBytes,
		Platform:         getPlatformInfo(ctx),
	}

	if err := ebpfReg.Push(ctx, registryRef, reg, pkg); err != nil {
		registrySpinner.UpdateText(fmt.Sprintf("Failed to save BPF OCI image: %s", registryRef))
		registrySpinner.Fail()
		return err
	}

	registrySpinner.UpdateText(fmt.Sprintf("Saved BPF OCI image to %s", registryRef))
	registrySpinner.Success()

	return nil
}

func getPlatformInfo(ctx context.Context) *ocispec.Platform {
	cmd := exec.CommandContext(ctx, "uname", "-srm")
	out, err := cmd.CombinedOutput()
	if err != nil {
		pterm.Warning.Printfln("Unable to derive platform info: %s", out)
		return nil
	}
	splitOut := strings.Split(string(out), " ")
	if len(splitOut) != 3 {
		pterm.Warning.Printfln("Unable to derive platform info: %s", out)
		return nil
	}
	return &ocispec.Platform{
		OS:           strings.TrimSpace(splitOut[0]),
		OSVersion:    strings.TrimSpace(splitOut[1]),
		Architecture: strings.TrimSpace(splitOut[2]), //remove newline
	}
}

func getBuildScript(path string) ([]byte, error) {
	if path != "" {
		buildScript, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("could not read build script: %v", err)
		}
		return buildScript, nil
	}

	return builder.GetBuildScript(), nil
}

func buildDocker(
	ctx context.Context,
	opts *buildOptions,
	inputFile, outputFile string,
) error {
	// TODO: debug log this
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	dockerArgs := []string{
		"run",
		"-v",
		fmt.Sprintf("%s:/usr/src/bpf", wd),
	}

	if len(opts.CFlags) > 0 {
		dockerArgs = append(dockerArgs, "--env", fmt.Sprintf("CFLAGS=%s", strings.Join(opts.CFlags, " ")))
	}
	dockerArgs = append(dockerArgs, opts.BuildImage, inputFile, outputFile)

	dockerCmd := exec.CommandContext(ctx, opts.Builder, dockerArgs...)
	byt, err := dockerCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", byt)
		return err
	}
	return nil
}

func buildLocal(
	ctx context.Context,
	opts *buildOptions,
	buildScript []byte,
	inputFile,
	outputFile string,
) error {
	// Pass the script into sh via stdin, then arguments
	// TODO: need to handle CWD gracefully
	shCmd := exec.CommandContext(ctx, "sh", "-s", "--", inputFile, outputFile)
	shCmd.Env = []string{
		fmt.Sprintf("CFLAGS=%s", strings.Join(opts.CFlags, " ")),
	}
	stdin, err := shCmd.StdinPipe()
	if err != nil {
		return err
	}
	// Write the script to stdin
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, string(buildScript))
	}()

	out, err := shCmd.CombinedOutput()
	pterm.Info.Printf("%s\n", out)
	if err != nil {
		return err
	}
	return nil
}
