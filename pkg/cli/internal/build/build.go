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

	"github.com/pterm/pterm"
	"github.com/solo-io/gloobpf/builder"
	"github.com/solo-io/gloobpf/pkg/cli/internal/defaults"
	"github.com/solo-io/gloobpf/pkg/internal/version"
	"github.com/solo-io/gloobpf/pkg/packaging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
)

type BuildOptions struct {
	BuildImage string
	Builder    string
	OutputFile string
	Local      bool
}

func addToFlags(flags *pflag.FlagSet, opts *BuildOptions) {
	flags.StringVarP(&opts.BuildImage, "build-image", "i", fmt.Sprintf("gcr.io/gloobpf/bpfbuilder:%s", version.Version), "Build image to use when compiling BPF program")
	flags.StringVarP(&opts.Builder, "builder", "b", "docker", "Executable to use for docker build command, default: `docker`")
	flags.StringVarP(&opts.OutputFile, "output-file", "o", "", "Output file for BPF ELF. If left blank will default to <inputfile.o>")
	flags.BoolVarP(&opts.Local, "local", "l", false, "Build the output binary and OCI image using local tools")

}

func BuildCommand(opts *BuildOptions) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "build INPUT_FILE REGISTRY_REF",
		Short: "Build a BPF program, and save it to an OCI image representation.",
		Long: `
The ebpfctl build command has 2 main parts
1. Compiling the BPF C program using clang.
2. Saving the compiled program in the OCI format.

By default building is done in a docker container, however, this can be switched to local by adding the local flag:
$ build INPUT_FILE REGISTRY_REF --local

`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return build(cmd, args, opts)
		},
		SilenceUsage: true, // Usage on error is bad
	}

	cmd.OutOrStdout()

	// Init flags
	addToFlags(cmd.PersistentFlags(), opts)

	return cmd
}

func build(cmd *cobra.Command, args []string, opts *BuildOptions) error {
	ctx := cmd.Context()

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
		buildSpinner, _ = pterm.DefaultSpinner.Start("Compiling BPF program locally")
		if err := buildLocal(ctx, inputFile, outputFile); err != nil {
			buildSpinner.UpdateText("Failed to compile BPF program")
			buildSpinner.Fail()
			return err
		}
	} else {
		buildSpinner, _ = pterm.DefaultSpinner.Start("Compiling BPF program locally")
		if err := buildDocker(ctx, opts, inputFile, outputFile); err != nil {
			buildSpinner.UpdateText("Failed to compile BPF program")
			buildSpinner.Fail()
			return err
		}
	}
	buildSpinner.UpdateText(fmt.Sprintf("Successfully compiled \"%s\" and wrote it to \"%s\"", inputFile, outputFile))
	buildSpinner.Success() // Resolve spinner with success message.

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

	reg, err := content.NewOCI(defaults.EbpfImageDir)
	if err != nil {
		registrySpinner.UpdateText("Failed to initialize registry")
		registrySpinner.Fail()
		return err
	}
	registryRef := args[1]
	ebpfReg := packaging.NewEbpfRegistry()

	pkg := &packaging.EbpfPackage{
		ProgramFileBytes: elfBytes,
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

func buildDocker(
	ctx context.Context,
	opts *BuildOptions,
	inputFile, outputFile string,
) error {
	// TODO: handle cwd to be glooBPF/epfctl?
	// TODO: debug log this
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	dockerArgs := []string{
		"run",
		"-v",
		fmt.Sprintf("%s:/usr/src/bpf", wd),
		opts.BuildImage,
		inputFile,
		outputFile,
	}
	dockerCmd := exec.CommandContext(ctx, opts.Builder, dockerArgs...)
	byt, err := dockerCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", byt)
		return err
	}
	return nil
}

func buildLocal(ctx context.Context, inputFile, outputFile string) error {
	buildScript := builder.GetBuildScript()

	// Pass the script into sh via stdin, then arguments
	// TODO: need to handle CWD gracefully
	shCmd := exec.CommandContext(ctx, "sh", "-s", "--", inputFile, outputFile)
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
	if err != nil {
		fmt.Printf("%s\n", out)
		return err
	}
	fmt.Printf("Successfully compiled \"%s\" and wrote it to \"%s\"\n", inputFile, outputFile)
	return nil
}
