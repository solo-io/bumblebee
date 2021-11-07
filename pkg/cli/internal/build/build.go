package build

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/solo-io/gloobpf/builder"
	"github.com/solo-io/gloobpf/pkg/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BuildOptions struct {
	BuildImage string
	Builder    string
	Local      bool
}

func addToFlags(flags *pflag.FlagSet, opts *BuildOptions) {
	flags.StringVarP(&opts.BuildImage, "build-image", "i", fmt.Sprintf("gcr.io/gloobpf/bpfbuilder:%s", version.Version), "")
	flags.StringVarP(&opts.Builder, "builder", "b", "docker", "")
	flags.BoolVarP(&opts.Local, "local", "l", false, "")
}

func BuildCommand(opts *BuildOptions) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "build",
		Aliases: []string{"b"},
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return build(cmd, args, opts)
		},
	}

	// Init flags
	addToFlags(cmd.PersistentFlags(), opts)

	return cmd
}

func build(cmd *cobra.Command, args []string, opts *BuildOptions) error {
	ctx := cmd.Context()

	inputFile := args[0]
	outputFile := args[1]

	if opts.Local {
		return buildLocal(ctx, inputFile, outputFile)
	}

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
	fmt.Printf("%s\n", byt)
	return nil
}

func buildLocal(ctx context.Context, inputFile, outputFile string) error {
	buildScript := builder.GetBuildScript()

	// Pass the script into sh via stdin, then arguments
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
