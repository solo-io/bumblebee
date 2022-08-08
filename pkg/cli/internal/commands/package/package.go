package package_cmd

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"

	"github.com/pterm/pterm"
	"github.com/solo-io/bumblebee/internal/version"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

//go:embed Dockerfile
var packagedDockerfile []byte

type buildOptions struct {
	BeeImage string
	Builder  string

	general *options.GeneralOptions
}

func addToFlags(flags *pflag.FlagSet, opts *buildOptions) {
	flags.StringVarP(&opts.Builder, "builder", "b", "docker", "Executable to use for docker build command")
	flags.StringVar(&opts.BeeImage, "bee-image", "ghcr.io/solo-io/bumblebee/bee:"+version.Version, "Docker image (including tag) to use a base image for packaged image")
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	buildOpts := &buildOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "package REGISTRY_REF DOCKER_IMAGE",
		Short: "Package a BPF program OCI image with the `bee` runner in a docker image",
		Long: `
The package command is used to package the desired BPF program along with the 'bee' runner in a Docker image.
This means that the resulting docker image is a single, runnable unit to load and attach your BPF proograms.
You can then ship this image around anywhere you run docker images, e.g. K8s.

Example workflow:
$ bee build examples/tcpconnect/tcpconnect.c tcpconnect
$ bee package tcpconnect bee-tcpconnect:latest
# deploy 'bee-tcpconnect:latest' to K8s cluster
`,
		Args: cobra.ExactArgs(2),
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

	reg, err := content.NewOCI(opts.general.OCIStorageDir)
	if err != nil {
		return err
	}
	registryRef := args[0]

	packagingSpinner, _ := pterm.DefaultSpinner.Start("Packaging BPF and bee image")
	tmpDir, _ := os.MkdirTemp("", "bee_oci_store")
	tmpStore := tmpDir + "/store"
	err = os.Mkdir(tmpStore, 0755)
	if err != nil {
		packagingSpinner.UpdateText(fmt.Sprintf("Failed to create temp dir: %s", tmpStore))
		packagingSpinner.Fail()
		return err
	}
	if opts.general.Verbose {
		fmt.Println("Temp dir name:", tmpDir)
		fmt.Println("Temp store:", tmpStore)
	}
	defer os.RemoveAll(tmpDir)

	tempReg, err := content.NewOCI(tmpStore)
	if err != nil {
		packagingSpinner.UpdateText(fmt.Sprintf("Failed to initialize temp OCI registry in: %s", tmpStore))
		packagingSpinner.Fail()
		return err
	}
	_, err = oras.Copy(ctx, reg, registryRef, tempReg, "",
		oras.WithAllowedMediaTypes(spec.AllowedMediaTypes()),
		oras.WithPullByBFS)
	if err != nil {
		packagingSpinner.UpdateText(fmt.Sprintf("Failed to copy image from '%s' to '%s'", opts.general.OCIStorageDir, tmpStore))
		packagingSpinner.Fail()
		return err
	}

	dockerfile := tmpDir + "/Dockerfile"
	err = os.WriteFile(dockerfile, packagedDockerfile, 0755)
	if err != nil {
		packagingSpinner.UpdateText(fmt.Sprintf("Failed to write: %s'", dockerfile))
		packagingSpinner.Fail()
		return err
	}

	packagedImage := args[1]
	err = buildPackagedImage(ctx, opts, registryRef, opts.BeeImage, tmpDir, packagedImage)
	if err != nil {
		packagingSpinner.UpdateText("Docker build of packaged image failed'")
		packagingSpinner.Fail()
		return err
	}

	packagingSpinner.UpdateText(fmt.Sprintf("Packaged image built and tagged at %s", packagedImage))
	packagingSpinner.Success()
	return nil
}

func buildPackagedImage(
	ctx context.Context,
	opts *buildOptions,
	ociImage, beeImage, tmpDir, packagedImage string,
) error {
	dockerArgs := []string{
		"build",
		"--build-arg",
		fmt.Sprintf("BPF_IMAGE=%s", ociImage),
		"--build-arg",
		fmt.Sprintf("BEE_IMAGE=%s", beeImage),
		tmpDir,
		"-t",
		packagedImage,
	}
	dockerCmd := exec.CommandContext(ctx, opts.Builder, dockerArgs...)
	byt, err := dockerCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", byt)
		return err
	}
	if opts.general.Verbose {
		fmt.Printf("%s\n", byt)
	}
	return nil
}
