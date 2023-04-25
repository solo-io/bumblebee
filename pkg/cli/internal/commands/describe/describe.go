package describe

import (
	"github.com/pterm/pterm"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type describeOptions struct {
	general *options.GeneralOptions
}

func addToFlags(flags *pflag.FlagSet, opts *describeOptions) {}

func Command(opts *options.GeneralOptions) *cobra.Command {
	describeOptions := &describeOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "describe BPF_OCI_IMAGE",
		Short: "Describe a BPF program via it's OCI ref",
		Args:  cobra.ExactArgs(1), // image
		RunE: func(cmd *cobra.Command, args []string) error {
			return describe(cmd, args, describeOptions)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), describeOptions)
	return cmd
}

func describe(cmd *cobra.Command, args []string, opts *describeOptions) error {
	// guaranteed to be length 1
	ref := args[0]
	client := spec.NewEbpfOCICLient()
	prog, err := spec.TryFromLocal(
		cmd.Context(),
		spec.PullOpts{
			Ref:             ref,
			LocalStorageDir: opts.general.OCIStorageDir,
			Client:          client,
			RegistryOptions: opts.general.AuthOptions.ToRegistryOptions(),
		},
	)
	if err != nil {
		return err
	}
	var (
		platformPanel, authorsPanel, descriptionPanel string
	)

	if prog.Description != "" {
		descriptionPanel = pterm.DefaultBox.Sprint(prog.Description)
	} else {
		descriptionPanel = pterm.DefaultBox.Sprint("No description found")
	}

	if prog.Description != "" {
		authorsPanel = pterm.DefaultBox.Sprint(prog.Authors)
	} else {
		authorsPanel = pterm.DefaultBox.Sprint("No Authors found")
	}

	if prog.Platform != nil {
		platformPanel = pterm.DefaultBox.
			WithTitle("Platform").
			Sprintf("%s %s %s", prog.Platform.OS, prog.Platform.OSVersion, prog.Platform.Architecture)
	} else {
		platformPanel = pterm.DefaultBox.WithTitle("Platform").Sprint("unknown")
	}

	panels, _ := pterm.DefaultPanel.WithPanels(pterm.Panels{
		{{Data: descriptionPanel}},
		{{Data: authorsPanel}},
		{{Data: platformPanel}},
	}).Srender()

	pterm.DefaultBox.WithTitle(ref).Println(panels)

	return nil
}
