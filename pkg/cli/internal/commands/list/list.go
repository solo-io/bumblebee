package list

import (
	"context"

	"github.com/pterm/pterm"
	"github.com/solo-io/gloobpf/pkg/cli/internal/options"
	"github.com/spf13/cobra"
	"oras.land/oras-go/pkg/content"
)

func Command(opts *options.GeneralOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			return list(cmd.Context(), opts)
		},
	}

	return cmd
}

func list(ctx context.Context, opts *options.GeneralOptions) error {
	localRegistry, err := content.NewOCI(opts.OCIStorageDir)
	if err != nil {
		return err
	}
	localRefs := localRegistry.ListReferences()

	tableData := pterm.TableData{
		[]string{"Name", "OS", "Arch"},
	}
	for name, ref := range localRefs {
		if ref.Platform != nil {
			tableData = append(tableData, []string{name, ref.Platform.OS, ref.Platform.Architecture})
		} else {
			tableData = append(tableData, []string{name, "unknown", "unknown"})
		}

	}

	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	return nil

}
