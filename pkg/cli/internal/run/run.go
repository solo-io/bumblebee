package run

import "github.com/spf13/cobra"

func RunCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "run",
		Aliases: []string{"r"},
	}
}
