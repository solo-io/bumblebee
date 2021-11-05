package build

import "github.com/spf13/cobra"

func BuildCommand() *cobra.Command {
	return &cobra.Command{
		Use: "build",
		Aliases: []string{"b"},
	}
}
