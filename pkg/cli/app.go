package cli

import (
	"github.com/spf13/cobra"
)

func EbpfCtl() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ebpfctl",
	}
	return cmd
}