package init

import "github.com/spf13/cobra"

// go:embed ringbuf.c
var ringbufProg []byte

// go:embed hash.c
var hashProg []byte

func InitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "init",
	}

	return cmd
}
