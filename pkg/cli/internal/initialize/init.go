package initialize // Can't name init because it's a hardcoded const in golang

import (
	"github.com/spf13/cobra"
)

// go:embed progs/ringbuf.c
var ringbufProg []byte

// go:embed progs/hash.c
var hashProg []byte

func InitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a sample BPF program",
	}

	return cmd
}
