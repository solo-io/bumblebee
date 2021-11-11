package spec

import (
	"os"
	"path/filepath"
)

var (
	EbpfConfigDir       = home() + "/.ebpf"
	EbpfImageDir        = filepath.Join(EbpfConfigDir, "store")
	EbpfCredentialsFile = filepath.Join(EbpfConfigDir, "credentials.json")
)

func home() string {
	dir, _ := os.UserHomeDir()
	return dir
}
