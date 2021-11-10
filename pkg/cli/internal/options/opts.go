package options

import (
	"github.com/solo-io/gloobpf/pkg/cli/internal/defaults"
	"github.com/spf13/pflag"
)

func NewGeneralOptions(flags *pflag.FlagSet) *GeneralOptions {
	opts := &GeneralOptions{}
	opts.addToFlags(flags)
	opts.AuthOptions.addToFlags(flags)
	return opts
}

type GeneralOptions struct {
	Verbose       bool
	OCIStorageDir string

	AuthOptions AuthOptions
}

func (opts *GeneralOptions) addToFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")
	flags.StringVar(&opts.OCIStorageDir, "storage", defaults.EbpfImageDir, "Directory to store OCI images locally")
}

type AuthOptions struct {
	CredentialsFiles []string
	Username         string
	Password         string
	Insecure         bool
	PlainHTTP        bool
}

func (opts *AuthOptions) addToFlags(flags *pflag.FlagSet) {
	flags.StringArrayVarP(&opts.CredentialsFiles, "config", "c", nil, "path to auth config")
	flags.StringVarP(&opts.Username, "username", "u", "", "registry username")
	flags.StringVarP(&opts.Password, "password", "p", "", "registry password")
	flags.BoolVarP(&opts.Insecure, "insecure", "", false, "allow connections to SSL registry without certs")
	flags.BoolVarP(&opts.PlainHTTP, "plain-http", "", false, "use plain http and not https")
}
