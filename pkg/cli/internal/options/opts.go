package options

import (
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
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
	flags.StringVar(&opts.OCIStorageDir, "storage", spec.EbpfImageDir, "Directory to store OCI images locally")
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
	flags.BoolVar(&opts.Insecure, "insecure", false, "allow connections to SSL registry without certs")
	flags.BoolVar(&opts.PlainHTTP, "plain-http", false, "use plain http and not https")
}

func (opts *AuthOptions) ToRegistryOptions() content.RegistryOptions {
	return content.RegistryOptions{
		Configs:   opts.CredentialsFiles,
		Username:  opts.Username,
		Password:  opts.Password,
		Insecure:  opts.Insecure,
		PlainHTTP: opts.PlainHTTP,
	}
}
