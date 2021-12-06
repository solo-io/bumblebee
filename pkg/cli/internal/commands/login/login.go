package login

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/docker/docker/pkg/term"
	"github.com/pkg/errors"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	auth "oras.land/oras-go/pkg/auth/docker"
)

// this is adapted from oras binary login:
// https://github.com/oras-project/oras/blob/master/cmd/oras/login.go

type loginOptions struct {
	general *options.GeneralOptions

	hostname  string
	debug     bool
	fromStdin bool
}

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *loginOptions) {
	flags.BoolVarP(&opts.debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
	flags.BoolVarP(&opts.fromStdin, "password-stdin", "", false, "read password or identity token from stdin")
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	loginOptions := &loginOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "login -u USERNAME -p PASSWORD SERVER_ADDRESS",
		Short: "Log in so you can push images to the remote server.",
		Long: `Log in to remote registry

Example - Login with username and password
bee login -u USERNAME -p PASSWORD SERVER_ADDRESS

Example - Login with username and password from stdin
  echo password | bee login -u USERNAME --password-stdin SERVER_ADDRESS

`,
		Args: cobra.ExactArgs(1), // hostname
		RunE: func(cmd *cobra.Command, args []string) error {
			loginOptions.hostname = args[0]
			return run(cmd, args, loginOptions)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), loginOptions)
	return cmd
}

func run(cmd *cobra.Command, args []string, opts *loginOptions) error {
	// Subscribe to signals for terminating the program.
	// This is used until management of signals is passed to the TUI
	stopper = make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range stopper {
			if sig == os.Interrupt || sig == syscall.SIGTERM {
				fmt.Println("got sigterm or interrupt")
				os.Exit(0)
			}
		}
	}()

	if opts.debug {
		f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Prepare auth client
	cli, err := auth.NewClient(opts.general.AuthOptions.CredentialsFiles...)
	if err != nil {
		return err
	}
	// Prompt credential
	if opts.fromStdin {
		password, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		opts.general.AuthOptions.Password = strings.TrimSuffix(string(password), "\n")
		opts.general.AuthOptions.Password = strings.TrimSuffix(opts.general.AuthOptions.Password, "\r")
	} else if opts.general.AuthOptions.Password == "" {
		if opts.general.AuthOptions.Username == "" {
			username, err := readLine("Username: ", false)
			if err != nil {
				return err
			}
			opts.general.AuthOptions.Username = strings.TrimSpace(username)
		}
		if opts.general.AuthOptions.Username == "" {
			if opts.general.AuthOptions.Password, err = readLine("Token: ", true); err != nil {
				return err
			} else if opts.general.AuthOptions.Password == "" {
				return errors.New("token required")
			}
		} else {
			if opts.general.AuthOptions.Password, err = readLine("Password: ", true); err != nil {
				return err
			} else if opts.general.AuthOptions.Password == "" {
				return errors.New("password required")
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "WARNING! Using --password via the CLI is insecure. Use --password-stdin.")
	}

	// Login
	if err := cli.Login(cmd.Context(), opts.hostname, opts.general.AuthOptions.Username, opts.general.AuthOptions.Password, opts.general.AuthOptions.Insecure); err != nil {
		return err
	}

	fmt.Println("Login Succeeded")
	return nil

}

func readLine(prompt string, slient bool) (string, error) {
	fmt.Print(prompt)
	if slient {
		fd := os.Stdin.Fd()
		state, err := term.SaveState(fd)
		if err != nil {
			return "", err
		}
		term.DisableEcho(fd, state)
		defer term.RestoreTerminal(fd, state)
	}

	reader := bufio.NewReader(os.Stdin)
	line, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}
	if slient {
		fmt.Println()
	}

	return string(line), nil
}
