module github.com/solo-io/bumblebee

go 1.17

require (
	github.com/cilium/ebpf v0.7.0
	github.com/gdamore/tcell/v2 v2.4.1-0.20210905002822-f057f0a857a1
	github.com/manifoldco/promptui v0.9.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.16.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/prometheus/client_golang v1.11.0
	github.com/pterm/pterm v0.12.33
	github.com/rivo/tview v0.0.0-20211109175620-badfa0f0b301
	github.com/solo-io/go-utils v0.21.24
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	go.uber.org/zap v1.17.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	oras.land/oras-go v1.0.0
)

require (
	github.com/docker/cli v20.10.11+incompatible
	github.com/docker/docker v20.10.11+incompatible
	github.com/pkg/errors v0.9.1
)

replace github.com/cilium/ebpf => github.com/solo-io/cilium-ebpf v0.7.1-0.20211109175948-0418708068be
