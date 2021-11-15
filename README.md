# eBPF
Staging ground for solo-io eBPF work

## Getting Started

The first step to get started is to install `ebpfctl` using one of the [installation](#Installation) techniques listed below.

`ebpfctl` is a tool which allows for easier development and running of `eBPF` programs. Specifically we allow users to run their `eBPF` probes without running any user space code. We accomplish this using a set of conventions, and a 

Once `ebpfctl` has been installed we can go ahead an initialize our first `eBPF` probe! To do this let's head over to our [tutorial](#TUTORIAL.md).


## BPF conventions


## Output Formats


## Installation

### Using our install script
```bash
curl -sL https://run.solo.io/ebpfctl/install | sh
```

### Using go
```bash
# This will install directly to the configured GOBIN
go install github.com/solo-io/ebpf/ebpfctl
```

#### Other options

You can also navigate to the releases page [here](https://github.com/solo-io/eBPF/releases/) for more versions/information.

## Contributing

Developing `eBPF` does not require a linux machine, however running the probes does. `eBPF` itself is a linux kernel technology, therefore any actual `BPF` programs must run in the linux kernel. We are working on an OSX development path, but it has not been completed as of yet.

We recommend doing `eBPF` development on a linux machine. Do not fret however if you don't have a native Linux desktop, neither do we. Using `vscode` and GCP allows for a seamless near native development experience. See the following [article](https://safwene-benaich.medium.com/developing-on-remote-vm-via-vscode-using-google-clouds-iap-6b6549f9270c) for more detail. The article details the steps on a Windows machine, but they should be nearly identical on a Mac. 

Also worh noting , `ebpfctl` does not currently support Arm architectures (coming soon). However, the above development trick should alleviate that issue in the short-term.

### Repo Structure

The following is a brief overview of the internal code structure

```.
├── builder # Dockerfile and scripts related to our eBPF build container
├── ci # Scripts and helpers for CI
├── ebpfctl # main.go file for ebpfctl, majority of code is in pkg
├── examples # Variety of example eBPF programs to be run with ebpfctl
├── pkg # Primary code directory
└── spec # Contains information related to eBPF OCI Spec
```
