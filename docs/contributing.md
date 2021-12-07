# Contributing

Developing `eBPF` does not require a linux machine, however running the probes does. `eBPF` itself is a linux kernel technology, therefore any actual `BPF` programs must run in the linux kernel. We are working on an OSX development path, but it has not been completed as of yet.

We recommend doing `eBPF` development on a linux machine. Do not fret however if you don't have a native Linux desktop, neither do we. Using `vscode` and GCP allows for a seamless near native development experience. See the following [article](https://safwene-benaich.medium.com/developing-on-remote-vm-via-vscode-using-google-clouds-iap-6b6549f9270c) for more detail. The article details the steps on a Windows machine, but they should be nearly identical on a Mac. 

Also worh noting , `bee` does not currently support Arm architectures (coming soon). However, the above development trick should alleviate that issue in the short-term.

## Repo Structure

The following is a brief overview of the internal code structure

```.
├── builder # Dockerfile and scripts related to our eBPF build container
├── ci # Scripts and helpers for CI
├── docs # Docs and other useful information for interacting with bumblebee
├── bee # main.go file for bee, majority of code is in pkg
├── examples # Variety of example eBPF programs to be run with bee
├── pkg # Primary code directory
└── spec # Contains information related to eBPF OCI Spec
```
## Development

For non-linux users, we have a [vagrant](https://learn.hashicorp.com/tutorials/vagrant/getting-started-install) box available. Just run

```bash
vagrant up
vagrant ssh
```

This folder will be mounted under "/source" in the vagrant VM.

For fast iterations of go code / bpf programs, you can build with our build script, and run with go run as follows:

```bash
cd /source
./builder/build.sh ./examples/tcpconnect/tcpconnect.c tcpconnect.o
go run -exec sudo ./bee/main.go run tcpconnect.o
```

To make a local docker image for the bee to use, you can run

```bash
make docker-build
```

or, if for podman:

```bash
make docker-build DOCKER=podman
```