<h1 align="center">BumbleBee</h1>

BumbleBee helps to build, run and distribute eBPF programs using OCI images. It allows you to focus on writing eBPF code, while taking care of the user space components - automatically exposing your data as metrics or logs.

### Documentation
- **Installation**
  - [Install Bee](#Installation)
- **Getting Started**
	- [What is eBPF?](https://ebpf.io/what-is-ebpf)
	-	[Ramp up on BumbleBee concepts](docs/concepts.md)
	- [Write your first BumbleBee program](docs/getting_started.md)
- **Developer Documentation**
	- [Contributing](docs/contributing.md)

---
## Getting Started

The first step to get started is to install `bee` using one of the [installation](#Installation) techniques listed below.

Once `bee` has been installed we can go ahead an initialize our first `eBPF` probe! To do this let's head over to our [tutorial](docs/getting_started.md).

## Installation

### Using our install script
```bash
curl -sL https://run.solo.io/bee/install | sh
```

### Using go
```bash
# This will install directly to the configured GOBIN
go install github.com/solo-io/bumblebee/bee
```

#### Other options

You can also navigate to the releases page [here](https://github.com/solo-io/bumblebee/releases/) for more versions/information.

### A note on permissions

Loading eBPF programs to the kernel (`bee run` command) requires elevated privileges. 
You can either run `bee` as root (with sudo), or add capabilities to the binary. To add capabilities, run the following command:

```bash
sudo setcap cap_sys_resource,cap_sys_admin,cap_bpf+eip $(which bee)
```

Adding capabilities is the preferred method, as if you run `bee run` with `sudo`, it will not find local images when you run `bee build` without sudo.

### License

Apache 2

### Thanks

This project would not be possible without the valuable open-source work of projects in the eBPF community. Specifically, we would like to thank the [eBPF go](https://github.com/cilium/ebpf/) library and [libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools/).