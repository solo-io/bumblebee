# eBPF
Staging ground for solo-io eBPF work

## Getting Started

The first step to get started is to install `ebpfctl` using one of the [installation](#Installation) techniques listed below.

`ebpfctl` is a tool which allows for easier development and running of `eBPF` programs. Specifically we allow users to run their `eBPF` probes without running any user space code. We accomplish this using a set of conventions, and a 

Once `ebpfctl` has been installed we can go ahead an initialize our first `eBPF` probe! To do this let's head over to our [tutorial](TUTORIAL.md).


### BPF conventions

`BPF` programs are typically made up of 2 main parts:
1. The maps which allow the user space and kernel space programs to share data.
2. The functions which can be attached to kernel probes and tracepoints.

For more detailed examples of these, please see our [tutorial](#TUTORIAL.md). This section will discuss the additional features and conventions we have added on top of this workflow.

#### Maps

As the `ebpfctl` runner is primarily targeted at observability at this time, much of the user space functionality of the tool is centered around the maps. The extension of the maps allows our user space runner to interpret and process the data from these maps in a generic way. The 2 main types of maps which are supported at this time are `RingBuffer` and `HashMap`. There is some overlap in the functionality of the two within our runner, but also some important differences.

**Important Note:** Currently all structs used in maps which are meant to be processed by our user space runner cannot be nested. This may be added in the future for the logging/eventing, but not for metrics.

##### RingBuffer

`RingBuffer` is a generic map type which traditionally allows for temporary storage of many arbitrary data types. This allows the kernel or user space program to feed data into them, which can be read out in order from the other. In the case of `ebpfctl` the direction will be `kernel -> user`. In order to be able to generically handle this data however, we have imposed a restriction that only one type of data may be stored in the RingBuffer. This may change in the future.

In order to specify the type of data to be stored in the RingBuffer, it can be added to the `BPF` map definition. Typically it is not valid to store the type in a `RingBuffer` map definition, as there can be multiple types, but in this case it allows us to properly parse the data, and that type never makes it into the kernel map definition.
```C
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event_t);
} events SEC(".maps.print");
```

The other aspect of the above program worth noting is the section name: `SEC(".maps.print")`. Specifically the `.print` suffix. For those familiar with `BPF` programs this will look new. Please see the [output formats](#Output-Formats) section below for more info. The `RingBuffer` map type supports the `.print` and `.counter` keywords.

The final thing worth noting about the `RingBuffer` is it's event based nature. Each object is handled only once, and then never read from again. This differs from the `HashMap`, which will be discussed in greater detail below.

##### HashMap

Like `RingBuffer` above, `HashMap` is a generic map type to store data, with some key differences. The `HashMap` does not function as a queue, but rather as a traditional map, with both keys and values, which retains it's data until manually removed.

In addition, `HashMap` supports section keywords to enable special [output formats](#Output-Formats). The valid keywords for this type of map are: `.print`,  `.counter`, and `.gauge`.


#### Programs

Nothing specific has been added on top of the BPF programs/functions themselves at this time.


### Output Formats

Part of what makes `ebpfctl` so special, as mentioned above, is that it allows us to write `eBPF` probes with 0 user space code. In fact it allows for easy translation of kernel data and events into metrics and logging. As mentioned above this is accomplished through the use of special conventions and keywords. Before reading this section, we recommend reading the [conventions](#BPF-conventions) above for a brief overview.

These special conventions and keywords come in the form of additional kernel code additions, some in section names, and some to the code itself. Let's begin with the section names.

Maps in `BPF` programs are defined using the `SEC(".maps")` keyword. When running using the `ebpfctl` runner, extra suffixes can be added to describe how this data should be handled. These can be roughly broken down into 2 behaviors, metrics and logging. Metrics turns the data into prometheus metrics which can be consumed by any standard prometheus deployments. And logging which emits structured json logs with the provided data, and can be consumed by any structured logging applications.

The second convention we have added is a set of `typedef`s which describe to our runner how the underlying type is meant to be processesd after it leaves the kernel. These are stored in a file called `solo_types.h` and are made available automatically when building with `ebpfctl`. Some examples include:
```C
// A basic ipv4 address represented as a u32
typedef u32 ipv4_addr;
// A basic ipv6 address represented as a u32
typedef u32 ipv6_addr;
// A duration in NS stored as a u64
typedef u64 duration;
```

These types can be used in the structs which populate our maps to instruct the runner to treat the values in a special way. For instance, any `duration` value will be processed in the user space program as a golang `time.Duration` and then can be printed, and tracked as such.


#### Logging

#### Metrics


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
