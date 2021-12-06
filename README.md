# eBPF
Staging ground for solo-io eBPF work

## Getting Started

The first step to get started is to install `bee` using one of the [installation](#Installation) techniques listed below.

`bee` is a tool which allows for easier development and running of `eBPF` programs. Specifically we allow users to run their `eBPF` probes without running any user space code. We accomplish this using a set of conventions, and a 

Once `bee` has been installed we can go ahead an initialize our first `eBPF` probe! To do this let's head over to our [tutorial](TUTORIAL.md).


### BPF conventions

`BPF` programs are typically made up of 2 main parts:
1. The maps which allow the user space and kernel space programs to share data.
2. The functions which can be attached to kernel probes and tracepoints.

For more detailed examples of these, please see our [tutorial](#TUTORIAL.md). This section will discuss the additional features and conventions we have added on top of this workflow.

#### Maps

As the `bee` runner is primarily targeted at observability, much of the user space functionality of the tool is centered around the maps. The extension of the maps allows our user space runner to interpret and process the data from these maps in a generic way. The 2 main types of maps which are supported at this time are `RingBuffer` and `HashMap`. There is some overlap in the functionality of the two within our runner, but also some important differences.

**Important Note:** Currently all structs used in maps which are meant to be processed by our user space runner cannot be nested. This may be added in the future for the logging/eventing, but not for metrics.

##### RingBuffer

`RingBuffer` is a generic map type which traditionally allows for temporary storage of many arbitrary data types. This allows the kernel or user space program to feed data into them, which can be read out in order from the other. In the case of `bee` the direction will be `kernel -> user`. In order to be able to generically handle this data however, we have imposed a restriction that only one type of data may be stored in the RingBuffer. This may change in the future.

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

In addition, `HashMap` supports section keywords to enable special [output formats](#Output-Formats). The valid keywords for this type of map are: `.print`, `.counter`, and `.gauge`.


#### Programs

Nothing specific has been added on top of the BPF programs/functions themselves at this time.


### Output Formats

Part of what makes `bee` so special, as mentioned above, is that it allows us to write `eBPF` probes with 0 user space code. In fact it allows for easy translation of kernel data and events into metrics and logging. As mentioned above this is accomplished through the use of special conventions and keywords. Before reading this section, we recommend reading the [conventions](#BPF-conventions) above for a brief overview.

These special conventions and keywords come in the form of additional kernel code additions, some in section names, and some to the code itself. Let's begin with the section names.

Maps in `BPF` programs are defined using the `SEC(".maps")` keyword. When running using the `bee` runner, extra suffixes can be added to describe how this data should be handled. These can be roughly broken down into 2 behaviors, metrics and logging. Metrics turns the data into prometheus metrics which can be consumed by any standard prometheus deployments. And logging which emits structured json logs with the provided data, and can be consumed by any structured logging applications.

The second convention we have added is a set of `typedef`s which describe to our runner how the underlying type is meant to be processesd after it leaves the kernel. These are stored in a file called `solo_types.h` and are made available automatically when building with `bee`. Some examples include:
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

Logging may be the simplest output format of our `eBPF` probes, but it is also incredibly powerful for both observability and debugging. Logging in our system comes in two main forms. Event based, and timer based. These two types of loggings are used based on the underlying map type which is being logged. When logging a `RingBuffer` each event is handled/logged individually, and therefore it will only be printed once. However, when using a `HashMap` the data has a longer life, and therefore the printing will happen each time there is an update. Let's look at a couple of quick examples to demonstrate this.

##### RingBuffer

The source for this example can be found in `./examples/kprobetcp/handler.c`. Detailed steps on building and running are omitted here, please see our [tutorial](#TUTORIAL.md) for more in depth steps.


When looking at the program itself, we can see that the struct being passed into the `RingBuffer` has the following structure. Keep this in mind when looking at the log line below.
```C
struct event_t {
	u32 pid;
	u32 uid;
	duration uptime;
} __attribute__((packed));
```

After running the program, I simply run `curl httpbin.org` in a seperate terminal and the following log line appeared.
```json
{"entry":{"pid":"1478616", "uid":"1003","uptime":"359h58m30.242761006s"},"mapName":"events"}
```
The data in contained is not particularly interesting, but rather the formatting and structure. We have printed the map name this data came from, as well as all the data contains. Notice that the uptime of the system is also printed as a human readable duration, because the `typedef duration` was used in the source struct!

##### HashMap

The source for this example can be found in `./examples/tcpconnect/tcpconnect.c`. Detailed steps on building and running are omitted here, please see our [tutorial](#TUTORIAL.md) for more in depth steps.

When looking at the program itself, we can see that the struct being passed into the `HashMap` has the following structure. Keep this in mind when looking at the log line below.
```C
struct dimensions_t {
	ipv4_addr saddr;
	ipv4_addr daddr;
} __attribute__((packed));
```

After running the program, I simply run `curl httpbin.org` a few times in a seperate terminal and the following log line appeared.
```json
{"entries":[{"key":{"daddr":"18.232.227.86","saddr":"10.128.0.79"},"value":"2"},{"key":{"daddr":"34.192.79.103","saddr":"10.128.0.79"},"value":"5"}],"mapName":"sockets_ext"}
```
This one differs slightly from the `RingBuffer` example above in a couple important ways. First of all the log lines do not happen at the same frequency as the events themselves, but rather on a timer. Secondly, there are multiple key/value pairs, rather than a single value. Each key/value pair represents in this case an upstream/downstream address pair, and the number of connections. Also worth noting that the data described using the `typedef ipv4_addr` gets formatted as the underlying IP type by the printer.

#### Metrics

Potentially even more powerful than the logging features of the `bee` runner are it's metrics capabilities. As opposed to the logging feature, the metrics feature allows for creation and export of generic metrics + labels from `eBPF` probes. A couple simple, yet powerful, examples of this functionality are in the `examples` folder. `activeconn` keeps track of all active tcpv4 connections in a gauge with source/dest IP as the metric labels. The `tcpconnect` example does something similar, but it increments a counter for each new connection, rather than maintaining all active.

##### Counter

Currently there are 2 ways to use a gauge with `bee`. One with a `HashMap` and one with a `RingBuffer`.

An example of the both the `RingBuffer` counter and `HashMap` counter exist in the `examples/tcpconnect` folder. The program tracks the number of TCP connections using both map types to illustrate their use. We do not recommend saving the same value two seperate ways.

After starting the program, and curling httpbin a few times we can, we can get the metrics from `curl localhost:9091/metrics | grep events`
```
# HELP ebpf_solo_io_events_hash 
# TYPE ebpf_solo_io_events_hash counter
ebpf_solo_io_events_hash{daddr="18.232.227.86",saddr="10.128.0.79"} 9
ebpf_solo_io_events_hash{daddr="3.216.167.140",saddr="10.128.0.79"} 5
# HELP ebpf_solo_io_events_ring 
# TYPE ebpf_solo_io_events_ring counter
ebpf_solo_io_events_ring{daddr="18.232.227.86",saddr="10.128.0.79"} 9
ebpf_solo_io_events_ring{daddr="3.216.167.140",saddr="10.128.0.79"} 5
```

As we can see the number of connections are being tracked both from our `HashMap` and `RingBuffer` implementation.

##### Gauge 


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

## Contributing

Developing `eBPF` does not require a linux machine, however running the probes does. `eBPF` itself is a linux kernel technology, therefore any actual `BPF` programs must run in the linux kernel. We are working on an OSX development path, but it has not been completed as of yet.

We recommend doing `eBPF` development on a linux machine. Do not fret however if you don't have a native Linux desktop, neither do we. Using `vscode` and GCP allows for a seamless near native development experience. See the following [article](https://safwene-benaich.medium.com/developing-on-remote-vm-via-vscode-using-google-clouds-iap-6b6549f9270c) for more detail. The article details the steps on a Windows machine, but they should be nearly identical on a Mac. 

Also worh noting , `bee` does not currently support Arm architectures (coming soon). However, the above development trick should alleviate that issue in the short-term.

### Repo Structure

The following is a brief overview of the internal code structure

```.
├── builder # Dockerfile and scripts related to our eBPF build container
├── ci # Scripts and helpers for CI
├── bee # main.go file for bee, majority of code is in pkg
├── examples # Variety of example eBPF programs to be run with bee
├── pkg # Primary code directory
└── spec # Contains information related to eBPF OCI Spec
```
# Development

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
make docker-local-build
```

or, if for podman:

```bash
make docker-local-build DOCKER=podman
```