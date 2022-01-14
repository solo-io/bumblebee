# Concepts

## Building

BumbleBee by default uses a containerized build environment to build your BPF programs to an ELF file, then packages that in an OCI image according to our image spec.

You can then package your BPF program as standard Docker image that contains the `bee` CLI/runner in addition to your BPF programs.
The end result is a standard docker image that can be distributed via standard docker-like workflows to run your BPF program anywhere you run containerized workloads, such as a K8s cluster.
Note that you will need sufficient capabilities to run the image, as loading and running the BPF program is a privileged operation for most intents and purposes.

An example workflow is as follows:
```bash
$ bee build examples/tcpconnect/tcpconnect.c tcpconnect
 SUCCESS  Successfully compiled "examples/tcpconnect/tcpconnect.c" and wrote it to "examples/tcpconnect/tcpconnect.o"
 SUCCESS  Saved BPF OCI image to tcpconnect

$ bee package tcpconnect bee-tcpconnect:latest
 SUCCESS  Packaged image built and tagged at bee-tcpconnect:latest

# run the bee-tcpconnect:latest image somewhere, deploy to K8s, etc.
# this example below runs locally via `docker` but see the following paragraph for a warning on weird terminal behavior when using this exact command!
$ docker run --privileged --tty bee-tcpconnect:latest
```

Note that the `--privileged` flag is required to provide the permissions necessary and the `--tty` flag is necessary for the TUI rendered by default with `bee run`.
The `--tty` requirement will be removed shortly as we will introduce a mode that does not render the TUI.
Additionally, if you run the image as above, when you attempt to quit via <ctrl-c> your terminal may be left in a bad state. This is because the <ctrl-c> is being handled by `docker run` and not making it to the TTY.
To clear your screen, do a non-containerized run, e.g. `bee run ghcr.io/solo-io/bumblebee/tcpconnect:$(bee version)`.
Again, this will have a better UX very soon!

## BPF conventions

`BPF` programs are typically made up of 2 main parts:
1. The maps which allow the user space and kernel space programs to share data.
2. The functions which can be attached to kernel probes and tracepoints.

For more detailed examples of these, please see our [tutorial](getting_started.md). This section will discuss the additional features and conventions we have added on top of this workflow.

### Maps

As the `bee` runner is primarily targeted at observability, much of the user space functionality of the tool is centered around the maps. The extension of the maps allows our user space runner to interpret and process the data from these maps in a generic way. The two main types of maps which are supported at this time are `RingBuffer` and `HashMap`. There is some overlap in the functionality of the two within our runner, but also some important differences.

**Important Note:** Currently all structs used in maps which are meant to be processed by our user space runner cannot be nested. This may be added in the future for the logging/eventing, but not for metrics.

#### RingBuffer

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

#### HashMap

Like `RingBuffer` above, `HashMap` is a generic map type to store data, with some key differences. The `HashMap` does not function as a queue, but rather as a traditional map, with both keys and values, which retains it's data until manually removed.

In addition, `HashMap` supports section keywords to enable special [output formats](#Output-Formats). The valid keywords for this type of map are: `.print`, `.counter`, and `.gauge`.


### Programs

Nothing specific has been added on top of the BPF programs/functions themselves at this time.


## Output Formats

Part of what makes `bee` so special, as mentioned above, is that it allows us to write `eBPF` probes with 0 user space code. In fact it allows for easy translation of kernel data and events into metrics and logging. As mentioned above this is accomplished through the use of special conventions and keywords. Before reading this section, we recommend reading the [conventions](#BPF-conventions) above for a brief overview.

These special conventions and keywords come in the form of additional kernel code additions, some in section names, and some to the code itself. Let's begin with the section names.

Maps in `BPF` programs are defined using the `SEC(".maps")` keyword. When running using the `bee` runner, extra suffixes can be added to describe how this data should be handled. These can be roughly broken down into 2 behaviors, metrics and logging. Metrics turns the data into prometheus metrics which can be consumed by any standard prometheus deployments. And logging which emits structured json logs with the provided data, and can be consumed by any structured logging applications.

The second convention we have added is a set of `typedef`s which describe to our runner how the underlying type is meant to be processed after it leaves the kernel. These are stored in a file called `solo_types.h` and are made available automatically when building with `bee`. Some examples include:
```C
// A basic ipv4 address represented as a u32
typedef u32 ipv4_addr;
// A basic ipv6 address represented as a u32
typedef u32 ipv6_addr;
// A duration in NS stored as a u64
typedef u64 duration;
```

These types can be used in the structs which populate our maps to instruct the runner to treat the values in a special way. For instance, any `duration` value will be processed in the user space program as a golang `time.Duration` and then can be printed, and tracked as such.


### Logging

Logging may be the simplest output format of our `eBPF` probes, but it is also incredibly powerful for both observability and debugging.
Logging in our system comes in two main forms: event based and timer based.
The type of logging used is based on the underlying map type.
When logging a `RingBuffer` each event is handled/logged individually as it is received and therefore it will only be printed once.
However, when using a `HashMap`, the data is polled on an interval. Therefore, the logging will happen on each interval and only when there is a change in the values of the map from the previous interval.

When using `bee` to run your BPF programs, the TUI that is rendered by default will automatically handle the printing of the data in maps that follow the naming conventions.
In other words, printing/logging of data is handled for metric output types automatically.
We have a TCP-based example that demonstrates both map types which will explore more in depth.
You can find the source in our examples folder here: [`/examples/tcpconnect/tcpconnect.c`](/examples/tcpconnect/tcpconnect.c).
Both map types below use the following `struct` to define the shape of data being processed by our maps:
```C
struct dimensions_t {
	ipv4_addr saddr;
	ipv4_addr daddr;
} __attribute__((packed));
```
This struct contains two IPv4 addresses, a source and destination IP.

#### RingBuffer

Looking at the `RingBuffer` map in our `tcpconnect` program:
```C
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct dimensions_t);
} events_ring SEC(".maps.counter");
``` 
We can see that the `struct dimensions_t` type is being passed into the `RingBuffer`.
So as TCP connections are established, the source and destination IP of these connections will be sent as events into this `RingBuffer`. Also note the `.maps.counter` section name.
This tells `bee` to "watch" this map and log the data (in addition to emitting counter metrics, which will explore more in a later section).

When running the program, as new TCP connections happen (by e.g. making a `curl 1.1.1.1` request in a separate terminal) we can see the TUI log the data:
```
daddr		saddr
1.1.1.1		10.128.0.119
```
The data in contained is not particularly interesting, but rather the formatting and structure.
As the connection was created and data sent to our map, we will dynamically get the data printed to our screen in the correct format!

#### HashMap

Looking at the `RingBuffer` map in our `tcpconnect` program:
```C
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} events_hash SEC(".maps.counter");
```

As above, we can see that the `struct dimensions_t` type is being used, this time as the `key` type for our `HashMap`.
When running the program, we can see the entries get updated as connections are created:
```
daddr         saddr          value
1.1.1.1       10.128.0.119   1
```
This one differs slightly from the `RingBuffer` example above in a couple important ways.
First of all the log lines do not happen at the same frequency as the events themselves, but rather on a timer.
Secondly, the values in the key (`daddr` and `saddr`) are printed in addition to the `value`, which represents the total count of connections for this given source/destination pair.
As these values change, or new source/destination pairs are introduced, the value will update and new rows will be printed accordingly.

### Metrics

Potentially even more powerful than the logging features of the `bee` runner are it's metrics capabilities. As opposed to the logging feature, the metrics feature allows for creation and export of generic metrics + labels from `eBPF` probes. A couple simple, yet powerful, examples of this functionality are in the `examples` folder. `activeconn` keeps track of all active tcpv4 connections in a gauge with source/dest IP as the metric labels. The `tcpconnect` example does something similar, but it increments a counter for each new connection, rather than maintaining all active.

#### Counter

Currently there are 2 ways to use a counter with `bee`. One with a `HashMap` and one with a `RingBuffer`.

An example of the both the `RingBuffer` counter and `HashMap` counter exist in the `examples/tcpconnect` folder. The program tracks the number of TCP connections using both map types to illustrate their use. We do not recommend saving the same value two separate ways.

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

#### Gauge 

Gauges are used to track numeric values that can change over time.
BumbleBee supports automatically exporting gauge style metrics for both `RingBuffer` and `HashMap` type maps as long as your map is correctly defined with a section name with a `.gauge` suffix.

An example of a gauge is the number of active connections to a given host.
The [/examples/activeconn/activeconn.c](/examples/activeconn/activeconn.c) file contains an implementation of active connection tracking by using a `HashMap` type map with a `.gauge` output type.

Let's take a closer look at the `struct` which defines the map that will contain the connection counts.
```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} sockets_ext SEC(".maps.gauge");
```

This defines a `HashMap` containing integer values for connection counts which are keyed by `struct dimensions_t` (which we explored in the [HashMap](#hashmap-1) section).
In other words, this means that each source and destination address pair will point to an integer representing the current number of active connections.

The exporting of metrics is automatically handled thanks to the section name of `.maps.gauge`.
This tells the `bee` runner to export gauge metrics of the current value for each entry in the `HashMap` map each time the value of the map is polled.
Alternatively, if we were using a `RingBuffer` with gauge output, when each entry is processed by the `bee` runner, the gauge value will be updated accordingly.
