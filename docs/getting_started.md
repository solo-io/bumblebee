# Tutorial

## Prerequisites
Most of this tutorial can be run on Linux or macOS (with docker for desktop). The "run" part requires Linux. To get a Linux environment you can use our [vagrant VM](contributing.md#Development).

## Introduction

Let's get started writing our first `eBPF` probe. This is super simple using the interactive `bee init` command. But first let's create a quick workspace directory using `mkdir ebpf-test && cd ebpf-test`.

Now let's run `bee init`!

## bee 

The first option you will be confronted with is the language with which you will develop your probe. Currently only `C` is supported, but support for `Rust` is planned as well.
```bash
? What language do you wish to use for the filter: 
  ▸ C
```

Now that we have selected the language to use, we will be prompted to select the type of program you want to create.
As eBPF enables you to write programs that can hook into essentially any kernel functionality, there are several "types" of programs you can create.
`bee` currently has two starting points: network or file-system based programs.
Network programs will be focused on hooking into various functions in the kernel networking stack while file-system programs hook into file operations, such as `open()` calls.
For this tutorial, let's select "Network".
```
? What type of program to initialize: 
  ▸ Network
    File system
```

Next you will be asked for the type of global map you would like to use. Maps are the instrument through which `eBPF` user space, and kernel space programs are able to communicate with each other. More detailed information on these maps, as well as the different types of maps which are available can be found in the `eBPF maps` section of the `BPF` [Linux documentation](https://man7.org/linux/man-pages/man2/bpf.2.html). For the sake of this demo we will arbitrarily decide on `RingBuffer`.

```bash
? What type of map should we initialize: 
  ▸ RingBuffer
    HashMap
```

After deciding on a map type, you will be asked to decide on an output format.
This step is the first that gets into the detail and magic of `bee`.
Normally developing `eBPF` applications requires writing user space and kernel space code.
However, with `bee` you only need to develop the kernel space code, and then `bee` can automatically handle and output the data from your eBPF maps.
Additionally, `bee` can emit metrics from the data being received by your eBPF maps.
Depending on your use-case, you can simply output the data in your map as text, which corresponds to the `print` output type.
However, if you would like to generate metrics from the data, you can select a metric type.
Currently, `counter` and `gauge` type metrics are supported.
More information on these can be found in the [output formats](concepts.md#Output-Formats) section below.
We will be choosing `print` for now, which again will only output map data as text and not emit any metrics.

```bash
? What type of output would you like from your map: 
  ▸ print
    counter
    gauge
```
Finally we will decide on our program file location.
```bash
✔ BPF Program File Location: probe.c
```
The output file `probe.c` should now have the following content:
```C
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

// 1. Change the license if necessary 
char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	// 2. Add ringbuf struct data here.
} __attribute__((packed));

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here: https://www.man7.org/linux/man-pages/man2/bpf.2.html
struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} print_events SEC(".maps");


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	// Init event pointer
	struct event_t *event;

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&print_events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}

	// 3. set data for our event,
	// For example:
	// event->pid = bpf_get_current_pid_tgid();

	bpf_ringbuf_submit(event, 0);

	return 0;
}
```

There's quite a bit of content in this file, so let's dive in!


This program is very similar to a regular [libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnect.bpf.c) program code. We'll review the code, and then point-out some differences from libbpf programs.

The first interesting part:
```C
#include "solo_types.h"
```
This header file includes types that `bee` can automatically interpret and display. More on this shortly.

Let's discuss the next part:
```C
struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} print_events SEC(".maps");
```

This defines a BPF map of type ring-buffer. A ring-buffer map is commonly used to stream events from 
kernel space to user space. The kernel eBPF probe writes to the ring buffer, and a user-mode program can asynchronously read events from the buffer.

Note the map name has the prefix `print_` - this has special meaning in `bee` - it instructs it to display this map as a stream of events (think logs and not metrics).

Note also that unlike libbpf ring buffer map, this one has a `__type` defined. This allows `bee` to automatically output the events written to the map. 

The final part to discuss now, is this part:

```C
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
```
This defines a kprobe that will be attached to `tcp_v4_connect`. This is not different from libbpf.


## Write Some Code

The event struct `event_t` defines the data that is streamed to our ring-buffer map. 
Let's populate the event struct with some useful data by adding fields to log the destination address and process id that attempts to make a connection:
```C
struct event_t {
	ipv4_addr daddr;
	u32 pid;
} __attribute__((packed));
```

At this point, our program would be able to send an event for each connection being established on the system.
However, with only a stream of data it may be difficult to see trends, such as how many connections are being made to specific hosts.

Let's also solve for this challenge by tracking connection counts in addition to simply streaming each connection.
To do this, we will need to add another eBPF map in addition to the ring-buffer which was initialized for us.
This new map will be a hash map and will keep track of the total number of connections to a given address.
Add the following struct and map definition before the probe:


```C
struct dimensions_t {
	ipv4_addr daddr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} counter_connection_count SEC(".maps");
```

Note the `ipv4_addr` type. This type is defined in `solo_types.h`. While it is simply defined to be a `u32`, this type definition is a hint to `bee` to format this field as an IPv4 address.

Now, let's define the code for our probe:

```C
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr) {
	struct event_t *event;
	struct dimensions_t hash_key = {};
	__u32 daddr;
	u64 counter;
	u64 *counterp;

	// read in the destination address
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	daddr = BPF_CORE_READ(usin, sin_addr.s_addr);

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&print_events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}
	// 3. set data for our event
	event->pid = bpf_get_current_pid_tgid();
	event->daddr = daddr;
	// submit the event (this makes it available for consumption)
	bpf_ringbuf_submit(event, 0);

	// increment the counter for this address
	hash_key.daddr = daddr;
	counterp = bpf_map_lookup_elem(&counter_connection_count, &hash_key);
	if (counterp) {
		__sync_fetch_and_add(counterp, 1);
	} else {
		// we may miss N events, where N is number of CPUs. We may want to 
		// fix this for prod, by adding another lookup/update calls here.
		// we skipped these for brevity
		counter = 1;
		bpf_map_update_elem(&counter_connection_count, &hash_key, &counter, BPF_NOEXIST);
	}

	return 0;
}
```

<details>
<summary>
See full source code here
</summary>

```C
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

// 1. Change the license if necessary 
char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	ipv4_addr daddr;
	u32 pid;
} __attribute__((packed));

struct dimensions_t {
	ipv4_addr daddr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} counter_connection_count SEC(".maps");

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here: https://www.man7.org/linux/man-pages/man2/bpf.2.html
struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} print_events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr) {
	// Init event pointer	
	struct event_t *event;
	struct dimensions_t hash_key = {};
	__u32 daddr;
	u64 counter;
	u64 *counterp;

	// read in the destination address
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	daddr = BPF_CORE_READ(usin, sin_addr.s_addr);

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&print_events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}
	// 3. set data for our event
	event->pid = bpf_get_current_pid_tgid();
	event->daddr = daddr;
	// submit the event (this makes it available for consumption)
	bpf_ringbuf_submit(event, 0);

	// increment the counter for this address
	hash_key.daddr = daddr;
	counterp = bpf_map_lookup_elem(&counter_connection_count, &hash_key);
	if (counterp) {
		__sync_fetch_and_add(counterp, 1);
	} else {
		// we may miss N events, where N is number of CPUs. We may want to 
		// fix this for prod, by adding another lookup/update calls here.
		// we skipped these for brevity
		counter = 1;
		bpf_map_update_elem(&counter_connection_count, &hash_key, &counter, BPF_NOEXIST);
	}

	return 0;
}
```
</details>


## Build it!

Use the `bee` tool to compile your program and store it as an OCI image:
```shell
bee build probe.c my_probe:v1
```

Note: The command above uses a `docker` build container to simplify building your code. If you use `podman` instead of docker, just add `--builder podman` to the command above.

You can see all your local probes with the `list` command:
```shell
bee list
Name                                        | OS      | OS Version             | Arch   
my_probe:v1                                 | Linux   | 5.15.4-201.fc35.x86_64 | x86_64
```

## Run it!

Note on permissions - to load a bpf program, one needs elevated permissions.
We can use `sudo` to run `bee` as root, but then `bee` will not be able to find local images that were built in the context of a regular user. To work around this, we can grant the `bee` executable the following capabilities:
```shell
sudo setcap cap_sys_resource,cap_sys_admin+eip $(which bee)
```
so it has the permissions it needs in the context of a regular user.

To run, simply use this command:
```shell
bee run my_probe:v1
```

`bee` will by default open a terminal UI and display the events coming from your probe. If you don't see anything, try running some `curl` or `wget` commands from a different terminal!

It should look something like this:

![bee running in terminal](bee_running.png)

## Collaborate!

You can push and pull probes from any OCI compatible registry, allowing you to use probes others have written with just one line of shell script!

In fact, you can try running some of the programs we've already pushed right now!
```
bee run ghcr.io/solo-io/bumblebee/tcpconnect:$(bee version)
```

This command automatically pulls the remote bpf program and runs it!

You can also push images to an OCI compliant registry, and share them with the community! As for authentication, `bee` will automatically pick-up your docker authentication settings. You can also run `bee login` (this stores the credentials **unencrypted** in `~/.bumblebee/config.json`), or provide the credentials in the command line.

To login to [GitHub Container Registry (GHCR)](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) for example, run:
```
export GITHUB_USER=<You github user name>
export GITHUB_TOKEN=<You github personal access token>
echo $GITHUB_TOKEN | bee login -u $GITHUB_USER --password-stdin ghcr.io
```

Then you can tag and push your image to your GHCR registry:
```
bee tag my_probe:v1 ghcr.io/$GITHUB_USER/my_probe:v1
bee push ghcr.io/$GITHUB_USER/my_probe:v1
```

If you don't have access to a registry, you can also start a local registry for testing purposes like so:
```
docker run --rm -p 5000:5000 registry:2
```

Once you have access to a registry, You can use `bee tag`, `bee push` and `bee pull` as you would with `docker`.

For example, let's re-tag our image from above and push it:

```
bee tag my_probe:v1 localhost:5000/my_probe:v1
bee push localhost:5000/my_probe:v1
```
Another example, that uses google container registry:

```
bee tag my_probe:v1 gcr.io/<YOUR PROJECT ID>/my_probe:v1
bee push gcr.io/<YOUR PROJECT ID>/my_probe:v1
```

### Security

Now that we have created, ran, and published our first container, let's talk about security!

`bumblebee` allows the community to create and share `eBPF` modules, but how do we ensure the code we're running is safe. This is a hot topic in the `eBPF` community as of right now, and we think we have a good answer.

Container provenance and signing is becoming more and more popular along with the rise of tools such as [`cosign`](https://github.com/sigstore/cosign). Since we publish our modules in the OCI format, we can easily verify the provenance of our modules using `cosign`!!

Let's take the image we just pushed as an easy example. Before starting you will need to download `cosign` by following their [instructions](https://docs.sigstore.dev/cosign/installation).

Now that `cosign` is installed we can go ahead and sign/verify the provenance of our modules.

```shell
$ cosign generate-key-pair
Enter password for private key:
Enter password for private key again:
Private key written to cosign.key
Public key written to cosign.pub
```

If you use a password, make sure to remember it!

Now that we have generated a key pair, we can go ahead and sign our image.

```shell
$ cosign sign  --key cosign.key  localhost:5000/my_probe:v1
Enter password for private key:
Pushing signature to: localhost:5000/my_probe
```

Time to verify our image.

```shell
cosign verify --key cosign.pub localhost:5000/my_probe:v1

Verification for localhost:5000/my_probe:v1 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/my_probe"},"image":{"docker-manifest-digest":"sha256:7a91c50d922925f152fec96ed1d84b7bc6b2079c169d68826f6cf307f22d40e6"},"type":"cosign container image signature"},"optional":null}]
```


### Troubleshooting

If you get a `403` error code when using `bee push` to push the image to your registry, check if you have permission to push.  The error below indicated the token only has read access to the registry but not write access. You'll need to generate a new `GITHUB_TOKEN` with proper access to fix it.

```
bee push ghcr.io/$GITHUB_USER/my_probe:v1
  ERROR   Failed to push image ghcr.io/$GITHUB_USER/my_probe:v1
Error: unexpected status: 403 Forbidden
```

Note: If you attempt to push to DockerHub, it will fail as expected. This is because DockerHub doesn't accept any other images than Docker images.

```
bee push docker.io/$USER/my_probe:v1
  ERROR   Failed to push image docker.io/$USER/my_probe:v1
```

## Summary

We've just gone over how `bee` can help you harness eBPF's power -- whether on your own or by using pre-made probes created by the community.
With `bee` we are trying to help you gain the benefits of eBPF while minimizing the learning curve and boilerplate code. We would love to hear your feedback!
