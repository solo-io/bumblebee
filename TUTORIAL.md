# Tutorial

## Introduction

Let's get started writing our first `eBPF` probe. This is super simple using the interactive `bee init` command. But first let's create a quick workspace directory using `mkdir ebpf-test && cd ebpf-test`.

Now let's run `bee init`!

## bee 

The first option you will be confronted with is the language with which you will develop your probe. Currently only `C` is supported, but support for `Rust` is planned as well.
```bash
? What language do you wish to use for the filter: 
  ▸ C
```
Next you will be asked for the type of global map you would like to use. Maps are the instrument through which `eBPF` user space, and kernel space programs are able to communicate with each other. More detailed information on these maps, as well as the different types of maps which are available can be found in the `eBPF maps` section of the `BPF` [linux documentation](https://man7.org/linux/man-pages/man2/bpf.2.html). For the sake of this demo we will arbitrarily decide on `RingBuffer`.

```bash
? What type of map should we initialize: 
    RingBuffer
  ▸ HashMap
```

After deciding on a map type, you will be asked to decide on an output format. This step is the first that gets into the detail and magic of `bee`. Normally developing `eBPF` applications requires writing user space, and kernel space code. However, with `bee` you only need to develop the kernel space code, and then `bee` can automatically handle and output the data in your specified format. The 2 main output types available currently are: `stats`, and `print`. More information on these can be found in the [output formats](#Output-Formats) section below. We will be choosing `print` as a simple example.

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
	// 2. Add rinbuf struct data here.
} __attribute__((packed));

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here: https://www.man7.org/linux/man-pages/man2/bpf.2.html
struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} events SEC(".maps.print");


SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
// Init event pointer
	struct event_t *event;

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
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

There's quite a bit of content in this file, so let's dive in
