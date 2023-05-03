# Overview

The capable example is heavily based on the [capable program in BCC repository](https://github.com/iovisor/bcc/blob/master/tools/capable.py), which is created by Brendan Gregg.
This eBPF program will trace all security capability checks (cap_capable() calls) in your system.

# Usage

To see all the syscalls in your environment, you can run your image without filters:

```console
bee run ghcr.io/solo-io/bumblebee/capable:$(bee version)
```

You can also try out the filtering capability by referencing fields in your BPF map:

```c
struct cap_event {
        __u64   mntnsid;
        __u32   pid;
        int     cap;
        __u32   tgid;
        __u32   uid;
        int     cap_opt;
        char    task[TASK_COMM_LEN];
};
```

For example, to filter for all the capability checks where the `task` is `ping`, you can use: 

```console
bee run -f="events,task,ping" ghcr.io/solo-io/bumblebee/capable:$(bee version)
```

# Prometheus integration

Let's say, you want to visualize the rate of such syscalls in your Prometheus stack, or want to alert on certain syscalls.

You can modify your `events` map to generate a `counter` from your cap_capable() calls:

> Note: you can rename `events` to `cap_events` to illustrate the goal of the exposed events better.

```c
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct cap_event);
} events SEC(".maps.counter");
```

You should consider removing high cardinality fields from your map to avoid overloading your Prometheus instance, e.g. `mntnsid`.
