# Overview

The oomkill example is heavily based on the [oomkill program in BCC's libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/oomkill.bpf.c), which is itself based on the original [BCC oomkill](https://github.com/iovisor/bcc/blob/master/tools/oomkill.py), created by Brendan Gregg.

The script traces the kernel out-of-memory killer, and prints details about which process was killed.

The main difference between the original program and this one, is that here, we are using a new BPF data structure, called [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html), while the original one is using BPF perf buffer.

Due to this decision, this version can be only used starting from Linux 5.8 kernel version, however this data structure solves multiple shortcomings of perfbuf, e.g. event ordering, and memory utilization, and using it instead of perfbuf is considered the current best practice.

# Usage

To see all the oomkills in your environment, you can run your image without filters:

```console
bee run ghcr.io/solo-io/bumblebee/oomkill:$(bee version)
```

You can also try out the filtering capability by referencing fields in your BPF map:

```c
struct data_t {
        __u32 fpid;
        __u32 tpid;
        __u64 pages;
        char fcomm[TASK_COMM_LEN];
        char tcomm[TASK_COMM_LEN];
};
```

The fields `tcomm`, and `tpid` identify the process that was oomkilled, while `fcomm` and `fpid` are details about the process that was triggering the oomkiller.

For example, to filter for all the oomkills where the oomkilled process is `bash`, you can use: 

```console
bee run -f="exits,tcomm,bash" ghcr.io/solo-io/bumblebee/oomkill:$(bee version)
```

# Prometheus integration

Visualizing and alerting on oomkills is crucial, and Bumblebee can help you with that.

Since we have the `counter_` prefix added to our `oomkills` map, exposing the oomkill events as a `counter` metric is enabled by default:

```c
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct data_t);
} counter_oomkills SEC(".maps");
```

To disable this functionality, you can change the prefix to `print_`.
