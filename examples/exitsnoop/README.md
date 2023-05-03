# Overview

The exitsnoop example is heavily based on the [exitsnoop program in BCC's libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/exitsnoop.bpf.c), which is itself based on the original [BCC exitsnoop](https://github.com/iovisor/bcc/blob/master/tools/exitsnoop.py).

This eBPF program will trace all process termination (exit, fatal signals).

# Usage

To see all the syscalls in your environment, you can run your image without filters:

```console
bee run ghcr.io/solo-io/bumblebee/exitsnoop:$(bee version)
```

You can also try out the filtering capability by referencing fields in your BPF map:

```c
struct event {
        __u64 start_time;
        __u64 exit_time;
        __u32 pid;
        __u32 tid;
        __u32 ppid;
        __u32 sig;
        int exit_code;
        char comm[TASK_COMM_LEN];
};
```

For example, to filter for all the syscalls where the `comm` is `bash`, you can use: 

```console
bee run -f="print_exits,comm,bash" ghcr.io/solo-io/bumblebee/exitsnoop:$(bee version)
```

# Prometheus integration

Let's say, you want to visualize the rate of such syscalls in your Prometheus stack, or want to alert on certain syscalls.

You can modify your `print_exits` map to generate a `counter` from your exit() calls:

```c
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} counter_exits SEC(".maps");
```

This will generate Prometheus metrics like this:

```console
# HELP ebpf_solo_io_counter_exits
# TYPE ebpf_solo_io_counter_exits counter
ebpf_solo_io_counter_exits{comm="infocmp",exit_code="0",exit_time="2396600383928",pid="16234",ppid="16221",sig="0",start_time="2396599269958",tid="16234"} 1
ebpf_solo_io_counter_exits{comm="ip6tables",exit_code="0",exit_time="2402597588547",pid="16237",ppid="2115",sig="0",start_time="2402596148575",tid="16237"} 1
ebpf_solo_io_counter_exits{comm="iptables",exit_code="0",exit_time="2397474999464",pid="16235",ppid="2115",sig="0",start_time="2397473028592",tid="16235"} 1
```

Note that some of the fields are not important in this usecase, and these can also overload your Prometheus instace, so if your use-case is only about Prometheus, you should consider removing these high cardinality fields from your map.
`exit_time`, `start_time`, are fields that should be removed in this case.