# Overview

The tcpconnlat example is heavily based on the [tcpconnlat program in BCC's libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c), which is itself based on the original [BCC tcpconnlat](https://github.com/iovisor/bcc/blob/master/tools/tcpconnlat.py).

This eBPF program will trace all TCP active connection latencies.

# Usage

To see all the connections in your environment, you can run your image without filters:

```console
bee run ghcr.io/solo-io/bumblebee/tcpconnlat:$(bee version)
```

You can also try out the filtering capability by referencing fields in your BPF map:

```c
struct event {
        ipv4_addr saddr_v4;
        ipv4_addr daddr_v4;
        char comm[TASK_COMM_LEN];
        __u64 delta_us;
        __u64 ts_us;
        __u32 tgid;
        int af;
};
```

For example, to filter for all active connections where the `daadr_v4` is `8.8.8.8`, you can use: 

```console
bee run -f="events,daddr_v4,8.8.8.8" ghcr.io/solo-io/bumblebee/tcpconnlat:$(bee version)
```

Result:

```console
af              comm                daddr_v4               delta_us               saddr_v4                  tgid                ts_us                   
2               telnet              8.8.8.8                1220                   10.132.0.48               15173               5149693413               
```

# Prometheus integration

Let's say, you want to visualize the latencies in your Prometheus stack, or want to alert on certain limits.

> Note that BumbleBee currently only supports counter and gauge metric types, so as of now, you cannot expose latency metrics as histograms. The support for histogram is on our [roadmap](https://github.com/solo-io/bumblebee/blob/main/ROADMAP.md).

> Also note that currently BumbleBee is exposing metrics for all the members of the struct describing the map as labels. As `ts_us` is there as a timestamp, the cardinality will explode quite soon, so **generate Prometheus metrics only in a lab or a very low traffic environment**.

You can modify your `events` map to generate a `counter` from your active connections:

```c
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} events SEC(".maps.counter");
```

This will generate Prometheus metrics like this:

```console
# HELP ebpf_solo_io_events 
# TYPE ebpf_solo_io_events counter
ebpf_solo_io_events{af="2",comm="coredns",daddr_v4="127.0.0.1",delta_us="44",saddr_v4="127.0.0.1",tgid="4508",ts_us="5914339221"} 1
ebpf_solo_io_events{af="2",comm="coredns",daddr_v4="127.0.0.1",delta_us="46",saddr_v4="127.0.0.1",tgid="4508",ts_us="5910339887"} 1
```
