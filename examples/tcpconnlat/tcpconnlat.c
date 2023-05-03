// Based on: https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "solo_types.h"

#define TASK_COMM_LEN   16

struct event {
        ipv4_addr saddr_v4;
        ipv4_addr daddr_v4;
        char comm[TASK_COMM_LEN];
        __u64 delta_us;
        __u64 ts_us;
        __u32 tgid;
        int af;
};

struct piddata {
        char comm[TASK_COMM_LEN];
        u64 ts;
        u32 tgid;
};

//Commenting these and the corresponding logic out until we have support for kernel-side filtering.
//const volatile __u64 targ_min_us = 0;
//const volatile pid_t targ_tgid = 0;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, struct sock *);
        __type(value, struct piddata);
} start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} print_events SEC(".maps");

static int trace_connect(struct sock *sk)
{
        u32 tgid = bpf_get_current_pid_tgid() >> 32;
        struct piddata piddata = {};

//        if (targ_tgid && targ_tgid != tgid)
//                return 0;

        bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
        piddata.ts = bpf_ktime_get_ns();
        piddata.tgid = tgid;
        bpf_map_update_elem(&start, &sk, &piddata, 0);
        return 0;
}

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
        struct piddata *piddatap;
        struct event event = {};
        s64 delta;
        u64 ts;

        if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
                return 0;

        piddatap = bpf_map_lookup_elem(&start, &sk);
        if (!piddatap)
                return 0;

        ts = bpf_ktime_get_ns();
        delta = (s64)(ts - piddatap->ts);
        if (delta < 0) {
                bpf_map_delete_elem(&start, &sk);
                return 0;
        }

        event.delta_us = delta / 1000U;

//        if (targ_min_us && event.delta_us < targ_min_us) {
//                bpf_map_delete_elem(&start, &sk);
//                return 0;
//        }

        __builtin_memcpy(&event.comm, piddatap->comm,
                        sizeof(event.comm));
        event.ts_us = ts / 1000;
        event.tgid = piddatap->tgid;
        event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        struct event *ring_val;

        ring_val = bpf_ringbuf_reserve(&print_events, sizeof(struct event), 0);
        if (!ring_val) {
                return 0;
        }

        memcpy(ring_val, &event, sizeof(struct event));

        bpf_ringbuf_submit(ring_val, 0);

        return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
        return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
        return handle_tcp_rcv_state_process(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";
