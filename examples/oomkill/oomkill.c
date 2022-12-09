// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
/* Adapted for `bee` from: https://github.com/iovisor/bcc/blob/master/libbpf-tools/oomkill.bpf.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct data_t {
        __u32 fpid;
        __u32 tpid;
        __u64 pages;
        char fcomm[TASK_COMM_LEN];
        char tcomm[TASK_COMM_LEN];
};

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct data_t);
} oomkills SEC(".maps.counter");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
        struct data_t *e;

        e = bpf_ringbuf_reserve(&oomkills, sizeof(struct data_t), 0);
        if (!e) {
                return 0;
        }

        e->tpid = BPF_CORE_READ(oc, chosen, tgid);
        bpf_get_current_comm(&e->fcomm, TASK_COMM_LEN);

        e->fpid = bpf_get_current_pid_tgid() >> 32;
        e->pages = BPF_CORE_READ(oc, totalpages);
        bpf_probe_read_kernel(&e->tcomm, sizeof(e->tcomm), BPF_CORE_READ(oc, chosen, comm));

        bpf_ringbuf_submit(e, 0);

        return 0;
}

char LICENSE[] SEC("license") = "GPL";
