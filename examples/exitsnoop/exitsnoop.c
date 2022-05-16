/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Adapted for `bee` from: https://github.com/iovisor/bcc/blob/master/libbpf-tools/exitsnoop.bpf.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

const volatile pid_t target_pid = 0;
const volatile bool trace_failed_only = false;
const volatile bool trace_by_process = true;

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} exits SEC(".maps.print");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        __u32 tid = (__u32)pid_tgid;
        int exit_code;
        struct task_struct *task;
        struct event event = {};

        if (target_pid && target_pid != pid)
                return 0;

        if (trace_by_process && pid != tid)
                return 0;

        task = (struct task_struct *)bpf_get_current_task();
        exit_code = BPF_CORE_READ(task, exit_code);
        if (trace_failed_only && exit_code == 0)
                return 0;

        event.start_time = BPF_CORE_READ(task, start_time);
        event.exit_time = bpf_ktime_get_ns();
        event.pid = pid;
        event.tid = tid;
        event.ppid = BPF_CORE_READ(task, real_parent, tgid);
        event.sig = exit_code & 0xff;
        event.exit_code = exit_code >> 8;
        bpf_get_current_comm(event.comm, sizeof(event.comm));

        struct event *ring_val;

        ring_val = bpf_ringbuf_reserve(&exits, sizeof(struct event), 0);
        if (!ring_val) {
                return 0;
        }

        memcpy(ring_val, &event, sizeof(struct event));

        /* submit event to ringbuf for printing */
        bpf_ringbuf_submit(ring_val, 0);

        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";