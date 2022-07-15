// Based on: https://github.com/kinvolk/inspektor-gadget/blob/main/pkg/gadgets/capabilities/tracer/core/bpf/capable.bpf.c
// Copyright 2022 Sony Group Corporation

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN   16
#define MAX_ENTRIES     10240

struct cap_event {
        __u64   mntnsid;
        __u32   pid;
        int     cap;
        __u32   tgid;
        __u32   uid;
        int     cap_opt;
        char    task[TASK_COMM_LEN];
};

struct key_t {
        __u32   pid;
        __u32   tgid;
        int     user_stack_id;
        int     kern_stack_id;
};

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct cap_event);
} events SEC(".maps.print");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct key_t);
        __type(value, struct cap_event);
        __uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __uint(key_size, sizeof(u64));
        __uint(value_size, sizeof(u32));
} mount_ns_set SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kprobe__cap_capable, const struct cred *cred, struct user_namespace *targ_ns, int cap, int cap_opt)
{
        __u32 pid;
        u64 mntns_id;
        __u64 pid_tgid;
        struct key_t i_key;
        struct task_struct *task;

        task = (struct task_struct*) bpf_get_current_task();
        mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

        pid_tgid = bpf_get_current_pid_tgid();
        pid = pid_tgid >> 32;

        struct cap_event *event;

        event = bpf_ringbuf_reserve(&events, sizeof(struct cap_event), 0);
        if (!event) {
                return 0;
        }

        event->pid = pid;
        event->tgid = pid_tgid;
        event->cap = cap;
        event->uid = bpf_get_current_uid_gid();
        event->mntnsid = mntns_id;
        event->cap_opt = cap_opt;
        bpf_get_current_comm(&event->task, sizeof(event->task));

        bpf_ringbuf_submit(event, 0);

        return 0;
}

char LICENSE[] SEC("license") = "GPL";
