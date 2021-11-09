#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	u32 uid;
	u32 type;
	duration uptime;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event_t);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	struct event_t *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = bpf_get_current_pid_tgid();
	task_info->uid = bpf_get_current_uid_gid();
	task_info->uptime = bpf_ktime_get_ns();

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
