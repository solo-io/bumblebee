#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	u32 type;
	u64 addr;
	u64 skb_addr;
	u64 ts;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event_t);
} events SEC(".maps");


SEC("kprobe/tcp_retransmit_skb")
int kprobe_retransmit_skb(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);
	struct event_t *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = bpf_get_current_pid_tgid();
	task_info->addr = PT_REGS_IP(ctx);
	task_info->skb_addr = (u64) skb;
	task_info->ts = bpf_ktime_get_ns();

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
