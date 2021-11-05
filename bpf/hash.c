#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct labels_t {
	u32 pid;
	u32 type;
	u64 addr;
	u64 skb_addr;
	u64 ts;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct labels_t);
	__type(value, u64);
} kprobe_map SEC(".maps");

SEC("kprobe/tcp_retransmit_skb")
int kprobe_retransmit_skb(struct pt_regs *ctx) {
  struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);
  struct event_t task_info;
  task_info.pid = bpf_get_current_pid_tgid();
	task_info.addr = PT_REGS_IP(ctx);
	task_info.skb_addr = (u64) skb;
	task_info.ts = bpf_ktime_get_ns();

  u64 initval = 1, *valp;

  valp = bpf_map_lookup_elem(&kprobe_map, &task_info);
  if (!valp) {
      bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
      return 0;
  }
  __sync_fetch_and_add(valp, 1);

  return 0;
}
