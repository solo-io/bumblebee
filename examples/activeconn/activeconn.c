#include "vmlinux.h"
#include "solo_types.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "unistd.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct dimensions_t {
	ipv4_addr saddr;
	ipv4_addr daddr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dimensions_t);
	__type(value, u64);
} gauge_sockets_ext SEC(".maps");

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	bpf_printk("enter called");

	bpf_printk("enter: setting sk for tid: %u", tid);
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
record(struct pt_regs *ctx, int ret, int op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;

	__u32 saddr;
	__u32 daddr;
	u64 val;
	u64 *valp;
  __u32 myval;
	struct dimensions_t key = {};

	bpf_printk("exit: getting sk for tid: '%u', ret is: '%d'", tid, ret);
	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp) {
		bpf_printk("exit: no pointer for tid, returning: %u", tid);
		return 0;
	}
	sk = *skpp;

	bpf_printk("exit: found sk for tid: %u", tid);
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	key.saddr = saddr;
	key.daddr = daddr;

	valp = bpf_map_lookup_elem(&gauge_sockets_ext, &key);
	if (!valp) {
		bpf_printk("no entry for {saddr: %u, daddr: %u}", key.saddr, key.daddr);
		val = 1;
	}
	else {
		bpf_printk("found existing value '%llu' for {saddr: %u, daddr: %u}", *valp, key.saddr, key.daddr);
		val = *valp + op;
	}
	bpf_map_update_elem(&gauge_sockets_ext, &key, &val, 0);
	bpf_map_delete_elem(&sockets, &tid);

	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	return record(ctx, ret, 1);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_close")
int BPF_KRETPROBE(tcp_close_ret, int ret)
{
	return record(ctx, ret, -1);
}

