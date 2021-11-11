package initialize

const (
	languageC = "C"

	mapTypeRingbuffer = "RingBuffer"
	mapTypeHash       = "HashMap"
)

// map of language name to description
var supportedLanguages = []string{
	languageC,
}

var supportedMapTypes = []string{
	mapTypeHash,
	mapTypeRingbuffer,
}

var mapTypeToTemplateData = map[string]*templateData{
	mapTypeRingbuffer: ringbufTemplate(),
	// Create hash templates
	mapTypeHash: ringbufTemplate(),
}

type templateData struct {
	StructData   string
	MapData      string
	FunctionBody string
}

func ringbufTemplate() *templateData {
	return &templateData{
		StructData:   ringbufStruct,
		MapData:      ringbufMap,
		FunctionBody: ringbufBody,
	}
}

const ringbufMap = `struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event_t);
} events SEC(".maps.print");`

const ringbufStruct = `struct event_t {
	// 2. Add rinbuf struct data here.
} __attribute__((packed));`

const ringbufBody = `
	// Init event pointer
	struct event_t *event;

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}

	// 3. set data for our event,
	// For example:
	// event->pid = bpf_get_current_pid_tgid();

	bpf_ringbuf_submit(event, 0);
`

const fileTemplate = `#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

// 1. Change the license if necessary 
char __license[] SEC("license") = "Dual MIT/GPL";

{{ .StructData }}

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here: https://www.man7.org/linux/man-pages/man2/bpf.2.html
{{ .MapData }}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
{{ .FunctionBody }}

	return 0;
}
`
