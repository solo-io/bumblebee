package initialize

type templateData struct {
	StructData   string
	MapData      MapData
	FunctionBody string
	RenderedMap  string
}

type MapData struct {
	OutputType  string
	MapTemplate string
}

const (
	languageC = "C"
)

// map of language name to description
var supportedLanguages = []string{
	languageC,
}

const (
	ringBuf = "RingBuffer"
	hashMap = "HashMap"
)

var supportedMapTypes = []string{ringBuf, hashMap}
var mapTypeToTemplateData = map[string]*templateData{
	ringBuf: ringbufTemplate(),
	hashMap: hashMapTemplate(),
}

func ringbufTemplate() *templateData {
	return &templateData{
		StructData: ringbufStruct,
		MapData: MapData{
			MapTemplate: ringbufMapTmpl,
		},
		FunctionBody: ringbufBody,
	}
}

func hashMapTemplate() *templateData {
	return &templateData{
		StructData: hashKeyStruct,
		MapData: MapData{
			MapTemplate: hashMapTmpl,
		},
		FunctionBody: hashMapBody,
	}
}

const (
	outputPrint   = "print"
	outputCounter = "counter"
	outputGauge   = "gauge"
)

var supportedOutputTypes = []string{outputPrint, outputCounter, outputGauge}
var mapOutputTypeToTemplateData = map[string]string{
	outputPrint:   ".print",
	outputCounter: ".counter",
	outputGauge:   ".gauge",
}

const ringbufMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} events SEC(".maps{{.OutputType}}");`

const ringbufStruct = `struct event_t {
	// 2. Add rinbuf struct data here.
} __attribute__((packed));`

const ringbufBody = `// Init event pointer
	struct event_t *event;

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}

	// 3. set data for our event,
	// For example:
	// event->pid = bpf_get_current_pid_tgid();

	bpf_ringbuf_submit(event, 0);`

const hashMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dimensions_t);
	__type(value, u64);
} values SEC(".maps{{.OutputType}}");`

const hashKeyStruct = `struct dimensions_t {
	// 2. Add dimensions to your value. This struct will be used as the key in the hash map of your data.
	// These will be treated as labels on your metrics.
	// In this example we will have single field which contains the PID of the process
	u32 pid;
} __attribute__((packed));`

const hashMapBody = `	// initialize our struct which will be the key in the hash map
	struct dimensions_t key;
	// initialize variable used to track PID of process calling tcp_v4_connect
	u32 pid;
	// define variable used to track the count of function calls, and a pointer to it for plumbing
	u64 counter;
	u64 *counterp;

	// get the pid for the current process which has entered the tcp_v4_connect function
	pid = bpf_get_current_pid_tgid();
	key.pid = pid;

	// check if we have an existing value for this key
	counterp = bpf_map_lookup_elem(&values, &key);
	if (!counterp) {
		// debug log to help see how the program works
		bpf_printk("no entry found for pid: %u}", key.pid);
		// no entry found, so this is the first occurrence, set value to 1
		counter = 1;
	}
	else {
		bpf_printk("found existing value '%llu' for pid: %u", *counterp, key.pid);
		// we found an entry, so let's increment the existing value for this PID
		counter = *counterp + 1;
	}
	// update our map with the new value of the counter
	bpf_map_update_elem(&values, &key, &counter, 0);`

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
{{ .RenderedMap }}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
{{ .FunctionBody }}

	return 0;
}
`
