package initialize

const (
	languageC = "C"
)

type TemplateOption struct {
	Name     string
	Template string
}

func (o TemplateOption) String() string {
	return o.Name
}

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

var (
	print = TemplateOption{
		Name:     "print",
		Template: ".print",
	}
	counter = TemplateOption{
		Name:     "counter",
		Template: ".counter",
	}
	gauge = TemplateOption{
		Name:     "gauge",
		Template: ".gauge",
	}
)
var outputDict = map[string]TemplateOption{
	print.Name:   print,
	counter.Name: counter,
	gauge.Name:   gauge,
}
var supportedOutputTypes = []TemplateOption{print, counter, gauge}

type templateData struct {
	StructData   string
	MapData      MapData
	FunctionBody string
	RenderedMap  string
}

type MapData struct {
	MapType     string
	OutputType  TemplateOption
	MapTemplate string
}

func ringbufTemplate() *templateData {
	return &templateData{
		StructData: ringbufStruct,
		MapData: MapData{
			MapType:     ringBuf,
			MapTemplate: ringbufMapTmpl,
		},
		FunctionBody: ringbufBody,
	}
}

func hashMapTemplate() *templateData {
	return &templateData{
		StructData: hashKeyStruct,
		MapData: MapData{
			MapType:     hashMap,
			MapTemplate: hashMapTmpl,
		},
		FunctionBody: hashMapBody,
	}
}

const ringbufMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} events SEC(".maps{{.OutputType.Template}}");`

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

	bpf_ringbuf_submit(event, 0);
`

const hashMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dimensions_t);
	__type(value, u64);
} values SEC(".maps{{.OutputType.Template}}");`

const hashKeyStruct = `struct dimensions_t {
	// 2. Add dimensions to your value. This struct will be used as the key in the hash map of your data.
	// These will be treated as labels on your metrics.
	// In this example we will have single field which contains the PID of the process
	u32 pid;
} __attribute__((packed));`

const hashMapBody = `// initialize our struct which will be the key in the hash map
	struct dimensions_t key;
	u32 pid;
	u64 counter;
	u64 *counterp;

	// get the pid for the current process which has entered the tcp_v4_connect function
	pid = bpf_get_current_pid_tgid();
	key.pid = pid;

	// check if we have an existing value for this key
	counterp = bpf_map_lookup_elem(&values, &key);
	if (!counterp) {
		bpf_printk("no entry found for pid: %u}", key.pid);
		counter = 1;
	}
	else {
		bpf_printk("found existing value '%llu' for pid: %u", *counterp, key.pid);
		counter = *counterp + 1;
	}
	bpf_map_update_elem(&values, &key, &counter, 0);
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
{{ .RenderedMap }}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
{{ .FunctionBody }}

	return 0;
}
`
