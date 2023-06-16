package initialize

type templateData struct {
	StructData   string
	MapData      OutputTypeTemplate
	FunctionBody OutputTypeTemplate
	RenderedMap  string
	RenderedBody string
}

type OutputTypeTemplate struct {
	OutputType string
	Template   string
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

	network    = "Network"
	fileSystem = "FileSystem"
)

var supportedProgramTypes = []string{network, fileSystem}

var supportedMapTypes = []string{ringBuf, hashMap}
var mapTypeToTemplateData = map[string]*templateData{
	ringBuf: ringbufTemplate(),
	hashMap: hashMapTemplate(),
}

func ringbufTemplate() *templateData {
	return &templateData{
		StructData: ringbufStruct,
		MapData: OutputTypeTemplate{
			Template: ringbufMapTmpl,
		},
		FunctionBody: OutputTypeTemplate{
			Template: ringbufBody,
		},
	}
}

func hashMapTemplate() *templateData {
	return &templateData{
		StructData: hashKeyStruct,
		MapData: OutputTypeTemplate{
			Template: hashMapTmpl,
		},
		FunctionBody: OutputTypeTemplate{
			Template: hashMapBody,
		},
	}
}

const (
	outputPrint   = "print"
	outputCounter = "counter"
	outputGauge   = "gauge"
)

var supportedOutputTypes = []string{outputPrint, outputCounter, outputGauge}
var mapOutputTypeToTemplateData = map[string]string{
	outputPrint:   "print_",
	outputCounter: "counter_",
	outputGauge:   "gauge_",
}

const openAtStruct = `// This struct represents the data we will gather from the tracepoint to send to our ring buffer map
// The 'bee' runner will watch for entries to our ring buffer and print them out for us
struct event {
	// In this example, we have a single field, the filename being opened
	char fname[255];
};`

const openAtMap = `struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	// Define the type of struct that will be submitted to the ringbuf
	// This allows the bee runner to dynamically read and output the data from the ringbuf
	__type(value, struct event);
} print_events SEC(".maps");`

const openAtBody = `// Attach our bpf program to the tracepoint for the openat() syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	// initialize the event struct which we will send the the ring buffer
	struct event event = {};

	// use a bpf helper function to read a string containing the filename 
	// the filename comes from the tracepoint we are attaching to
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ctx->args[1]);

	// create a pointer which will be used to access memory in the ring buffer
	struct event *ring_val;

	// use another bpf helper to reserve memory for our event in the ring buffer
	// our pointer will now point to the correct location we should write our event to
	ring_val = bpf_ringbuf_reserve(&print_events, sizeof(struct event), 0);
	if (!ring_val) {
		return 0;
	}
	
	// copy our event into the ring buffer
	memcpy(ring_val, &event, sizeof(struct event));

	// submit the event to the ring buffer
	bpf_ringbuf_submit(ring_val, 0);

	return 0;
}`

const ringbufMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__type(value, struct event_t);
} {{.OutputType}}events SEC(".maps");`

const ringbufStruct = `struct event_t {
	// 2. Add ringbuf struct data here.
} __attribute__((packed));`

const ringbufBody = `SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	// Init event pointer
	struct event_t *event;

	// Reserve a spot in the ringbuffer for our event
	event = bpf_ringbuf_reserve(&{{.OutputType}}events, sizeof(struct event_t), 0);
	if (!event) {
		return 0;
	}

	// 3. set data for our event,
	// For example:
	// event->pid = bpf_get_current_pid_tgid();

	bpf_ringbuf_submit(event, 0);
	
	return 0;
}`

const hashMapTmpl = `struct {
	__uint(max_entries, 1 << 24);
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dimensions_t);
	__type(value, u64);
} {{.OutputType}}values SEC(".maps");`

const hashKeyStruct = `struct dimensions_t {
	// 2. Add dimensions to your value. This struct will be used as the key in the hash map of your data.
	// These will be treated as labels on your metrics.
	// In this example we will have single field which contains the PID of the process
	u32 pid;
} __attribute__((packed));`

const hashMapBody = `SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	// initialize our struct which will be the key in the hash map
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
	counterp = bpf_map_lookup_elem(&{{.OutputType}}values, &key);
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
	bpf_map_update_elem(&values, &key, &counter, 0);
	
	
	return 0;
}`

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

{{ .RenderedBody }}
`
