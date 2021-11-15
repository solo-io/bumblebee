# eBPF
Staging ground for solo-io eBPF work

## Installation

## Getting Started


### Build image
```
make docker-build
```

### Build eBPF

#### In Docker
```
go run -exec sudo ./ebpfctl/main.go build  <bpf program file> <ELF output file>

go run -exec sudo ./ebpfctl/main.go build bpf/ringbuf.c localhost:5000/oras:ringbuf-demo
```

#### Locally
```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

go run -exec sudo ./ebpfctl/main.go build -l <bpf program file> <ELF output file>
```


### Run eBPF
```
go run -exec sudo ./ebpfctl/main.go run bpf/hash.o
```