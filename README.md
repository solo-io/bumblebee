# glooBPF
Staging ground for solo-io eBPF work


### Build image
```
make docker-build
```

### Build eBPF
```
sudo docker run -v "$PWD":/usr/src/bpf bpfbuilder <bpf program file> <ELF output file>
```

### Run eBPF
```
go run -exec sudo ./ebpfctl/main.go run bpf/hash.o
```