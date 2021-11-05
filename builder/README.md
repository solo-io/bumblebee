
### Build image
```
make build
```

### Build eBPF
```
sudo docker run -v "$PWD":/usr/src/bpf bpfbuilder <bpf program file> <ELF output file>
```