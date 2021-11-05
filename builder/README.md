
### Build image
```
make build
```

### Build eBPF
```
sudo docker run -v "$PWD":/usr/src/bpf bpfbuilder build.sh <bpf program file> <ELF output file>
```