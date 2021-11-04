module github.com/solo-io/ebpf-ext

go 1.17

require github.com/cilium/ebpf v0.7.0

require golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 // indirect

replace github.com/cilium/ebpf => github.com/solo-io/ebpf v0.7.1-0.20211104114948-e8fdf7d423c5
