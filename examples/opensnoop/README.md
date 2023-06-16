# Overview

The `opensnoop` example is heavily based on the [`opensnoop` program in the BCC's libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.c), which is itself based on the original [BCC `opensnoop`](https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py) created by Brendan Gregg. 

This eBPF program will trace all `open()` syscalls by attaching to tracepoints in the kernel and sending data related to `open()` call (e.g. which file name is being opened, which command is executing the `open()`, etc.) to a map which will then be streamed to the `bee` runner.

However, as you can probably imagine, there are quite a lot of `open()` syscalls happening on a system at any given time, so in order to make this info more digestable, `bee` provides support for filtering the output by regular expressions applied to the various fields in the data. Eventually we plan on exposing filters in the eBPF program itself through the `bee run` command as well.

To see this in action, you can run `opensnoop` without any filter, and you should see a fairly active stream of data:
```
bee run ghcr.io/solo-io/bumblebee/opensnoop:$(bee version)
```

Now we can start paring this down with the filtering capability. Let's run `opensnoop` with a filter applied, such as:
```
bee run -f="print_events,comm,node" ghcr.io/solo-io/bumblebee/opensnoop:$(bee version)
```
This command will run the `opensnoop` program (pulled from our GitHub container registry) and filter the entries in the `print_events` map to only entries that have a `comm` value of `node`. In other words, we will be viewing `open()` syscalls that have been initiated by the `node` command.

Note that the last field is a regex, so you can get more creative than simply adding the command name if you want.

As another example, if you wanted to filter for `open()`s by the root user (userid `0`) you could do:
```
bee run -f="print_events,uid,0" ghcr.io/solo-io/bumblebee/opensnoop:$(bee version)
```
