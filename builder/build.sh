#! /bin/bash
set -eu

clang-13 -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -c $1 -o $2

# strip debug sections (see: https://github.com/libbpf/libbpf-bootstrap/blob/94000ca67c5e7be4741c09c435c9ae1777822378/examples/c/Makefile#L65)
llvm-strip-13 -g $2
