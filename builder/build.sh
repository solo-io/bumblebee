#! /bin/bash
set -eu

clang-13 -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -c $1 -o $2

