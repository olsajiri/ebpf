#!/bin/bash

set -euo pipefail

source "$(dirname "$(realpath "$0")")/lib.sh"

tmp=$(mktemp -d)

cleanup() {
	rm -r "$tmp"
}

trap cleanup EXIT

# Download and process libbpf.c
if [ -z $KERNEL_LOCAL ]; then
  curl -fL "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/tools/lib/bpf/libbpf.c?h=v$KERNEL_VERSION" -o "$tmp/libbpf.c"

  # Download and process vmlinux and btf_testmod
  extract_oci_image "ghcr.io/cilium/ci-kernels:$KERNEL_VERSION" "$tmp"

  "/lib/modules/$(uname -r)/build/scripts/extract-vmlinux" "$tmp/boot/vmlinuz" > "$tmp/vmlinux"
else
  cp $KERNEL_LOCAL/libbpf.c $tmp
  cp $KERNEL_LOCAL/vmlinux $tmp
  mkdir -p $tmp/lib/modules
  cp $KERNEL_LOCAL/bpf_testmod.ko $tmp/lib/modules
fi

"./internal/cmd/gensections.awk" "$tmp/libbpf.c" | gofmt > "./elf_sections.go"

objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip > "btf/testdata/vmlinux.btf.gz"
find "$tmp/lib/modules" -type f -name bpf_testmod.ko -exec objcopy --dump-section .BTF="btf/testdata/btf_testmod.btf" {} /dev/null \;
