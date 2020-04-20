#!/bin/sh
rm -rf target
cargo rustc --release -- --emit=llvm-ir
mkdir -p target/bpf
cp target/release/deps/rust_xdp_modules-*.ll target/bpf/rust_xdp_modules.ll
cargo rustc --release -- --emit=llvm-bc
cp target/release/deps/rust_xdp_modules-*.bc target/bpf/rust_xdp_modules.bc
llc target/bpf/rust_xdp_modules.bc -march=bpf -filetype=obj -o target/bpf/rust_xdp_modules.o