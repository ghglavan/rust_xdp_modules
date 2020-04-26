#!/bin/sh

set -e

if [[ $# -ne 1 ]] ; then
    echo "Usage ./build.sh lib_name"
    exit 1
fi

lib=$1

lib_name=${lib//[-]/_}

rm -rf target
mkdir target
mkdir target/bpf
cd ${lib}

rm -rf target
cargo rustc --lib --release -- --emit=llvm-bc
cp target/release/deps/${lib_name}-*.bc ../target/bpf/${lib_name}.bc
cd ..
llc target/bpf/${lib_name}.bc -march=bpf -filetype=obj -o target/bpf/${lib_name}.o