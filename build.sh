set -e

if [ -z "$1" ]; then
    echo "Usage: build.sh <bin>"
    exit 1
fi

cargo build --release --bin "$1"

if [ -f "src/ffi/$1.rs" ]; then
    cargo rustc --release --lib --crate-type cdylib
fi
