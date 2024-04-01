#!/usr/bin/env bash

cargo build -Z build-std=core --target bpfel-unknown-none $@
