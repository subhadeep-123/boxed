#!/bin/bash
set -e

wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz
# Extract without sudo: --rootless maps container root to the invoking user,
# so the rootfs must be owned by that user to be writable inside the container.
mkdir -p /tmp/minirootfs
tar -xzf alpine-minirootfs-3.19.0-x86_64.tar.gz -C /tmp/minirootfs

# Layered fixture for --image tests: 00-base is the same Alpine rootfs,
# 01-app contributes a marker file to prove multi-layer stacking works.
mkdir -p /tmp/boxed-layers/00-base /tmp/boxed-layers/01-app
sudo tar -xzf alpine-minirootfs-3.19.0-x86_64.tar.gz -C /tmp/boxed-layers/00-base
sudo sh -c 'echo app-layer-marker > /tmp/boxed-layers/01-app/app-marker.txt'

sleep 1

rm alpine-minirootfs-3.19.0-x86_64.tar.gz
echo "Cleaning Up..."