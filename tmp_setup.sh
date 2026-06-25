#!/bin/bash
set -e

wget https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-minirootfs-3.19.0-x86_64.tar.gz
mkdir -p /tmp/minirootfs
sudo tar -xzf alpine-minirootfs-3.19.0-x86_64.tar.gz -C /tmp/minirootfs

sleep 1

rm alpine-minirootfs-3.19.0-x86_64.tar.gz
echo "Cleaning Up..."