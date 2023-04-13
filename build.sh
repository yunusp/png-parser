#!/bin/sh

set -xe
CC=cc
CFLAGS="-Wall -Wextra"
$CC $CFLAGS -o png png.c