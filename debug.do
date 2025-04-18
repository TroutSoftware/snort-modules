redo-ifchange envrc

. ./envrc
redo-ifchange configure plugins.list $PD/snort_plugins.cc
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p p/debug
CFLAGS="-O1 -g" ./configure > p/debug/build.ninja
ninja -C p/debug >&2
redo-ifchange p/debug/tm.so # detect manual clean