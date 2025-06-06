redo-ifchange envrc deps

. ./envrc

redo-ifchange ninja_generate plugins.list
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/debug
mkdir -p $BUILD_DIR/release

CFLAGS="-Og -g" ./ninja_generate > $BUILD_DIR/debug/build.ninja
CFLAGS="-O2" ./ninja_generate > $BUILD_DIR/release/build.ninja

redo-ifchange $BUILD_DIR/debug/build.ninja
redo-ifchange $BUILD_DIR/release/build.ninja
