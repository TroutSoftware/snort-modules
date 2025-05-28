redo-ifchange envrc deps

. ./envrc

redo-ifchange ninja_generate plugins.list
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/debug
mkdir -p $BUILD_DIR/release

PD=$PD ID=$ID INSTALL_DIR=$INSTALL_DIR CFLAGS="-Og -g" ./ninja_generate > $BUILD_DIR/debug/build.ninja
PD=$PD ID=$ID INSTALL_DIR=$INSTALL_DIR CFLAGS="-O2" ./ninja_generate > $BUILD_DIR/release/build.ninja

redo-ifchange $BUILD_DIR/debug/build.ninja
redo-ifchange $BUILD_DIR/release/build.ninja
