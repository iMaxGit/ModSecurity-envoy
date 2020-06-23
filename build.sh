#!/bin/bash

if [ ! -f envoy/VERSION ]; then
    echo "Downloading submodule"
    git suubmoduule update --init
    echo "Done"
fi

ENVOY_VER=$(cat envoy/VERSION)

read -p "Build with envoy v${ENVOY_VER} [Y/n]: " -r

if [ ! -e $REPLY ] && [[ ! $REPLY =~ ^[Yy]$ ]]; then
    cd envoy
    echo "All versions:"
    git ls-remote --tags 2> /dev/null | grep -o "refs/tags/.*" | sort -rV | grep -o '[^\/]*$'
    echo
    read -p "Choise version: " -r
    git checkout $REPLY
    cd ..
fi

echo "Write workspace file"

cat <<EOL > WORKSPACE
workspace(name = "envoy_filter_modsecurity")

local_repository(
    name = "envoy",
    path = "envoy",
)
EOL

cat envoy/WORKSPACE | sed -e '1d' | sed -e 's|//bazel|@envoy//bazel|g' >> WORKSPACE

echo "Start build"

bazel build //:envoy
