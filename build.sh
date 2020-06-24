#!/bin/bash

function check_modsecurity() {
    if [ -d /usr/local/modsecurity/lib/pkgconfig ]; then
        export PKG_CONFIG_PATH="/usr/local/modsecurity/lib/pkgconfig:$PKG_CONFIG_PATH"
        export LD_LIBRARY_PATH="/usr/local/modsecurity/lib:$LD_LIBRARY_PATH"
    fi

    if ! pkg-config modsecurity --exists; then
        echo "Not found ModSecurity"
        exit 1
    fi
}

function gen_workspace() {
    cat <<EOL > WORKSPACE
workspace(name = "envoy_filter_modsecurity")

local_repository(
    name = "envoy",
    path = "envoy",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_pkg_config",
    strip_prefix = "bazel_pkg_config-master",
    urls = ["https://github.com/cherrry/bazel_pkg_config/archive/master.zip"],
)

load("@bazel_pkg_config//:pkg_config.bzl", "pkg_config")

pkg_config(
    name = "modsecurity",
    ignore_opts = [
        "-lmodsecurity"
    ]
)
EOL
    # patch envoy workspace
    cat envoy/WORKSPACE | sed -e '1d' | sed -e 's|//bazel|@envoy//bazel|g' >> WORKSPACE
}

if [ ! -f envoy/VERSION ]; then
    if [ -d .git ]; then
        echo "Downloading submodule"
        git suubmoduule update --init
        echo "Done"
    else
        echo "Please download envoy source"
        exit 1
    fi
fi

case $1 in
    list-versions )
        cd envoy
        if [ -d .git ]; then
            git ls-remote --tags 2> /dev/null | grep -o "refs/tags/.*" | sort -rV | grep -o '[^\/]*$'
        else
            echo "Not clone from git"
            exit 1
        fi
        ;;
    version )
        echo "v$(cat envoy/VERSION)"
        ;;
    set-version )
        cd envoy
        if [ -d .git ]; then
            git checkout $2
        else
            echo "Not clone from git"
            exit 1
        fi
        ;;
    test )
        check_modsecurity

        # show version to build
        echo "Test with envoy $($0 version)"

        gen_workspace

        bazel test //:envoy_binary_test || exit 1
        bazel test //http-filter-example:http_filter_integration_test || exit 1
        ;;
    build )

        check_modsecurity

        # show version to build
        echo "Build with envoy $($0 version)"

        gen_workspace

        echo "Start build"

        bazel build //:envoy || exit 1

        echo "Done!"
        ;;
    help|*)
        echo "$0 <command [args...]>"
        echo
        echo "Commands:"
        echo "    list-versions      List online envoy versions"
        echo "    version            Get current envoy version"
        echo "    set-version <ver>  Set envoy version"
        echo "    build              Start build"
        echo "    help               This message"
        ;;
esac
