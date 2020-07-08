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
    ],
    min_version = "3.0.4"
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
        if [ -f .git ] || [ -d .git ]; then
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
        if [ -f .git ] || [ -d .git ]; then
            git pull origin HEAD
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

        bazel test //:envoy_binary_test ${@:2} || exit 1
        bazel test //http-filter-modsecurity:modsecurity_filter_integration_test ${@:2} || exit 1

        echo "Done!"
        ;;
    build )

        check_modsecurity

        # show version to build
        echo "Build with envoy $($0 version)"

        gen_workspace

        echo "Start build"

        bazel build //:envoy ${@:2} || exit 1

        echo "Done!"
        ;;
    install )
        if [ ! -f bazel-bin/envoy ]; then
            $0 build || exit 1
        fi
        install -m 755 -s bazel-bin/envoy /usr/local/bin/envoy
        echo "Done!"
        ;;
    help|*)
        echo "$0 <command [args...]>"
        echo
        echo "Commands:"
        echo "    list-versions      List online envoy versions (git)"
        echo "    version            Get current envoy version"
        echo "    set-version <ver>  Set envoy version (git)"
        echo "    build              Start build"
        echo "    test               Start test"
        echo "    install            Install envoy to system path"
        echo "    help               This message"
        ;;
esac
