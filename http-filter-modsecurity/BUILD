load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_package",
)

load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

envoy_package()

api_proto_package(
    deps = [
        "@envoy_api//envoy/api/v2/core:pkg",
        "@envoy_api//envoy/config/core/v3:pkg",
        "@com_github_cncf_udpa//udpa/annotations:pkg",
    ]
)

envoy_cc_library(
    name = "webhook_fetch_lib",
    srcs = ["webhook_fetcher.cc"],
    hdrs = ["webhook_fetcher.h"],
    repository = "@envoy",
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "modsecurity_filter_lib",
    srcs = ["modsecurity_filter.cc", "utility.cc"],
    hdrs = ["modsecurity_filter.h", "utility.h", "webhook_fetcher.h"],
    repository = "@envoy",
    deps = [
        ":pkg_cc_proto",
        ":webhook_fetch_lib",
        #"@envoy//include/envoy/upstream:cluster_manager_interface", # v1.18
        "@envoy//envoy/upstream:cluster_manager_interface", # v1.20
        "@envoy//source/common/http:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@modsecurity//:lib",
        "@envoy//source/exe:envoy_common_lib",
	"@envoy//envoy/http:filter_interface",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    #category = "envoy.filters.http", # v1.18
    #security_posture = "unknown", # v1.18
    repository = "@envoy",
    deps = [
        ":modsecurity_filter_lib",
        #"@envoy//include/envoy/registry", # v1.18
        "@envoy//envoy/registry",
        "@envoy//source/common/protobuf:utility_lib",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
    ],
    visibility = ["//visibility:public"],
)

envoy_cc_test(
    name = "modsecurity_filter_integration_test",
    srcs = ["modsecurity_filter_integration_test.cc"],
    repository = "@envoy",
    deps = [
        ":modsecurity_filter_config",
        "@envoy//test/integration:http_integration_lib",
    ],
)
