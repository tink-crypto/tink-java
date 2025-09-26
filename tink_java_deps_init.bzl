"""Initialization of dependencies of Java Tink."""

load("@build_bazel_rules_android//android:rules.bzl", "android_sdk_repository")
load("@com_google_protobuf//:protobuf_deps.bzl", javalite_protobuf_deps = "protobuf_deps")

def tink_java_deps_init():
    """Initializes dependencies of Java Tink."""
    javalite_protobuf_deps()

    android_sdk_repository(
        name = "androidsdk",
        api_level = 30,
    )
