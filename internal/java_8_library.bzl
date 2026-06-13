load("@rules_java//java:java_library.bzl", "java_library")

def java_8_library(name, javacopts = [], **kwargs):
    java_library(
        name = name,
        javacopts = javacopts + ["--release", "8"],
        **kwargs
    )
