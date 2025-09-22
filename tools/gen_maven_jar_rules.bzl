# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Definition of gen_maven_jar_rules. """

load("@rules_jvm_external//:defs.bzl", "javadoc")
load("//tools:jar_jar.bzl", "jar_jar")
load("//tools:java_single_jar.bzl", "java_single_jar")

_TINK_PACKAGES = [
    "com.google.crypto.tink",
]

def gen_maven_jar_rules(
        name,
        deps = [],
        resources = [],
        root_packages = _TINK_PACKAGES,
        shaded_packages = [],
        shading_rules = "",
        exclude_packages = [],
        additional_javadoc_dependencies = [],
        manifest_lines = [],
        create_snapshot_bundle = False,
        pom_template_for_snapshot_bundle = None):
    """
    Generates rules that generate Maven jars for a given package.

    Args:
      name: Given a name, this function generates 3 rules: a compiled package
        name.jar, a source package name-src.jar and a Javadoc package
        name-javadoc.jar.
      deps: A combination of the deps of java_single_jar and javadoc_library
      resources: A list of resource files. Files must be stored in
        src/main/resources. Mapping rules: src/main/resources/a/b/c.txt will be
        copied to a/b/c.txt in the output jar.
      root_packages: See javadoc_library
      shaded_packages: These packages will be shaded, according to the rules
        specified in shading_rules.
      shading_rules: The shading rules, must specified when shaded_packages is present.
        Rules file format can be found at https://github.com/bazelbuild/bazel/blob/master/third_party/jarjar/java/com/tonicsystems/jarjar/help.txt.
      exclude_packages: See javadoc_library
      additional_javadoc_dependencies: Additional dependencies to give javadoc
      manifest_lines: lines to put in the output manifest file (manifest
        files in the input jars are ignored)
      create_snapshot_bundle: If true, creates a target <name>-maven-bundle which provides a
        snapshot maven_bundle.zip file.
      pom_template_for_snapshot_bundle: The pom file to use for the bundle.
    """

    if shaded_packages:
        unshaded_jar = name + "-unshaded"
        java_single_jar(
            name = unshaded_jar,
            deps = deps,
            resources = resources,
            root_packages = root_packages + shaded_packages,
            manifest_lines = manifest_lines,
        )
        jar_jar(
            name = name,
            input_jar = unshaded_jar,
            rules = shading_rules,
        )
    else:
        java_single_jar(
            name = name,
            deps = deps,
            resources = resources,
            root_packages = root_packages,
            manifest_lines = manifest_lines,
        )

    source_jar_name = name + "-src"
    java_single_jar(
        name = source_jar_name,
        deps = deps,
        root_packages = root_packages,
        source_jar = True,
    )

    javadoc_name = name + "-javadoc"
    javadoc(
        name = javadoc_name,
        deps = deps + additional_javadoc_dependencies,
    )

    if create_snapshot_bundle:
        if not pom_template_for_snapshot_bundle:
            fail("If create_snapshot_bundle is True, pom_template_for_snapshot_bundle must be specified.")

        bundle_name = name + "-maven-bundle"
        native.genrule(
            name = bundle_name,
            srcs = [
                ":" + name,
                ":" + source_jar_name,
                ":" + javadoc_name,
                pom_template_for_snapshot_bundle,
            ],
            tags = ["manual"],
            outs = [bundle_name + ".zip"],
            cmd = """
                set -e
                ZIP_ROOT=$$(mktemp -d)
                INNER_DIR="$$ZIP_ROOT/com/google/crypto/tink/{name}/{version_for_bundle}"
                mkdir -p "$$INNER_DIR"
                # Copy files and substitute version in POM
                cp "$(location :{name})" "$$INNER_DIR/{name}-{version_for_bundle}.jar"
                cp "$(location :{source_jar_name})" "$$INNER_DIR/{name}-{version_for_bundle}-sources.jar"
                cp "$(location :{javadoc_name})" "$$INNER_DIR/{name}-{version_for_bundle}-javadoc.jar"
                sed "s/VERSION_PLACEHOLDER/{version_for_bundle}/" \
                   "$(location {pom_template_for_snapshot_bundle})" > \
                   "$$INNER_DIR/{name}-{version_for_bundle}.pom"
                # Generate checksums
                for f in "$$INNER_DIR"/*; do
                  md5sum "$$f" > "$$f.md5"
                  sha1sum "$$f" > "$$f.sha1"
                  sha256sum "$$f" > "$$f.sha256"
                  sha512sum "$$f" > "$$f.sha512"
                done
                # Zip the contents and clean up
                cd "$$ZIP_ROOT" && zip -r $$OLDPWD/$(location {bundle_name}.zip) .
            """.format(
                name = name,
                version_for_bundle = "HEAD-SNAPSHOT",
                source_jar_name = source_jar_name,
                javadoc_name = javadoc_name,
                pom_template_for_snapshot_bundle = pom_template_for_snapshot_bundle,
                bundle_name = bundle_name,
            ),
        )
