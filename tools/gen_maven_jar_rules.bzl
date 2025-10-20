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
        manifest_lines = []):
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

def maven_bundle(
        name,
        lib_name,
        pom_template,
        lib_version,
        maven_jar_rules_target,
        gpg_secret_key_file,
        gpg_pin_file,
        tags = []):
    """Creates a Maven bundle.

    A maven bundle is a zip file containing data ready to upload to maven. For example, for
    Tink 1.19.0, the zip file contains the directory
    com/google/crypto/tink/tink/1.19.0 which in turn contains the files:
        tink-1.19.0-javadoc.jar
        tink-1.19.0-javadoc.jar.{asc,md5,sha1,sha256,sha512}
        tink-1.19.0-sources.jar
        tink-1.19.0-sources.jar.{asc,md5,sha1,sha256,sha512}
        tink-1.19.0.jar
        tink-1.19.0.jar.{asc,md5,sha1,sha256,sha512}
        tink-1.19.0.pom
        tink-1.19.0.pom.{asc,md5,sha1,sha256,sha512}
    The .asc files are GPG signatures.

    To create GPG signatures, a key file and a file containing a pin are needed. To create these
    two files (e.g. for testing):
        openssl rand -hex 20 > gpg_pin.txt
    Then, create a keygen.conf file with the following contents (spaces in the beginning of lines
    are ignored and can hence be kept):
        %echo Generating a basic RSA 2048 key
        Key-Type: RSA
        Key-Length: 2048
        Subkey-Type: RSA
        Subkey-Length: 2048
        Expire-Date: 1y
        Name-Real: Key For Testing
        Name-Email: non_existent_email@tink_google_crypto.com
        Name-Comment: Key for Testing
        %commit
        %echo Done

    Then, run GPG:
        export GNUPGHOME=$(mktemp -d)
        gpg --full-generate-key --batch \
            --passphrase-fd 0 \
            --passphrase-file gpg_pin.txt \
            --pinentry-mode loopback \
            keygen.conf
        gpg --export-secret-keys --batch \
            --passphrase-fd 0 \
            --pinentry-mode loopback \
            --passphrase-file gpg_pin.txt \
            --armor > gpg_key.asc

    Args:
        name: The name of the rule
        lib_name: Use to create the directory in the zip file and the names.
          For example, the main jar file in the bundle will be:
          com/google/crypto/tink/<lib_name>/<lib_version>/<lib_name>-<lib_version>.jar
        pom_template: The pom file, but instead of version it should
          contain the string VERSION_PLACEHOLDER
        lib_version: The version which will be used in the filenames
          and in VERSION_PLACEHOLDER in pom_template
        maven_jar_rules_target: The name of the gen_maven_jar_rules target.
        gpg_secret_key_file: A file containing a gpg secret key. See above
          for how to generate this.
        gpg_pin_file: A file containing a gpg pin. See above for how to
          generate.
        tags: Tags to pass to native.genrule
        """

    jar_target = maven_jar_rules_target
    source_jar_target = maven_jar_rules_target + "-src"
    javadoc_jar_target = maven_jar_rules_target + "-javadoc"
    native.genrule(
        name = name,
        srcs = [
            jar_target,
            source_jar_target,
            javadoc_jar_target,
            pom_template,
            gpg_pin_file,
            gpg_secret_key_file,
        ],
        tags = tags,
        outs = [name + ".zip"],
        cmd = """
            set -e
            export GNUPGHOME=$$(mktemp -d)
            gpg --batch --yes --import {gpg_secret_key_file}
            ZIP_ROOT=$$(mktemp -d)
            INNER_DIR="$$ZIP_ROOT/com/google/crypto/tink/{lib_name}/{lib_version}"
            mkdir -p "$$INNER_DIR"
            # Copy files and substitute version in POM
            cp "$(location {jar_target})" "$$INNER_DIR/{lib_name}-{lib_version}.jar"
            cp "$(location {source_jar_target})" "$$INNER_DIR/{lib_name}-{lib_version}-sources.jar"
            cp "$(location {javadoc_jar_target})" "$$INNER_DIR/{lib_name}-{lib_version}-javadoc.jar"
            sed "s/VERSION_PLACEHOLDER/{lib_version}/" \
                "$(location {pom_template})" > \
                "$$INNER_DIR/{lib_name}-{lib_version}.pom"
            # Generate checksums
            for f in "$$INNER_DIR"/*; do
              md5sum "$$f" | cut -d' ' -f1 > "$$f.md5"
              sha1sum "$$f" | cut -d' ' -f1 > "$$f.sha1"
              sha256sum "$$f" | cut -d' ' -f1 > "$$f.sha256"
              sha512sum "$$f" | cut -d' ' -f1 > "$$f.sha512"
              gpg --pinentry-mode loopback --batch --yes \
                  --passphrase-file {gpg_pin_file} \
                  --output "$$f.asc" --detach-sign "$$f"
            done
            # Zip the contents and clean up
            cd "$$ZIP_ROOT" && zip -r $$OLDPWD/$(location {name}.zip) .
        """.format(
            name = name,
            lib_name = lib_name,
            lib_version = lib_version,
            jar_target = jar_target,
            source_jar_target = source_jar_target,
            javadoc_jar_target = javadoc_jar_target,
            pom_template = pom_template,
            gpg_secret_key_file = gpg_secret_key_file if gpg_secret_key_file else jar_target,
            gpg_pin_file = gpg_pin_file if gpg_pin_file else jar_target,
        ),
    )
