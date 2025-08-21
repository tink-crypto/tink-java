#!/bin/bash

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# NOTE:
#   - This must be run from the root of the library workspace.

usage() {
  cat <<EOF
Usage: $0 [-dh] [-n jars_name_prefix] [-u github_url] [-c bazel_cache_name]
          <action (install|snapshot|release)> <library name>
          <pom template> <version>"
  -d: Dry run. Only execute idempotent commands (default: false).
  -n: gen_maven_jar_rules target name (with slash). The Bazel target name with
      which the gen_maven_jar_rules was declared (e.g. paymentmethodtoken/maven)
      for the target "//paymentmethodtoken:maven" (default: <library name>).
  -u: GitHub URL. GitHub URL for Javadoc publishing; it is mandatory when
      <action> is "snaphot" or "release".
  -c: Bazel cache to use; credentials are expected to be in the file
      ./cache_key.
  -h: Help. Print this usage information.

Builds an Apache Maven archive using Bazel and performs an action on them.
  * snapshot: Builds the artifact, uploads it to the snapshot server. Also
              uploads javadoc to the given GitHub URL (branch gh-pages).
  * release:  Builds the artifact, then uploads it to the actual release server.
              Also uploads javadoc to the given GitHub URL (branch gh-pages).
  * install:  Creates the artifact with Bazel, then installs the result locally.
              This emulates the effect of the user later installing the uploaded
              artefact.

The POM template must be a normal POM file, but with VERSION_PLACEHOLDER instead
of the actual version. The version must be of the form xx.xx.xx (e.g., 1.18.0).
EOF
  exit 1
}

# Arguments to use for all git invocations.
readonly GIT_ARGS=(
  -c user.email=noreply@google.com
  -c user.name="Tink Team"
)

to_absolute_path() {
  local -r path="$1"
  echo "$(cd "$(dirname "${path}")" && pwd)/$(basename "${path}")"
}

set -eox

# Options.
DRY_RUN="false"
GIT_URL=

# Positional arguments.
LIBRARY_NAME=
POM_FILE=
ARTIFACT_VERSION=

# Other.
MAVEN_ARGS=()
CACHE_FLAGS=()

parse_args() {
  # Parse options.
  while getopts "dhn::u::c:" opt; do
    case "${opt}" in
      d) DRY_RUN="true" ;;
      n) BAZEL_TARGET="${OPTARG}" ;;
      u) GIT_URL="${OPTARG}" ;;
      c) CACHE_FLAGS=(
           "--remote_cache=https://storage.googleapis.com/${OPTARG}"
           "--google_credentials=$(to_absolute_path ./cache_key)"
         ) ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))

  readonly DRY_RUN
  readonly BAZEL_TARGET
  readonly GIT_URL
  readonly CACHE_FLAGS

  # Parse args.
  if (( $# < 4 )); then
    usage
  fi
  ACTION="$1"
  LIBRARY_NAME="$2"
  POM_FILE="$3"
  ARTIFACT_VERSION="$4"

  BAZEL_BIN_JAR="${BAZEL_TARGET:-${LIBRARY_NAME}}.jar"
  BAZEL_SRC_JAR="${BAZEL_TARGET:-${LIBRARY_NAME}}-src.jar"
  BAZEL_DOC_JAR="${BAZEL_TARGET:-${LIBRARY_NAME}}-javadoc.jar"
  readonly BAZEL_BIN_JAR
  readonly BAZEL_SRC_JAR
  readonly BAZEL_DOC_JAR

  # Make sure the version has the correct format.
  if [[ ! "${ARTIFACT_VERSION}" =~ (^HEAD$|^[0-9]+\.[0-9]+\.[0-9]$) ]]; then
    usage
  fi

  if [[ ! -f "${POM_FILE}" ]]; then
    echo "ERROR: The POM file doesn't exist: ${POM_FILE}" >&2
    usage
  fi

  local -r maven_scripts_dir="$(cd "$(dirname "${POM_FILE}")" && pwd)"

  readonly ACTION
  readonly LIBRARY_NAME
  readonly POM_FILE
  readonly ARTIFACT_VERSION
  readonly MAVEN_ARGS
}

#######################################
# Runs a given command if DRY_RUN isn't true.
# Globals:
#   DRY_RUN
# Arguments:
#   The command to run and its arguments.
#######################################
do_run_if_not_dry_run() {
  print_command "$@"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "  *** Dry run, command not executed. ***"
    return 0
  fi
  do_run_command "$@"
  return $?
}

echo_output_file() {
  local workspace_dir="$1"
  local library="$2"

  (
    cd "${workspace_dir}"
    local file="bazel-bin/${library}"
    if [[ ! -e "${file}" ]]; then
       file="bazel-genfiles/${library}"
    fi
    if [[ ! -e "${file}" ]]; then
      echo "Could not find Bazel output file for ${library}"
      exit 1
    fi
    echo -n "${workspace_dir}/${file}"
  )
}

#######################################
# Pusblishes Javadoc to GitHub pages.
#
# Globals:
#   ACTION
#   GIT_ARGS
#   GIT_URL
#   LIBRARY_NAME
#   ARTIFACT_VERSION
# Arguments:
#   workspace_dir: Workspace directory for the library.
#   javadoc: Javadoc library name.
#######################################
publish_javadoc_to_github_pages() {
  local workspace_dir="$1"
  local javadoc="$2"

  local -r javadoc_file="$(echo_output_file "${workspace_dir}" "${javadoc}")"

  rm -rf gh-pages
  git "${GIT_ARGS[@]}" clone \
    --quiet --branch=gh-pages "${GIT_URL}" gh-pages > /dev/null
  (
    cd gh-pages
    if [ -d "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}" ]; then
      git "${GIT_ARGS[@]}" rm -rf \
          "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    fi
    mkdir -p "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    unzip "${javadoc_file}" \
      -d "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    rm -rf "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}/META-INF/"
    git "${GIT_ARGS[@]}" add \
      -f "javadoc/${LIBRARY_NAME}/${ARTIFACT_VERSION}"
    if [[ "$(git "${GIT_ARGS[@]}" status --porcelain)" ]]; then
      # Changes exist.
      do_run_if_not_dry_run \
        git "${GIT_ARGS[@]}" commit \
        -m "${LIBRARY_NAME}-${ARTIFACT_VERSION} Javadoc auto-pushed to gh-pages"

      do_run_if_not_dry_run \
        git "${GIT_ARGS[@]}" push -fq origin gh-pages > /dev/null
      echo -e "Published Javadoc to gh-pages.\n"
    else
      # No changes exist.
      echo -e "No changes in ${LIBRARY_NAME}-${ARTIFACT_VERSION} Javadoc.\n"
    fi
  )
}

###################################
# Adds signatures and hashes for all files in a directory.
#
# "add_signatures_and_hashes /some/directory/some_file" adds
# /some/directory/some_file.md5, sha1, and so on, as required by Maven.
# In case $ACTION == "release", also uses gpg to create the signature.
###################################
add_signatures_and_hashes() {
  local filename="$1"

  md5sum "${filename}" > "${filename}.md5"
  sha1sum "${filename}" > "${filename}.sha1"
  sha256sum "${filename}" > "${filename}.sha256"
  sha512sum "${filename}" > "${filename}.sha512"

  if [[ "${ACTION}" == "release" ]]; then
    gpg -ab "${filename}" > "${filename}.asc"
  fi
}

###################################
# Renames files in a directory and adds files with hashes.
#
# "package_maven_bundle /tmp/directory 1.2.3" renames all files in /tmp/dir from
# 'filename.ext' to 'filename-1.2.3.ext'
# Then, it adds files
#   'filename-1.2.3.ext.md5'
#   'filename-1.2.3.ext.sha1'
#   'filename-1.2.3.ext.sha256'
#   'filename-1.2.3.ext.sha512'
#   'filename-1.2.3.ext.asc' (in case $ACTION == "release")
# Globals:
#   $ACTION
###################################
rename_and_add_hashes() {
  local directory="$1"
  local version="$2"
  for filename in "${directory}/"*; do
    filename_no_dir=$(basename -- "${filename}")
    # https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
    base="${filename_no_dir%.*}"
    ext="${filename_no_dir##*.}"
    mv "${directory}/${base}.${ext}" "${directory}/${base}-${version}.${ext}"
    add_signatures_and_hashes "${directory}/${base}-${version}.${ext}"
  done
}


##############
# Creates a file "maven_bundle.zip" in the current directory.
##############
build_maven_bundle() {
  local -r build_dir=$(mktemp -d)
  local -r version="${ARTIFACT_VERSION}"

  local -r jars_name_prefix="tink"
  # The zip file we create will contain files in this directory.
  local -r inner_zip_dir="com/google/crypto/tink/${LIBRARY_NAME}/${version}"
  mkdir -p "${build_dir}/${inner_zip_dir}"

  local -r lib_jar="${build_dir}/${inner_zip_dir}/${LIBRARY_NAME}.jar"
  local -r src_jar="${build_dir}/${inner_zip_dir}/${LIBRARY_NAME}-sources.jar"
  local -r doc_jar="${build_dir}/${inner_zip_dir}/${LIBRARY_NAME}-javadoc.jar"
  local -r pomfile="${build_dir}/${inner_zip_dir}/${LIBRARY_NAME}.pom"

  sed "s/VERSION_PLACEHOLDER/${version}/" "${POM_FILE}" > "${pomfile}"

  cp "bazel-bin/${BAZEL_BIN_JAR}" "${lib_jar}"
  cp "bazel-bin/${BAZEL_SRC_JAR}" "${src_jar}"
  cp "bazel-bin/${BAZEL_DOC_JAR}" "${doc_jar}"

  rename_and_add_hashes "${build_dir}/${inner_zip_dir}" ${version}
  (
    cd "${build_dir}"
    zip -r maven_bundle.zip "${inner_zip_dir}"
  )
  mv "${build_dir}/maven_bundle.zip" .
  rm -rf "${build_dir}"
}

main() {
  parse_args "$@"

  # Creates the JAR files which we expect in the following.
  bazelisk build "${CACHE_FLAGS[@]}" "${BAZEL_BIN_JAR}" "${BAZEL_SRC_JAR}" "${BAZEL_DOC_JAR}"
  if [[ "${ACTION}" == "install" ]]; then
    sed "s/VERSION_PLACEHOLDER/${ARTIFACT_VERSION}/" "${POM_FILE}" > pom_for_install.xml
    cat pom_for_install.xml
    mvn install:install-file \
      "-Dfile=bazel-bin/${BAZEL_BIN_JAR}" \
      "-Dsources=bazel-bin/${BAZEL_SRC_JAR}" \
      "-Djavadoc=bazel-bin/${BAZEL_DOC_JAR}" \
      -DpomFile=pom_for_install.xml
    exit
  fi;

  build_maven_bundle
  zipinfo maven_bundle.zip

  if [[ "${ACTION}" == "release" ]]; then
    echo "release not yet implemented"
  fi

  if [[ "${ACTION}" == "snapshot" ]]; then
    echo "snapshot not yet implemented"
  fi
  # TODO - b/433476142: Redo this.
  # publish_javadoc_to_github_pages "${workspace_dir}" "${javadoc}"
}

main "$@"
