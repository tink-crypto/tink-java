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

set -euo pipefail

#######################################
# Prints and error message with the missing deps for the given target diff-ing
# the expected and actual list of targets.
#
# Globals:
#   None
# Arguments:
#   target: Bazel target.
#   expected_deps: Expected list of dependencies.
#   actual_deps: Actual list of dependencies.
# Outputs:
#   Writes to stdout
#######################################
print_missing_deps() {
  local -r target="$1"
  local -r expected_deps="$2"
  local -r actual_deps="$3"

  echo "#========= ERROR ${target} target:"
  local -r deps_to_add="$(diff --changed-group-format='%>' \
    --unchanged-group-format='' "${actual_deps}" "${expected_deps}")"
  echo "The following dependencies are missing from the ${target} target:"
  echo "${deps_to_add}"
  echo "#==============================="
}

#######################################
# Checks if the //:tink and //:tink-android Maven targets in BUILD.bazel have
# all the required dependencies.
#
#  * ":tink" should have all java_libraries except integration as dependencies.
#  * ":tink-android" should have all android_libraries except integration as
#    dependencies.
#
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes to stdout
#######################################
test_build_bazel_file() {
  local -r tink_java_prefix="//src/main/java/com/google/crypto/tink"
  # src_android contains android_library targets where the source file differes
  # for java and android.
  local -r tink_java_android_prefix="//src_android/main/java/com/google/crypto/tink"
  local -r tink_java_integration_prefix="${tink_java_prefix}/integration"

  # Targets in tink_java_prefix of type java_library, excluding:
  #  * testonly targets,
  #  * targets in tink_java_integration_prefix.
  local -r expected_tink_deps="$(mktemp)"
  bazel query "kind(java_library,${tink_java_prefix}/...) \
except attr(testonly,1,${tink_java_prefix}/...) \
except kind(java_library,${tink_java_integration_prefix}/...)" \
    > "${expected_tink_deps}"

  # Targets in tink_java_prefix and tink_java_android_prefix of type
  # android_library, excluding testonly targets.
  local -r expected_android_deps="$(mktemp)"
  bazel query "kind(android_library,${tink_java_prefix}/...) \
except attr(testonly,1,${tink_java_prefix}/...)" \
    > "${expected_android_deps}"
  bazel query "kind(android_library,${tink_java_android_prefix}/...) \
except attr(testonly,1,${tink_java_prefix}/...)" \
    >> "${expected_android_deps}"

  # Dependencies of //:tink of type java_library that are in tink_java_prefix.
  # Note: Considering only direct dependencies of the target.
  local -r actual_java_targets="$(mktemp)"
  bazel query "filter(${tink_java_prefix},kind(java_library,deps(//:tink,1)))" \
    > "${actual_java_targets}"

  local error_in_tink="false"
  if ! cmp -s "${actual_java_targets}" "${expected_tink_deps}"; then
    error_in_tink="true"
    print_missing_deps "//:tink" "${expected_tink_deps}" \
      "${actual_java_targets}"
  fi
  readonly error_in_tink

  # Dependencies of //:tink-android of type android_library that are in
  # tink_java_prefix and tink_java_android_prefix.
  # Note: Considering only direct dependencies of the target.
  local -r actual_android_targets="$(mktemp)"
  bazel query "filter(${tink_java_prefix}, \
kind(android_library,deps(//:tink-android,2)))" > "${actual_android_targets}"
  bazel query "filter(${tink_java_android_prefix}, \
kind(android_library,deps(//:tink-android,2)))" >> "${actual_android_targets}"

  local error_in_tink_android="false"
  if ! cmp -s "${actual_java_targets}" "${expected_tink_deps}"; then
    error_in_tink_android="true"
    print_missing_deps "//:tink-android" "${expected_android_deps}" \
      "${actual_android_targets}"
  fi
  readonly error_in_tink_android

  if [[ "${error_in_tink}" == "true" \
        || "${error_in_tink_android}" == "true" ]]; then
    exit 1
  fi
}

main() {
  if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
    TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
    cd "${TINK_BASE_DIR}/tink_java"
    chmod +x "${KOKORO_GFILE_DIR}/use_bazel.sh"
    "${KOKORO_GFILE_DIR}/use_bazel.sh" "$(cat .bazelversion)"
  fi

  test_build_bazel_file

  ./kokoro/testutils/run_bazel_tests.sh .
}

main "$@"
