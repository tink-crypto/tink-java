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

set -eu

# Version of Android build-tools required for gradle.
readonly ANDROID_BUILD_TOOLS_VERSION="28.0.3"

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

BAZEL_CMD="bazel"
# Prefer using Bazelisk if available.
if command -v "bazelisk" &> /dev/null; then
  BAZEL_CMD="bazelisk"
fi
readonly BAZEL_CMD


if [[ "${IS_KOKORO}" == "true" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java"
fi

#######################################
# Checks if the direct dependencies of the //:tink Bazel target are in
# maven/tink-java.pom.xml. In case of discrepancies, it prints the diff on
# standard output and exits with exit code 1.
#
# Globals:
#   None
# Arguments:
#   None
#######################################
function check_maven_deps() {
  local -r maven_direct_deps="$(mktemp)"
  mvn dependency:list -DoutputFile="${maven_direct_deps}" \
    -DexcludeTransitive=true -f maven/tink-java.pom.xml -Dsort=true -q

  # Get the list of deps and get them in the form:
  #    <groupId>:<artifactId>:<version>
  local -r actual_deps="$(cat "${maven_direct_deps}" \
    | grep compile | cut -d: -f1,2,4 | sed -E 's/^\s+//')"

  local -r bazel_direct_deps="$("${BAZEL_CMD}" query --output=build \
    'attr(tags, .*,filter(@maven, deps(//:tink, 2)))' \
      | grep maven_coordinates | cut -d'"' -f2 | cut -d'=' -f2 )"

  # cmp -bl <(echo "${actual_deps}" ) <(echo "${bazel_direct_deps}")
  if ! cmp -s <(echo "${bazel_direct_deps}" ) <(echo "${actual_deps}"); then
    echo "There are the following mismatches between the dependencies in Bazel \
and the POM file:"
    diff <(echo "${bazel_direct_deps}" ) <(echo "${actual_deps}")
    exit 1
  fi
}

check_maven_deps

# Install the latest snapshot for tink-java and tink-android locally.
./maven/maven_deploy_library.sh install tink maven/tink-java.pom.xml HEAD
./maven/maven_deploy_library.sh install tink-android \
  maven/tink-java-android.pom.xml HEAD

# Run the Java and Android helloworld examples against the local artifacts.
./kokoro/testutils/test_maven_snapshot.sh -l "examples/helloworld/pom.xml"
./examples/android/helloworld/gradlew -PmavenLocation=local \
  -p ./examples/android/helloworld build

readonly GITHUB_JOB_NAME="tink/github/java/gcp_ubuntu/maven/continuous"

if [[ "${IS_KOKORO}" == "true" \
      && "${KOKORO_JOB_NAME}" == "${GITHUB_JOB_NAME}" ]]; then
  # GITHUB_ACCESS_TOKEN is populated by Kokoro.
  readonly GIT_CREDENTIALS="ise-crypto:${GITHUB_ACCESS_TOKEN}"
  readonly GITHUB_URL="https://${GIT_CREDENTIALS}@github.com/tink-crypto/tink-java.git"
  ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink \
    maven/tink-java.pom.xml HEAD
fi
