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

if [[ "${IS_KOKORO}" == "true" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java"
fi

# Compare the dependencies of the ":tink" target with the declared dependencies.
# These should match the dependencies declared in tink-java.pom.xml, since
# since these are the dependencies which are declared on maven.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh "//:tink" \
  "maven/tink-java.pom.xml"

# For Android, we compare the unshaded version -- trial and error revealed that
# this is the target that has the correct dependencies.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh \
  -e com.google.protobuf:protobuf-javalite \
  "//:tink-android-unshaded" "maven/tink-java-android.pom.xml"

# Install the latest snapshot for tink-java and tink-android locally.
./maven/maven_deploy_library.sh install tink maven/tink-java.pom.xml HEAD
./maven/maven_deploy_library.sh install tink-android \
  maven/tink-java-android.pom.xml HEAD

# TODO(tholenst): find a good way to test these jar files.
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
  ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink-android \
    maven/tink-java-android.pom.xml HEAD
fi
