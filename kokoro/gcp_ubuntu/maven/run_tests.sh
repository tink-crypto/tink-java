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

if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java"
  chmod +x "${KOKORO_GFILE_DIR}/use_bazel.sh"
  "${KOKORO_GFILE_DIR}/use_bazel.sh" "$(cat .bazelversion)"
fi

./kokoro/testutils/update_android_sdk.sh

if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  yes | "${ANDROID_HOME}/tools/bin/sdkmanager" \
    "build-tools;${ANDROID_BUILD_TOOLS_VERSION}"
  yes | "${ANDROID_HOME}/tools/bin/sdkmanager" --licenses
fi

# Install the latest snapshot for tink-java and tink-android locally.
./maven/maven_deploy_library.sh install tink maven/tink-java.pom.xml HEAD
./maven/maven_deploy_library.sh install tink-android \
  maven/tink-java-android.pom.xml HEAD

# Run the Java and Android helloworld examples against the local artifacts.
./kokoro/testutils/test_maven_snapshot.sh -l "examples/helloworld/pom.xml"
./examples/android/helloworld/gradlew -PmavenLocation=local \
  -p ./examples/android/helloworld build
