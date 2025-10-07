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

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: 5d260c8726d4a26dad8a (to quickly find the script from logs)"
echo "================================================================================"

set -euo pipefail

if [[ -n "${KOKORO_ROOT:-}" ]] ; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_java"
  export JAVA_HOME=$(/usr/libexec/java_home -v11)
  export XCODE_VERSION="14.1"
  export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
fi

CACHE_FLAGS=()
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  CACHE_FLAGS+=("--remote_cache=https://storage.googleapis.com/${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/java-macos")
  CACHE_FLAGS+=("--google_credentials=$(realpath ./cache_key)")
fi
readonly CACHE_FLAGS

echo "------------- Installing Android SDK"
source ./kokoro/testutils/update_android_sdk.sh
export ANDROID_HOME=/tmp/android-sdk-30

echo "Java home: ${JAVA_HOME}"

## We only test MacOS with bzlmod. We can then update to Java 11 properly.
cat > .bazelmod << EOF
always --noenable_bzlmod
always --enable_workspace
# Minumum C++ version. Override it building this project with
# `bazel build --cxxopt='-std=c++<XY>' --host_cxxopt='c++<XY>' ...`
# (Both -std and --host_cxxopt must be set to force the desired version.)
build --cxxopt='-std=c++17' --host_cxxopt='-std=c++17'
build --java_language_version=11
build --java_runtime_version=remotejdk_11
# Silence all C/C++ warnings in external code.
#
# Note that this will not silence warnings from external headers included
# in project code.
build --per_file_copt=external/.*@-w
build --host_per_file_copt=external/.*@-w
test --test_output=errors
EOF

sed -i.bak "sXandroid-sdk-30Xtmp/android-sdk-30Xg" MODULE.bazel

echo ">>>> .bazelrc"
cat .bazelrc
echo "<<<<"

echo ">>>> MODULE.bazel"
cat MODULE.bazel
echo "<<<<"

echo "---------- BUILDING MAIN (bzlmod)"
time bazelisk build "${CACHE_FLAGS[@]}" -- ...
echo "---------- TESTING MAIN (bzlmod)"
# TODO(b/440525448): Re-enable tests with requires_conscrypt once they are fixed.
time bazelisk test "${CACHE_FLAGS[@]}" --test_tag_filters=-requires_conscrypt -- ...
