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
  export JAVA_HOME=$(/usr/libexec/java_home -v1.8)
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

echo "---------- BUILDING MAIN"
time bazelisk build "${CACHE_FLAGS[@]}" -- ...
echo "---------- TESTING MAIN"
time bazelisk test "${CACHE_FLAGS[@]}" -- ...

cd examples

echo "---------- BUILDING EXAMPLES"
time bazelisk build "${CACHE_FLAGS[@]}" -- ...
echo "---------- TESTING EXAMPLES"
time bazelisk test "${CACHE_FLAGS[@]}" -- ...

# TODO: b/428261485 -- enable this.
# echo "---------- TURNING ON BAZELMOD"
# cd ..
# sed -i.bak "s/always --noenable_bzlmod//g" .bazelrc
#
# echo "---------- BUILDING MAIN (bzlmod)"
# time bazelisk build "${CACHE_FLAGS[@]}" -- ...
# echo "---------- TESTING MAIN (bzlmod)"
# time bazelisk test "${CACHE_FLAGS[@]}" -- ...
