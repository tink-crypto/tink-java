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
# The remote cache key is staged in a private temporary directory instead of
# the checkout. This job runs repository code as the same user, so this only
# keeps the key out of the workspace tree and shortens its lifetime.
CACHE_CREDS_DIR=""
cleanup_cache_creds() {
  if [[ -n "${CACHE_CREDS_DIR}" ]]; then
    rm -rf "${CACHE_CREDS_DIR}"
  fi
}
trap cleanup_cache_creds EXIT

if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  CACHE_CREDS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tink_cache_creds.XXXXXXXX")"
  chmod 700 "${CACHE_CREDS_DIR}"
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" "${CACHE_CREDS_DIR}/cache_key"
  chmod 600 "${CACHE_CREDS_DIR}/cache_key"
  CACHE_FLAGS+=("--remote_cache=https://storage.googleapis.com/${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/java-macos")
  CACHE_FLAGS+=("--google_credentials=${CACHE_CREDS_DIR}/cache_key")
  # Avoid downloading cached intermediate/top-level build outputs unless needed
  # by a local action.
  CACHE_FLAGS+=("--remote_download_minimal")
fi
readonly CACHE_FLAGS

echo "------------- Installing Android SDK"
source ./kokoro/testutils/update_android_sdk.sh
export ANDROID_HOME=/tmp/android-sdk-37

echo "Java home: ${JAVA_HOME}"

# --nobuild_tests_only ensures all non-test targets in '...' are built too.
echo "---------- BUILDING AND TESTING MAIN (bzlmod)"
time bazelisk test --nobuild_tests_only --test_output=errors \
  ${CACHE_FLAGS[@]:+"${CACHE_FLAGS[@]}"} -- ...
