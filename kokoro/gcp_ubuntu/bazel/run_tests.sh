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

# By default when run locally this script runs the command below directly on the
# host. The CONTAINER_IMAGE variable can be set to run on a custom container
# image for local testing. E.g.:
#
# CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-cmake:latest" \
#  sh ./kokoro/gcp_ubuntu/bazel_fips/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-java. That is:
#   ${TINK_BASE_DIR}/tink_java
set -eEuo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  readonly C_PREFIX="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images"
  readonly C_NAME="linux-tink-java-base"
  readonly C_HASH="f9c43b8158b304fb38f5ee0ef49151d10f641ec95ec72ee7ca5243f2d4b14de6"
  CONTAINER_IMAGE="${C_PREFIX}/${C_NAME}@sha256:${C_HASH}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
: "${TINK_BASE_DIR:=$(cd .. && pwd)}"
readonly TINK_BASE_DIR
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi
readonly RUN_COMMAND_ARGS

cd "${TINK_BASE_DIR}/tink_java"

cat <<'EOF' > _do_run_test.sh
set -euo pipefail

./tools/create_maven_build_file.sh -o BUILD.bazel.temp
if ! cmp -s BUILD.bazel BUILD.bazel.temp; then
  echo "ERROR: Update your BUILD.bazel file using ./tools/create_maven_build_file.sh" >&2
  diff -u BUILD.bazel BUILD.bazel.temp
  exit 1
fi
./kokoro/testutils/run_bazel_tests.sh .
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
  rm -rf BUILD.bazel.temp
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
