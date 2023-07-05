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
# CONTAINER_IMAGE="gcr.io/tink-test-infrastructure/linux-tink-go-base:latest" \
#  sh ./kokoro/gcp_ubuntu/gomod/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-java. That is:
#   ${TINK_BASE_DIR}/tink_java
set -eEuo pipefail

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  source \
    "${TINK_BASE_DIR}/tink_java/kokoro/testutils/tink_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_JAVA_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi

: "${TINK_BASE_DIR:=$(cd .. && pwd)}"
readonly TINK_BASE_DIR
readonly CONTAINER_IMAGE

# If running from the tink_java folder this has no effect.
cd "${TINK_BASE_DIR}/tink_java"

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

cat <<EOF > _do_run_test.sh
set -euo pipefail

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
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh

readonly GITHUB_JOB_NAME="tink/github/java/gcp_ubuntu/maven/continuous"

if [[ "${IS_KOKORO}" == "true" \
      && "${KOKORO_JOB_NAME}" == "${GITHUB_JOB_NAME}" ]]; then
  # GITHUB_ACCESS_TOKEN is populated by Kokoro.
  readonly GIT_CREDENTIALS="ise-crypto:${GITHUB_ACCESS_TOKEN}"
  readonly GITHUB_URL="https://${GIT_CREDENTIALS}@github.com/tink-crypto/tink-java.git"

  # Share the required env variables with the container to allow publishing the
  # snapshot on Sonatype.
  cat <<EOF > env_variables.txt
SONATYPE_USERNAME
SONATYPE_PASSWORD
EOF
  RUN_COMMAND_ARGS+=( -e env_variables.txt )

  ./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink \
    maven/tink-java.pom.xml HEAD
  ./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh -u "${GITHUB_URL}" snapshot tink-android \
    maven/tink-java-android.pom.xml HEAD
fi
