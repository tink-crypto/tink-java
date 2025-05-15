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
    "${TINK_BASE_DIR}/tink_java/kokoro/testutils/java_test_container_images.sh"
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

# File that stores environment variables to pass to the container.
readonly ENV_VARIABLES_FILE="/tmp/env_variables.txt"

if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  cat <<EOF > "${ENV_VARIABLES_FILE}"
BAZEL_REMOTE_CACHE_NAME=${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_JAVA_BASE_IMAGE_HASH}
EOF
  RUN_COMMAND_ARGS+=( -e "${ENV_VARIABLES_FILE}" )
fi

cat <<'EOF' > _do_run_test.sh
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

MAVEN_DEPLOY_LIBRARY_OPTS=()
if [[ -n "${BAZEL_REMOTE_CACHE_NAME:-}" ]]; then
  MAVEN_DEPLOY_LIBRARY_OPTS+=( -c "${BAZEL_REMOTE_CACHE_NAME}" )
fi
readonly MAVEN_DEPLOY_LIBRARY_OPTS

# Install the latest snapshot for tink-java and tink-android locally.
./maven/maven_deploy_library.sh "${MAVEN_DEPLOY_LIBRARY_OPTS[@]}" install \
  tink maven/tink-java.pom.xml HEAD
./maven/maven_deploy_library.sh "${MAVEN_DEPLOY_LIBRARY_OPTS[@]}" install \
  tink-android maven/tink-java-android.pom.xml HEAD

# TODO(tholenst): find a good way to test these jar files.
./examples/android/helloworld/gradlew -PmavenLocation=local \
  -p ./examples/android/helloworld build
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh "${ENV_VARIABLES_FILE}"
}

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh

readonly GITHUB_JOB_NAME="tink/github/java/gcp_ubuntu/maven/continuous"

if [[ "${IS_KOKORO}" == "true" \
      && "${KOKORO_JOB_NAME}" == "${GITHUB_JOB_NAME}" ]]; then
  # GITHUB_ACCESS_TOKEN is populated by Kokoro.
  readonly GIT_CREDENTIALS="ise-crypto:${GITHUB_ACCESS_TOKEN}"
  readonly GITHUB_URL="https://${GIT_CREDENTIALS}@github.com/tink-crypto/tink-java.git"

  # Share the required env variables with the container to allow publishing the
  # snapshot on Sonatype.
  cat <<EOF >> "${ENV_VARIABLES_FILE}"
SONATYPE_USERNAME
SONATYPE_PASSWORD
EOF

  MAVEN_DEPLOY_LIBRARY_OPTS=( -u "${GITHUB_URL}" )
  if [[ -n "${BAZEL_REMOTE_CACHE_NAME:-}" ]]; then
    MAVEN_DEPLOY_LIBRARY_OPTS+=( -c "${BAZEL_REMOTE_CACHE_NAME}" )
  fi
  readonly MAVEN_DEPLOY_LIBRARY_OPTS

  ./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh "${MAVEN_DEPLOY_LIBRARY_OPTS[@]}" snapshot \
    tink maven/tink-java.pom.xml HEAD
  ./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
    ./maven/maven_deploy_library.sh "${MAVEN_DEPLOY_LIBRARY_OPTS[@]}" snapshot \
    tink-android maven/tink-java-android.pom.xml HEAD
fi
