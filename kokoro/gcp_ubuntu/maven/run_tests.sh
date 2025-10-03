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

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: c1c976bfe50c1d810225 (to quickly find the script from logs)"
echo "================================================================================"

set -eEuox pipefail

if [[ ! -v TINK_BASE_DIR ]] ; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
fi
readonly TINK_BASE_DIR
echo "TINK_BASE_DIR is ${TINK_BASE_DIR}"
if [[ ! -v CONTAINER_IMAGE ]] ; then
  source \
    "${TINK_BASE_DIR}/tink_java/kokoro/testutils/java_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_JAVA_BASE_IMAGE}"
fi
readonly CONTAINER_IMAGE
echo "CONTAINER_IMAGE is ${CONTAINER_IMAGE}"

cd "${TINK_BASE_DIR}/tink_java"

if [[ -v TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  cat <<EOF > /tmp/env_variables.txt
BAZEL_REMOTE_CACHE_NAME=${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_JAVA_BASE_IMAGE_HASH}
EOF
else
  touch /tmp/env_variables.txt
fi

if [[ ! -z "${TINK_GCR_SERVICE_KEY:-}" ]]; then
  gcloud auth activate-service-account --key-file="${TINK_GCR_SERVICE_KEY}"
  gcloud config set project tink-test-infrastructure
  gcloud auth configure-docker us-docker.pkg.dev --quiet
fi

echo "-- PULLING DOCKER IMAGE"
time docker pull "${CONTAINER_IMAGE}"

echo "-- RUNNING DOCKER"
docker run \
  --network="host" \
  --mount type=bind,src="${TINK_BASE_DIR}",dst=/tink_orig_dir \
  --env-file /tmp/env_variables.txt \
  --rm \
  "${CONTAINER_IMAGE}" \
  bash -c "/tink_orig_dir/tink_java/kokoro/testutils/build_maven_bundle.sh"

cd "${KOKORO_ARTIFACTS_DIR}"
mkdir -p kokoro_upload_dir/release
cp "${TINK_BASE_DIR}"/kokoro_upload_dir/* kokoro_upload_dir/release
