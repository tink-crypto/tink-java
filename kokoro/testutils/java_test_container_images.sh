#!/bin/bash
# Copyright 2023 Google LLC
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

_image_prefix() {
  local -r artifact_registry_url="us-docker.pkg.dev"
  local -r test_project="tink-test-infrastructure"
  local -r artifact_registry_repo="tink-ci-images"
  echo "${artifact_registry_url}/${test_project}/${artifact_registry_repo}"
}

# Linux container images for Tink Java libraries.
readonly TINK_JAVA_BASE_IMAGE_NAME="linux-tink-java-base"
readonly TINK_JAVA_BASE_IMAGE_HASH="8c7e62f2244930bc2c22a5a20d6d8c4df39abff94af06142cce8137d173fc744"
readonly TINK_JAVA_BASE_IMAGE="$(_image_prefix)/${TINK_JAVA_BASE_IMAGE_NAME}@sha256:${TINK_JAVA_BASE_IMAGE_HASH}"

readonly TINK_JAVA_GCLOUD_IMAGE_NAME="linux-tink-java-gcloud"
readonly TINK_JAVA_GCLOUD_IMAGE_HASH="cbad1e8f7fa2204897cfcd467b13075c72d4e1ae0f3990692ddda10125e2a287"
readonly TINK_JAVA_GCLOUD_IMAGE="$(_image_prefix)/${TINK_JAVA_GCLOUD_IMAGE_NAME}@sha256:${TINK_JAVA_GCLOUD_IMAGE_HASH}"

unset -f _image_prefix
