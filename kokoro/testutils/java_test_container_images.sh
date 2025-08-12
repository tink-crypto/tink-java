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
readonly TINK_JAVA_BASE_IMAGE_HASH="7ffd76af78df335a5952e0ffa47b62313da11017b42ec0c6f91e11afadbf4c4f"
readonly TINK_JAVA_BASE_IMAGE="$(_image_prefix)/${TINK_JAVA_BASE_IMAGE_NAME}@sha256:${TINK_JAVA_BASE_IMAGE_HASH}"

readonly TINK_JAVA_GCLOUD_IMAGE_NAME="linux-tink-java-gcloud"
readonly TINK_JAVA_GCLOUD_IMAGE_HASH="c8d60059837693aa17e8cada4fea00da69563a1006375c42a7d0e0511fb1fd82"
readonly TINK_JAVA_GCLOUD_IMAGE="$(_image_prefix)/${TINK_JAVA_GCLOUD_IMAGE_NAME}@sha256:${TINK_JAVA_GCLOUD_IMAGE_HASH}"

unset -f _image_prefix
