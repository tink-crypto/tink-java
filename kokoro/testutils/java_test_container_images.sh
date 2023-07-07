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
readonly TINK_JAVA_BASE_IMAGE_HASH="78760bd248a1045096e91cac1841e677dc1ba5b0881090d1fe29df62e4c3f83b"
readonly TINK_JAVA_BASE_IMAGE="$(_image_prefix)/${TINK_JAVA_BASE_IMAGE_NAME}@sha256:${TINK_JAVA_BASE_IMAGE_HASH}"

readonly TINK_JAVA_GCLOUD_IMAGE_NAME="linux-tink-java-gcloud"
readonly TINK_JAVA_GCLOUD_IMAGE_HASH="1905add78813e8321297356204d710fe8337f7a32db2d9681d0192da9dd9bbcc"
readonly TINK_JAVA_GCLOUD_IMAGE="$(_image_prefix)/${TINK_JAVA_GCLOUD_IMAGE_NAME}@sha256:${TINK_JAVA_GCLOUD_IMAGE_HASH}"

unset -f _image_prefix
