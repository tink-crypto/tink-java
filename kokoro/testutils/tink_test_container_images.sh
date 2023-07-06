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

readonly ARTIFACT_REGISTRY_URL="us-docker.pkg.dev"
readonly TEST_PROJECT="tink-test-infrastructure"
readonly ARTIFACT_REGISTRY_REPO="tink-ci-images"

readonly IMAGE_PREFIX="${ARTIFACT_REGISTRY_URL}/${TEST_PROJECT}/${ARTIFACT_REGISTRY_REPO}"

# Linux container images for Tink Java libraries.
readonly TINK_JAVA_BASE_IMAGE_NAME="linux-tink-java-base"
readonly TINK_JAVA_BASE_IMAGE_HASH="78760bd248a1045096e91cac1841e677dc1ba5b0881090d1fe29df62e4c3f83b"
readonly TINK_JAVA_BASE_IMAGE="${IMAGE_PREFIX}/${TINK_JAVA_BASE_IMAGE_NAME}@sha256:${TINK_JAVA_BASE_IMAGE_HASH}"

# Linux container images for Tink Go libraries.
readonly TINK_GO_BASE_IMAGE_NAME="linux-tink-go-base"
readonly TINK_GO_BASE_IMAGE_HASH="2fddb51977a951759ab3b87643b672d590f277fe6ade5787fa8721dd91ea839a"
readonly TINK_GO_BASE_IMAGE="${IMAGE_PREFIX}/${TINK_GO_BASE_IMAGE_NAME}@sha256:${TINK_GO_BASE_IMAGE_HASH}"

# Linux container images for Tink Python libraries.
readonly TINK_PY_BASE_IMAGE_NAME="linux-tink-py-base"
readonly TINK_PY_BASE_IMAGE_HASH="3307f6df04cae8fb97f1b1e6ec06b5e38063055da0b0a8c7b85735d761848486"
readonly TINK_PY_BASE_IMAGE="${IMAGE_PREFIX}/${TINK_PY_BASE_IMAGE_NAME}@sha256:${TINK_PY_BASE_IMAGE_HASH}"
