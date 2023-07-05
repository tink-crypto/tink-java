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

# Linux container images for Tink C++ libraries.
readonly TINK_CC_BASE_IMAGE_NAME="linux-tink-cc-base"
readonly TINK_CC_BASE_IMAGE_HASH="56b511c2d0d4c38c8f98f520edce0d37769a01ede1527a34a5afdc0aa3529405"
readonly TINK_CC_BASE_IMAGE="${IMAGE_PREFIX}/${TINK_CC_BASE_IMAGE_NAME}@sha256:${TINK_CC_BASE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_IMAGE_NAME="linux-tink-cc-cmake"
readonly TINK_CC_CMAKE_IMAGE_HASH="379a51d8aa072d27317a8fb8bdf84e2675f0c5c2a2ead5ae2ea0e514c9c4ea6f"
readonly TINK_CC_CMAKE_IMAGE="${IMAGE_PREFIX}/${TINK_CC_CMAKE_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-1_1_1"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH="9fd2a1deff3b1c0168ae09cb5403fd3ad64b55735bbff89f0ec6b2a3707fabbf"
readonly TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE="${IMAGE_PREFIX}/${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_1_1_1_IMAGE_HASH}"

readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME="linux-tink-cc-cmake-and-openssl-3"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH="8e890867759c120d91b4e5726a38e644acfc365a172bbedb1f72bb03e4befaaf"
readonly TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE="${IMAGE_PREFIX}/${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_NAME}@sha256:${TINK_CC_CMAKE_AND_OPENSSL_3_IMAGE_HASH}"

# Linux container images for Tink Java libraries.
readonly TINK_JAVA_BASE_IMAGE_NAME="linux-tink-java-base"
readonly TINK_JAVA_BASE_IMAGE_HASH="78760bd248a1045096e91cac1841e677dc1ba5b0881090d1fe29df62e4c3f83b"
readonly TINK_JAVA_BASE_IMAGE="${IMAGE_PREFIX}/${TINK_JAVA_BASE_IMAGE_NAME}@sha256:${TINK_JAVA_BASE_IMAGE_HASH}"
