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

set -euo pipefail

# Fail if RELEASE_VERSION is not set.
if [[ -z "${RELEASE_VERSION:-}" ]]; then
  echo "RELEASE_VERSION must be set" >2&
  exit 1
fi

readonly TINK_JAVA_GITHUB_URL="github.com/tink-crypto/tink-java"
IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

# WARNING: Setting this environment varialble to "true" will cause this script
# to actually perform a release.
: "${DO_MAKE_RELEASE:="false"}"

if [[ ! "${DO_MAKE_RELEASE}" =~ ^(false|true)$ ]]; then
  echo "DO_MAKE_RELEASE must be either \"true\" or \"false\"" >2&
  exit 1
fi

#######################################
# Create a Maven release on Sonatype.
#
# Globals:
#   GITHUB_ACCESS_TOKEN (optional from Kokoro)
#   IS_KOKORO
#   RELEASE_VERSION
#   TINK_JAVA_GITHUB_URL
#
#######################################
create_maven_release() {
  local gitub_protocol_and_auth="ssh://git"
  if [[ "${IS_KOKORO}" == "true" ]] ; then
    gitub_protocol_and_auth="https://ise-crypto:${GITHUB_ACCESS_TOKEN}"
  fi
  readonly gitub_protocol_and_auth
  local -r github_url="${gitub_protocol_and_auth}@${TINK_JAVA_GITHUB_URL}"

  local maven_deploy_library_options=( -u "${github_url}" )
  if [[ "${DO_MAKE_RELEASE}" == "false" ]]; then
    maven_deploy_library_options+=( -d )
  fi
  readonly maven_deploy_library_options

  if [[ "${IS_KOKORO}" == "true" ]]; then
    # Import the PGP signing key and make the passphrase available as an env
    # variable.
    gpg --import --pinentry-mode loopback \
      --passphrase-file \
      "${KOKORO_KEYSTORE_DIR}/70968_tink_dev_maven_pgp_passphrase" \
      --batch "${KOKORO_KEYSTORE_DIR}/70968_tink_dev_maven_pgp_secret_key"
    export TINK_DEV_MAVEN_PGP_PASSPHRASE="$(cat \
      "${KOKORO_KEYSTORE_DIR}/70968_tink_dev_maven_pgp_passphrase")"
  fi

  ./maven/maven_deploy_library.sh "${maven_deploy_library_options[@]}" release \
    tink maven/tink-java.pom.xml "${RELEASE_VERSION}"
  ./maven/maven_deploy_library.sh "${maven_deploy_library_options[@]}" release \
    tink-android maven/tink-java-android.pom.xml "${RELEASE_VERSION}"
}

main() {
  if [[ "${IS_KOKORO}" == "true" ]] ; then
    readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
    cd "${TINK_BASE_DIR}/tink_java"
  fi
  create_maven_release
}

main "$@"
