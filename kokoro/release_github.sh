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

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

# If not defined, default to /tmp.
: "${TMPDIR:="/tmp"}"

#######################################
# Create a GitHub release.
#
# Globals:
#   KOKORO_GIT_COMMIT (optional from Kokoro)
#   GITHUB_ACCESS_TOKEN (optional from Kokoro)
#   TMPDIR
#   IS_KOKORO
#   RELEASE_VERSION
#
#######################################
create_github_release() {
  local -a github_release_opt=()
  if [[ "${IS_KOKORO}" == "true" ]] ; then
    # TODO(b/259058631): Add -r when testing is complete. Without -r the release
    # script will only print the git commands.
    # Note: KOKORO_GIT_COMMIT is populated by Kokoro.
    github_release_opt+=(
      -c "${KOKORO_GIT_COMMIT}"
      -t "${GITHUB_ACCESS_TOKEN}"
    )
  fi
  readonly github_release_opt

  # If running on Kokoro, TMPDIR is populated with the tmp folder.
  local -r tmp_folder="$(mktemp -d "${TMPDIR}/release_XXXXXX")"
  local -r release_script="$(pwd)/kokoro/testutils/create_github_release.sh"
  if [[ ! -f "${release_script}" ]]; then
    echo "${release_script} not found."
    echo "Make sure you run this script from the root of tink-java."
    return 1
  fi

  pushd "${tmp_folder}"
  # Create a GitHub release branch/tag.
  "${release_script}" "${github_release_opt[@]}" "${RELEASE_VERSION}" \
    tink-java
  popd
}

main() {
  if [[ "${IS_KOKORO}" == "true" ]] ; then
    readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
    cd "${TINK_BASE_DIR}/tink_java"
  fi
  create_github_release
}

main "$@"
