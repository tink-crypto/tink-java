#!/bin/bash
# Copyright 2025 Google LLC
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

#######################################
# Publishes the javadoc which can be found in `javadoc_file` into
# "<git_url>/tree/gh_pages/javadoc/<library_name>/<artifact_version>"
# The git_url typically contains the credentials.
# Example usage:
#   publish_javadoc_to_github_pages \
#     https://ise-crypto:ACCESSTOKEN@github.com/tink-crypto/tink-java \
#     tink \
#     HEAD_SNAPSHOT \
#     path/to/javadoc.jar
#
# The pushed Javadoc can be looked at on the gh_pages branch in the github
# repo (ex: https://github.com/tink-crypto/tink-java/tree/gh-pages) or on
# javadoc.io (ex: https://javadoc.io/doc/com.google.crypto.tink/).
#
# This uses a fixed name and email.
#
# Arguments:
#   git_url: The git URL.
#   library_name: The name of the library
#   artifact_version: The version
#   javadoc_file: JAR file containing the javadoc.
#######################################

readonly GIT_ARGS=(
  -c user.email=noreply@google.com
  -c user.name="Tink Team"
)

main() {
  local -r git_url=$1
  local -r library_name=$2
  local -r artifact_version=$3
  local -r javadoc_file="$(realpath $4)"

  rm -rf gh-pages
  git "${GIT_ARGS[@]}" clone \
    --quiet --branch=gh-pages "${git_url}" gh-pages > /dev/null
  (
    cd gh-pages
    if [ -d "javadoc/${library_name}/${artifact_version}" ]; then
      git "${GIT_ARGS[@]}" rm -rf "javadoc/${library_name}/${artifact_version}"
    fi
    mkdir -p "javadoc/${library_name}/${artifact_version}"
    unzip "${javadoc_file}" \
      -d "javadoc/${library_name}/${artifact_version}"
    rm -rf "javadoc/${library_name}/${artifact_version}/META-INF/"
    git "${GIT_ARGS[@]}" add -f "javadoc/${library_name}/${artifact_version}"
    if [[ "$(git status --porcelain)" ]]; then
      # Changes exist.
      git "${GIT_ARGS[@]}" commit \
        -m "${library_name}-${artifact_version} Javadoc auto-pushed to gh-pages"

      git "${GIT_ARGS[@]}" push -fq origin gh-pages > /dev/null
      echo -e "Published Javadoc to gh-pages.\n"
    else
      # No changes exist.
      echo -e "No changes in ${library_name}-${artifact_version} Javadoc.\n"
    fi
  )
}

main "$@"
