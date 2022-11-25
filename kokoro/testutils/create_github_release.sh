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

# This script performs a source release on GitHub for a given repo, that is:
# - Creates a release branch (if it does not yet exist),
# - Creates a release tag.
set -eo pipefail

# Parameters and arguments. These will be populated/modified by args parsing.

# Whether to actually create a release. This is false by default and meant to
# prevent accidental releases.
DO_RELEASE="false"
# This must be of the form `MAJOR.MINOR.PATCH`.
VERSION=
# Repo name after github.com/tink-crypto/, e.g., tink-cc.
REPO_NAME=
# Commit at which to make the release. If unspecified, the release is made from
# HEAD.
COMMIT_HASH=
# Optional personal access token.
ACCESS_TOKEN=

# Derived variables.
GITHUB_REPO_URL=
RELEASE_BRANCH=
TAG=
TARGET_BRANCH_EXISTS="false"

# Constants.
readonly GITHUB_ORG_URL="github.com/tink-crypto"

usage() {
  echo "Usage: $0 [-rh] [-c <commit hash>] [-t <access token>] <version> \\"
  echo "         <repository>"
  echo " <version>: The version identifier in MAJOR.MINOR.PATCH format."
  echo " <repository>: The name of the repository (e.g. \"tink-cc\")."
  echo " -c: Commit hash to use as HEAD of the release branch (optional)."
  echo " -t: Access token. Without this, the default is SSH (optional)."
  echo " -r: Whether to actually create a release; this is false by default."
  echo " -h: Show this help message."
  exit 1
}

process_params() {
  while getopts "rhc:t:" opt; do
    case "${opt}" in
      r) DO_RELEASE="true" ;;
      c) COMMIT_HASH="${OPTARG}" ;;
      t) ACCESS_TOKEN="${OPTARG}" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly DO_RELEASE
  readonly COMMIT_HASH
  readonly ACCESS_TOKEN

  VERSION="$1"
  if [[ ! "${VERSION}" =~ ^[0-9]+.[0-9]+.[0-9]+$ ]]; then
    echo "Invalid version format: expected MAJOR.MINOR.PATCH, got ${VERSION}"
    usage
  fi
  readonly VERSION

  REPO_NAME="$2"
  if [[ -z "${REPO_NAME}" ]]; then
    echo "Repo name must be specified."
    usage
  fi
  readonly REPO_NAME

  # Use SSH by default.
  local protocol_and_credentials="ssh://git"
  if [[ -n "${ACCESS_TOKEN}" ]]; then
    protocol_and_credentials="https://ise-crypto:${ACCESS_TOKEN}"
  fi
  readonly protocol_and_credentials
  GITHUB_REPO_URL="${protocol_and_credentials}@${GITHUB_ORG_URL}/${REPO_NAME}"
  readonly GITHUB_REPO_URL

  # Release branch is only MAJOR.MINOR.
  readonly RELEASE_BRANCH="$(echo "${VERSION}" | cut -d'.' -f1,2)"
  readonly TAG="v${VERSION}"

  # Splitting declaration and assignment guarantees correct propagation of the
  # exit code of the subshell.
  local github_refs
  github_refs="$(git ls-remote "${GITHUB_REPO_URL}")"
  readonly github_refs
  local -r expected_release_branch="refs/heads/${RELEASE_BRANCH}"
  local -r expected_release_tag="refs/tags/${TAG}"
  if echo "${github_refs}" | grep "${expected_release_branch}" > /dev/null; then
    TARGET_BRANCH_EXISTS="true"
    echo "WARNING: The release branch already exists."
    echo "The commit hash ${COMMIT_HASH} will be ignored"
  fi
  readonly TARGET_BRANCH_EXISTS

  # Verify that release tag does not exist.
  if echo "${github_refs}" | grep "${expected_release_tag}" > /dev/null; then
    echo "The tag \"${TAG}\" already exists in the GitHub repository." >&2
    exit 1
  fi
}

#######################################
# Prints a command
#
# Args:
#   Command to execute.
#
#######################################
print_command() {
  printf '%q ' '+' "$@"
  echo
}

#######################################
# Runs a command if DO_RELEASE is true.
#
# Args:
#   Command to execute.
# Globals:
#   DO_RELEASE
#
#######################################
run_command() {
  if [[ "${DO_RELEASE}" == "false" ]]; then
    echo "  *** Dry run, command not executed. ***"
    return 0
  fi
  # Actually run the command.
  "$@"
  return $?
}

#######################################
# Prints and runs a command.
#
# Args:
#   Command to execute.
#
#######################################
print_and_run_command() {
  print_command "$@"
  run_command "$@"
}

#######################################
# Creates and checks out to the release branch.
#
# The release branch is created if TARGET_BRANCH_EXISTS is false. If COMMIT_HASH
# is specified, use COMMIT_HASH as HEAD for the branch.
#
# Globals:
#   TARGET_BRANCH_EXISTS
#   RELEASE_BRANCH
#   COMMIT_HASH
#
#######################################
git_checkout_release_branch() {
  if [[ "${TARGET_BRANCH_EXISTS}" == "false" ]]; then
    # Target branch does not exist so we create the release branch.
    if [[ -n "${COMMIT_HASH:-}" ]]; then
      # Use COMMIT_HASH as HEAD for this branch.
      print_and_run_command git branch "${RELEASE_BRANCH}" "${COMMIT_HASH}"
    else
      print_and_run_command git branch "${RELEASE_BRANCH}"
    fi
    print_and_run_command git push origin "${RELEASE_BRANCH}"
  fi
  print_and_run_command git checkout "${RELEASE_BRANCH}"
}

#######################################
# Creates a release tag
#
# Globals:
#   TAG
#   REPO_NAME
#   VERSION
#
#######################################
git_create_release_tag() {
  print_and_run_command git tag -a "${TAG}" -m "${REPO_NAME} version ${VERSION}"
  print_and_run_command git push origin "${TAG}"
}

main() {
  process_params "$@"
  # Avoid logging the full URL; replace GIT_URL with a version that omits user
  # and access token.
  local -r protocol="$(echo "${GITHUB_REPO_URL}" | cut -d':' -f1)"
  local -r github_repo="$(echo "${GITHUB_REPO_URL}" | cut -d'@' -f2)"
  print_command git clone "${protocol}://...@${github_repo}"
  run_command git clone "${GITHUB_REPO_URL}"
  print_and_run_command cd "${REPO_NAME}"
  git_checkout_release_branch
  git_create_release_tag
}

main "$@"
