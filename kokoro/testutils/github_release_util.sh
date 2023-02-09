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

# Options.
# Whether to actually create a release. This is false by default and meant to
# prevent accidental releases.
DO_RUN_ACTION="false"
# Commit at which to make the release. If unspecified, the release is made from
# HEAD.
COMMIT_HASH=
# Optional personal access token.
ACCESS_TOKEN=

# Arguments.
# Action to be performed.
ACTION=
# This must be of the form `MAJOR.MINOR.PATCH`.
VERSION=
# Repo name after github.com/tink-crypto/, e.g., tink-cc.
REPO_NAME=

# Derived variables.
GITHUB_REPO_URL=
RELEASE_BRANCH=
TAG=
GITHUB_REFS=
BRANCH_EXISTS="false"

# Constants.
readonly GITHUB_ORG_URL="github.com/tink-crypto"

usage() {
  echo "Usage: $0 [-rh] [-c <commit hash>] [-t <access token>] <action> \\"
  echo "         <version> <repository>"
  echo " <action>: The action to be performed (crete_branch|create_tag)."
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
      r) DO_RUN_ACTION="true" ;;
      c) COMMIT_HASH="${OPTARG}" ;;
      t) ACCESS_TOKEN="${OPTARG}" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly DO_RUN_ACTION
  readonly COMMIT_HASH
  readonly ACCESS_TOKEN

  ACTION="$1"
  if [[ ! "${ACTION}" =~ create_branch|create_tag ]]; then
    echo "ERROR: Expected (create_branch|create_tag) got ${ACTION}" >&2
    usage
  fi
  readonly ACTION

  VERSION="$2"
  if [[ ! "${VERSION}" =~ ^[0-9]+.[0-9]+.[0-9]+$ ]]; then
    echo "ERROR: Invalid version format: expected MAJOR.MINOR.PATCH, got \
${VERSION}" >&2
    usage
  fi
  readonly VERSION

  REPO_NAME="$3"
  if [[ -z "${REPO_NAME}" ]]; then
    echo "ERROR: Repo name must be specified." >&2
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

  # Splitting declaration and assignment guarantees correct propagation of the
  # exit code of the subshell.
  local GITHUB_REFS
  GITHUB_REFS="$(git ls-remote "${GITHUB_REPO_URL}")"
  readonly GITHUB_REFS

  local -r expected_release_branch="refs/heads/${RELEASE_BRANCH}"
  if echo "${GITHUB_REFS}" | grep "${expected_release_branch}" > /dev/null; then
    BRANCH_EXISTS="true"
  fi
  readonly BRANCH_EXISTS

  if [[ "${ACTION}" == "create_tag" ]]; then
    if [[ "${BRANCH_EXISTS}" == "false" ]]; then
      echo "ERROR: The release branch does not exist in \
${GITHUB_ORG_URL}/${REPO_NAME}." >&2
      return 1
    fi
    local -r release_tag="v${VERSION}"
    local -r expected_release_tag="refs/tags/${release_tag}"
    if echo "${GITHUB_REFS}" | grep "${expected_release_tag}" > /dev/null; then
      echo "ERROR The tag \"${release_tag}\" already exists in \
${GITHUB_ORG_URL}/${REPO_NAME}." >&2
      return 1
    fi

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
# Runs a command if DO_RUN_ACTION is true.
#
# Args:
#   Command to execute.
# Globals:
#   DO_RUN_ACTION
#
#######################################
run_command() {
  if [[ "${DO_RUN_ACTION}" == "false" ]]; then
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
# If COMMIT_HASH is specified, use COMMIT_HASH as HEAD for the branch.
#
# Globals:
#   RELEASE_BRANCH
#   COMMIT_HASH
#
#######################################
git_create_release_branch() {
  if [[ "${BRANCH_EXISTS}" == "true" ]]; then
    echo "WARNING: The release branch already exists. Nothing to do."
    return 0
  fi
  # Target branch does not exist so we create the release branch.
  if [[ -n "${COMMIT_HASH:-}" ]]; then
    # Use COMMIT_HASH as HEAD for this branch.
    print_and_run_command git branch "${RELEASE_BRANCH}" "${COMMIT_HASH}"
  else
    print_and_run_command git branch "${RELEASE_BRANCH}"
  fi
  print_and_run_command git push origin "${RELEASE_BRANCH}"
}

#######################################
# Creates a release tag.
#
# Globals:
#   RELEASE_BRANCH
#   REPO_NAME
#   VERSION
#
#######################################
git_create_release_tag() {
  if [[ "${BRANCH_EXISTS}" == "false" ]]; then
    echo "ERROR: The release branch does not exist in \
${GITHUB_ORG_URL}/${REPO_NAME}." >&2
    return 1
  fi
  local -r release_tag="v${VERSION}"
  local -r expected_release_tag="refs/tags/${release_tag}"
  if echo "${GITHUB_REFS}" | grep "${expected_release_tag}" > /dev/null; then
    echo "ERROR The tag \"${release_tag}\" already exists in \
${GITHUB_ORG_URL}/${REPO_NAME}." >&2
    return 1
  fi
  print_and_run_command git checkout "${RELEASE_BRANCH}"
  print_and_run_command git tag -a "${release_tag}" \
    -m "${REPO_NAME} version ${VERSION}"
  print_and_run_command git push origin "${release_tag}"
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

  case "${ACTION}" in
    create_branch) git_create_release_branch ;;
    create_tag) git_create_release_tag ;;
  esac
}

main "$@"
