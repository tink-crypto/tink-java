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
####################################################################################

# This script runs the Java hello world test application with Maven.
#
# This is to test Maven snapshots that, if local, should be pre-installed
# locally.

usage() {
  echo "Usage: $0 [-lh] <path/to/example/helloworld/pom.xml>"
  echo "  -l: Local. Test a local tink-java artifact (default: false)."
  echo "  -h: Help. Print this usage information."
  exit 1
}

# Load the test library.
source "kokoro/testutils/test_utils.sh"

LOCAL="false"
EXAMPLE_APPLICATION_POM=

process_args() {
  while getopts "lh" opt; do
    case "${opt}" in
      l) LOCAL="true" ;;
      h) usage ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly LOCAL
  EXAMPLE_APPLICATION_POM="$1"
  readonly EXAMPLE_APPLICATION_POM
}

test_MavenSnapshotTest_RunJavaTestApplication() {
  local mvn_flags=()
  if [[ "${LOCAL}" == "true" ]]; then
    # Use snapshots present in the local repository.
    mvn_flags+=( --no-snapshot-updates )
  fi
  readonly mvn_flags
  mvn "${mvn_flags[@]}" package -f "${EXAMPLE_APPLICATION_POM}"
  ASSERT_CMD_SUCCEEDED

  local -r plaintext="${TEST_CASE_TMPDIR}/plaintext.bin"
  local -r encrypted="${TEST_CASE_TMPDIR}/encrypted.bin"
  local -r decrypted="${TEST_CASE_TMPDIR}/decrypted.bin"
  local -r keyset="${TEST_CASE_TMPDIR}/keyset.cfg"

  dd if=/dev/urandom of="${plaintext}" bs=1K count=1
  mvn exec:java "${mvn_flags[@]}" -f "${EXAMPLE_APPLICATION_POM}" \
    -Dexec.args="encrypt --keyset ${keyset} --in ${plaintext} --out \
${encrypted}"
  ASSERT_CMD_SUCCEEDED
  mvn exec:java "${mvn_flags[@]}" -f $EXAMPLE_APPLICATION_POM \
    -Dexec.args="decrypt --keyset ${keyset} --in ${encrypted} --out \
${decrypted}"
  ASSERT_CMD_SUCCEEDED
  ASSERT_FILE_EQUALS "${plaintext}" "${decrypted}"
}

main() {
  process_args "$@"
  run_all_tests
}

main "$@"
