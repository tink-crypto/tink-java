#!/bin/bash

# Copyright 2021 Google LLC
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

# Installs the Android SDK and tools and sets the ANDROID_HOME environment
# variable if running on Kokoro.
set -x

if [[ -z "${KOKORO_ROOT}" ]] ; then
  exit 0
fi

readonly ANDROID_COMMANDLINETOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-8512546_latest.zip"
readonly ANDROID_COMMANDLINETOOLS_SHA256="2ccbda4302db862a28ada25aa7425d99dce9462046003c1714b059b5c47970d8"
readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

export ANDROID_HOME="/tmp/android-sdk"

if [[ "${PLATFORM}" == 'darwin' ]]; then
  export JAVA_OPTS="-Djava.net.preferIPv6Addresses=true"
fi

mkdir -p "${ANDROID_HOME}"
time curl -LsS "${ANDROID_COMMANDLINETOOLS_URL}" -o cmdline-tools.zip
echo "${ANDROID_COMMANDLINETOOLS_SHA256} cmdline-tools.zip" | sha256sum -c
unzip cmdline-tools.zip -d "${ANDROID_HOME}"
# Discard STDOUT due to noisy progress bar which can't be silenced.
(yes || true) | "${ANDROID_HOME}/cmdline-tools/bin/sdkmanager" \
  "--sdk_root=${ANDROID_HOME}" \
  "build-tools;30.0.3" \
  "platforms;android-23" \
  "platforms;android-26" \
  > /dev/null
rm -rf cmdline-tools.zip
