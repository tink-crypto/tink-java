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

# This script is meant to be run as root in Docker using the Tink Java Docker
# image. It assumes that /tink_orig_dir/tink_java contains a clone of
# https://github.com/tink-crypto/tink-java (which it will read as root).
#  - Run all necessary tests for doing a release.
#  - Build the following targets (as tinkuser):
#      @tink-java//:tink-snapshot-bundle
#      @tink-java//:tink-android-snapshot-bundle
#  - If the files /tink_orig_dir/tink-java/gpg_pin.txt and
#    /tink_orig_dir/tink_java/gpg_key.asc both exist, also build:
#      @tink-java//:tink-release-bundle
#      @tink-java//:tink-android-relase-bundle
#  - Copy the resulting files into /tink_orig_dir/kokoro_upload_dir/

# Generated with openssl rand -hex 10
echo "================================================================================"
echo "Tink Script ID: 99f3f260ad81d267c339 (to quickly find the script from logs)"
echo "================================================================================"

set -euox pipefail

### ======================================== EMBEDDED SCRIPT: _do_as_tinkuser.sh
### The _do_as_tinkuser.sh script will run as "tinkuser"
cat <<'END_DO_AS_TINKUSER' > /tink_orig_dir/tink_java/_do_as_tinkuser.sh
#!/bin/bash
set -euo pipefail

# TODO: b/442549419 Add mvn to the standard path in the Docker image.
export PATH=/usr/local/apache-maven/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export ANDROID_HOME=/android-sdk-30

# Compare the dependencies of the ":tink" target with the declared dependencies.
# These should match the dependencies declared in tink-java.pom.xml, since
# since these are the dependencies which are declared on maven.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh "//:tink" \
  "maven/tink-java.pom.xml"

# For Android, we compare the unshaded version -- trial and error revealed that
# this is the target that has the correct dependencies.
./kokoro/testutils/check_maven_bazel_deps_consistency.sh \
  -e com.google.protobuf:protobuf-javalite \
  "//:tink-android-unshaded" "maven/tink-java-android.pom.xml"


echo "Creating GPG key and GPG pin for testing"
echo "========================================"
openssl rand -hex 20 > gpg_test_pin.txt
cat > /tmp/keygen.conf << -EOKEYGEN
        %echo Generating a basic RSA 2048 key
        Key-Type: RSA
        Key-Length: 2048
        Subkey-Type: RSA
        Subkey-Length: 2048
        Expire-Date: 1y
        Name-Real: Key For Testing
        Name-Email: non_existent_email@tink_google_crypto.com
        Name-Comment: Key for Testing
        %commit
        %echo Done
-EOKEYGEN

export GNUPGHOME=$(mktemp -d)
gpg --full-generate-key --batch \
    --passphrase-fd 0 \
    --passphrase-file gpg_test_pin.txt \
    --pinentry-mode loopback \
    /tmp/keygen.conf
gpg --export-secret-keys --batch \
    --passphrase-fd 0 \
    --pinentry-mode loopback \
    --passphrase-file gpg_test_pin.txt \
    --armor > gpg_test_key.asc

echo "Done creating GPG key and GPG pin"
echo "================================="

sed -i "s/always --noenable_bzlmod/always --enable_bzlmod/g" .bazelrc
sed -i "s/always --enable_workspace/always --noenable_workspace/g" .bazelrc

cat .bazelrc

mkdir exported_bundles

bazelisk build :tink-snapshot-bundle
cp bazel-bin/tink-snapshot-bundle.zip exported_bundles

# Run tests in https://github.com/tink-crypto/tink-java/tree/main/examples/maven
{
  TMP_JAR_DIR=$(mktemp -d)
  unzip bazel-bin/tink-snapshot-bundle.zip -d "${TMP_JAR_DIR}"
  mvn install:install-file \
        "-Dfile=${TMP_JAR_DIR}/com/google/crypto/tink/tink/HEAD-SNAPSHOT/tink-HEAD-SNAPSHOT.jar" \
        "-Dsources=${TMP_JAR_DIR}/com/google/crypto/tink/tink/HEAD-SNAPSHOT/tink-HEAD-SNAPSHOT-sources.jar" \
        "-Djavadoc=${TMP_JAR_DIR}/com/google/crypto/tink/tink/HEAD-SNAPSHOT/tink-HEAD-SNAPSHOT-javadoc.jar" \
        "-DpomFile=${TMP_JAR_DIR}/com/google/crypto/tink/tink/HEAD-SNAPSHOT/tink-HEAD-SNAPSHOT.pom"
  pushd examples/maven
  mvn -f pom-for-tink-snapshot.xml test
  popd
}

bazelisk build :tink-android-snapshot-bundle
cp bazel-bin/tink-android-snapshot-bundle.zip exported_bundles

# If the file gpg_pin.txt exist then we assume that gpg_key.asc also exists.
# The build will fail otherwise which is fine.
if [[ -f "gpg_pin.txt" ]]; then
  bazelisk build :tink-release-bundle
  cp bazel-bin/tink-release-bundle.zip exported_bundles
  bazelisk build :tink-android-release-bundle
  cp bazel-bin/tink-android-release-bundle.zip exported_bundles
fi

END_DO_AS_TINKUSER
### ==================================================== END: _do_as_tinkuser.sh

chmod +x /tink_orig_dir/tink_java/_do_as_tinkuser.sh

echo "=== COPYING /tink_orig_dir to /home/tinkuser"
cp -r /tink_orig_dir/tink_java /home/tinkuser
chown --recursive tinkuser:tinkgroup /home/tinkuser/tink_java
cd /home/tinkuser/tink_java

echo "=== SWITCHING to tinkuser"
su tinkuser /usr/bin/bash -c "./_do_as_tinkuser.sh"

mkdir -p /tink_orig_dir/kokoro_upload_dir/
cp -r exported_bundles/* /tink_orig_dir/kokoro_upload_dir/

exit
