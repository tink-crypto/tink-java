// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for PrfConfig2026 which run under fips mode.
 *
 * <p>We test this by tagging the test with "fips" which will run in three configurations:
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=False,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True and BORINGSSL_FIPS=0 in C++.`
 */
@RunWith(JUnit4.class)
public class PrfConfig2026FipsTest {
  @BeforeClass
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Nullable
  private static PrfKey createHmacPrfKeyOrNull() {
    try {
      return HmacPrfKey.builder()
          .setParameters(
              HmacPrfParameters.builder()
                  .setKeySizeBytes(32)
                  .setHashType(HmacPrfParameters.HashType.SHA256)
                  .build())
          .setKeyBytes(SecretBytes.randomBytes(32))
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static PrfKey createHkdfPrfKeyOrNull() {
    try {
      return HkdfPrfKey.builder()
          .setParameters(
              HkdfPrfParameters.builder()
                  .setKeySizeBytes(32)
                  .setHashType(HkdfPrfParameters.HashType.SHA256)
                  .build())
          .setKeyBytes(SecretBytes.randomBytes(32))
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static PrfKey createAesCmacPrfKeyOrNull() {
    try {
      return AesCmacPrfKey.create(AesCmacPrfParameters.create(32), SecretBytes.randomBytes(32));
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  /**
   * Returns Keys which should work.
   *
   * <p>If `//src/main/java/com/google/crypto/tink/config:use_only_fips=False` then this is all
   * keys. If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and BoringSSL was
   * compiled with `BORINGSSL_FIPS` then these are the FIPS keys in BoringSSL. If
   * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and `BORINGSSL_FIPS=0` then
   * this is the empty list.
   */
  private static List<PrfKey> createKeysWhichShouldWork() {
    // On Android we don't want to run this test.
    if (TestUtil.isAndroid()) {
      return new ArrayList<>();
    }
    ArrayList<PrfKey> result = new ArrayList<>();
    if (TinkFipsUtil.fipsModuleAvailable() || !TinkFipsUtil.useOnlyFips()) {
      result.add(createHmacPrfKeyOrNull());
    }

    if (!TinkFipsUtil.useOnlyFips()) {
      result.add(createHkdfPrfKeyOrNull());
      result.add(createAesCmacPrfKeyOrNull());
    }
    // Of the supported keys, no key should be null.
    for (int i = 0; i < result.size(); i++) {
      assertWithMessage("Position %s is null", i).that(result.get(i)).isNotNull();
    }
    return result;
  }

  /**
   * Returns Keys which should fail.
   *
   * <p>If `//src/main/java/com/google/crypto/tink/config:use_only_fips=False` then this is empty.
   * If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True` and BoringSSL was
   * compiled with `BORINGSSL_FIPS` then these are the keys which can still be created in Tink, and
   * which are not FIPS. (Note that it is acceptable if creating the key fails in this case, then we
   * simply ignore the key). If `//src/main/java/com/google/crypto/tink/config:use_only_fips=True`
   * and `BORINGSSL_FIPS=0` then this is all keys which can still be created.
   */
  private static List<PrfKey> createKeysWhichShouldFail() {
    // On Android we don't want to run this test.
    if (TestUtil.isAndroid()) {
      return new ArrayList<>();
    }
    ArrayList<PrfKey> result = new ArrayList<>();
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      PrfKey hmacKey = createHmacPrfKeyOrNull();
      if (hmacKey != null) {
        result.add(hmacKey);
      }
    }

    if (TinkFipsUtil.useOnlyFips()) {
      PrfKey hkdfKey = createHkdfPrfKeyOrNull();
      if (hkdfKey != null) {
        result.add(hkdfKey);
      }
      PrfKey aesCmacKey = createAesCmacPrfKeyOrNull();
      if (aesCmacKey != null) {
        result.add(aesCmacKey);
      }
    }
    return result;
  }

  @Test
  public void getPrimitive_prfSet_works() throws Exception {
    for (PrfKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      PrfSet prfSet = handle.getPrimitive(PrfConfig2026.get(), PrfSet.class);

      byte[] message = "message".getBytes(UTF_8);
      byte[] output = prfSet.computePrimary(message, 16);
      assertThat(output).hasLength(16);
    }
  }

  @Test
  public void serializeAndParseKey_works() throws Exception {
    for (PrfKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = PrfConfig2026.get();
      byte[] serialized =
          TinkProtoKeysetFormat.serializeKeyset(
              keysetHandle, InsecureSecretKeyAccess.get(), config);
      KeysetHandle parsed =
          TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

      assertWithMessage("Failed for key: %s", key).that(parsed.equalsKeyset(keysetHandle)).isTrue();
    }
  }

  @Test
  public void serializeAndParseParameters_works() throws Exception {
    for (PrfKey key : createKeysWhichShouldWork()) {
      Parameters parameters = key.getParameters();
      Configuration config = PrfConfig2026.get();
      byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
      Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed).isEqualTo(parameters);
    }
  }

  @Test
  public void createKey_works() throws Exception {
    for (PrfKey key : createKeysWhichShouldWork()) {
      Configuration config = PrfConfig2026.get();

      KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

      assertWithMessage("Failed for key: %s", key)
          .that(handle.getPrimary().getKey().getParameters())
          .isEqualTo(key.getParameters());
    }
  }

  @Test
  public void getPrimitive_nonFipsKeys_throws() throws Exception {
    for (PrfKey key : createKeysWhichShouldFail()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration configuration = PrfConfig2026.get();
      assertThrows(
          "Expected getPrimitive(PrfSet) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, PrfSet.class));
    }
  }

  @Test
  public void createKey_nonFipsKeys_throws() throws Exception {
    for (PrfKey key : createKeysWhichShouldFail()) {
      Configuration config = PrfConfig2026.get();

      assertThrows(
          "Expected generateNew to throw for key: " + key,
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
    }
  }

  // Note: we do not check parse/serialize for Non-FIPS keys -- we are fine with either behavior.
}
