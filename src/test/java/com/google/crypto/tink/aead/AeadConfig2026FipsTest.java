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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertWithMessage;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.Aead;
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
 * Tests for AeadConfig2026 which run under fips mode.
 *
 * <p>We test this by tagging the test with "fips" which will run it three configurations: *
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=False,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True,`
 * `//src/main/java/com/google/crypto/tink/config:use_only_fips=True and BORINGSSL_FIPS=0 in C++.`
 */
@RunWith(JUnit4.class)
public class AeadConfig2026FipsTest {
  @BeforeClass
  public static void setup() {
    if (TestUtil.isAndroid()) {
      return;
    }
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());
  }

  @Nullable
  private static AeadKey createAesCtrHmacAeadKeyOrNull() {
    try {
      return AesCtrHmacAeadKey.builder()
          .setParameters(
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(16)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setIvSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                  .build())
          .setAesKeyBytes(SecretBytes.randomBytes(16))
          .setHmacKeyBytes(SecretBytes.randomBytes(32))
          .setIdRequirement(1234)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createAesGcmKeyOrNull() {
    try {
      return AesGcmKey.builder()
          .setParameters(
              AesGcmParameters.builder()
                  .setKeySizeBytes(16)
                  .setIvSizeBytes(12)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build())
          .setKeyBytes(SecretBytes.randomBytes(16))
          .setIdRequirement(1234)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createAesEaxKeyOrNull() {
    try {
      return AesEaxKey.builder()
          .setParameters(
              AesEaxParameters.builder()
                  .setKeySizeBytes(16)
                  .setIvSizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.TINK)
                  .build())
          .setKeyBytes(SecretBytes.randomBytes(16))
          .setIdRequirement(1234)
          .build();
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createChaCha20Poly1305KeyOrNull() {
    try {
      return ChaCha20Poly1305Key.create(
          ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 1234);
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createXChaCha20Poly1305KeyOrNull() {
    try {
      return XChaCha20Poly1305Key.create(
          XChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 1234);
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createXAesGcmKeyOrNull() {
    try {
      return XAesGcmKey.create(
          XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12),
          SecretBytes.randomBytes(32),
          1234);
    } catch (GeneralSecurityException | IllegalStateException e) {
      return null;
    }
  }

  @Nullable
  private static AeadKey createAesGcmSivKeyOrNull() {
    try {
      return AesGcmSivKey.builder()
          .setParameters(
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(16)
                  .setVariant(AesGcmSivParameters.Variant.TINK)
                  .build())
          .setKeyBytes(SecretBytes.randomBytes(16))
          .setIdRequirement(1234)
          .build();
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
  private static List<AeadKey> createKeysWhichShouldWork() {
    ArrayList<AeadKey> result = new ArrayList<>();
    if (TinkFipsUtil.fipsModuleAvailable() || !TinkFipsUtil.useOnlyFips()) {
      result.add(createAesCtrHmacAeadKeyOrNull());
      result.add(createAesGcmKeyOrNull());
    }

    if (!TinkFipsUtil.useOnlyFips()) {
      result.add(createAesEaxKeyOrNull());
      result.add(createChaCha20Poly1305KeyOrNull());
      result.add(createXChaCha20Poly1305KeyOrNull());
      result.add(createXAesGcmKeyOrNull());
      result.add(createAesGcmSivKeyOrNull());
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
  private static List<AeadKey> createKeysWhichShouldFail() {
    ArrayList<AeadKey> result = new ArrayList<>();
    if (TinkFipsUtil.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable()) {
      AeadKey aesCtrHmacAeadKey = createAesCtrHmacAeadKeyOrNull();
      if (aesCtrHmacAeadKey != null) {
        result.add(aesCtrHmacAeadKey);
      }
      AeadKey aesGcmKey = createAesGcmKeyOrNull();
      if (aesGcmKey != null) {
        result.add(aesGcmKey);
      }
    }

    if (TinkFipsUtil.useOnlyFips()) {
      AeadKey aesEaxKey = createAesEaxKeyOrNull();
      if (aesEaxKey != null) {
        result.add(aesEaxKey);
      }
      AeadKey chaCha20Poly1305Key = createChaCha20Poly1305KeyOrNull();
      if (chaCha20Poly1305Key != null) {
        result.add(chaCha20Poly1305Key);
      }
      AeadKey xChaCha20Poly1305Key = createXChaCha20Poly1305KeyOrNull();
      if (xChaCha20Poly1305Key != null) {
        result.add(xChaCha20Poly1305Key);
      }
      AeadKey xAesGcmKey = createXAesGcmKeyOrNull();
      if (xAesGcmKey != null) {
        result.add(xAesGcmKey);
      }
      AeadKey aesGcmSivKey = createAesGcmSivKeyOrNull();
      if (aesGcmSivKey != null) {
        result.add(aesGcmSivKey);
      }
    }
    return result;
  }

  @Test
  public void getPrimitive_aead_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      Aead aead = handle.getPrimitive(AeadConfig2026.get(), Aead.class);

      byte[] message = "message".getBytes(UTF_8);
      byte[] associatedData = "associatedData".getBytes(UTF_8);
      byte[] ciphertext = aead.encrypt(message, associatedData);
      try {
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);
        assertWithMessage("Decrypted message does not match for key: %s", key)
            .that(decrypted)
            .isEqualTo(message);
      } catch (GeneralSecurityException e) {
        assertWithMessage("Aead decryption failed for key: %s", key).fail();
      }
    }
  }

  @Test
  public void serializeAndParseKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldWork()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration config = AeadConfig2026.get();
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
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldWork()) {
      Parameters parameters = key.getParameters();
      Configuration config = AeadConfig2026.get();
      byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
      Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

      assertWithMessage("Failed for key: %s", key).that(parsed).isEqualTo(parameters);
    }
  }

  @Test
  public void createKey_works() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldWork()) {
      Configuration config = AeadConfig2026.get();

      KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

      assertWithMessage("Failed for key: %s", key)
          .that(handle.getPrimary().getKey().getParameters())
          .isEqualTo(key.getParameters());
    }
  }

  @Test
  public void getPrimitive_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldFail()) {
      KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
      if (key.getIdRequirementOrNull() == null) {
        entry.withRandomId();
      } else {
        entry.withFixedId(key.getIdRequirementOrNull());
      }
      KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

      Configuration configuration = AeadConfig2026.get();
      assertThrows(
          "Expected getPrimitive(Aead) to throw for key: " + key,
          GeneralSecurityException.class,
          () -> handle.getPrimitive(configuration, Aead.class));
    }
  }

  @Test
  public void createKey_nonFipsKeys_throws() throws Exception {
    assumeFalse(TestUtil.isAndroid());
    for (AeadKey key : createKeysWhichShouldFail()) {
      Configuration config = AeadConfig2026.get();

      assertThrows(
          "Expected generateNew to throw for key: " + key,
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(key.getParameters(), config));
    }
  }

  // Note: we do not check parse/serialize for Non-FIPS keys -- we are fine with either behavior.
}
