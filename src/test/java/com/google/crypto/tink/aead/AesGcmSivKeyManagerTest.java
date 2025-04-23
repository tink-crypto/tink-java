// Copyright 2017 Google Inc.
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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AesGcmSivParameters.Variant;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesGcmSivKeyManagerTest. */
@RunWith(Theories.class)
public class AesGcmSivKeyManagerTest {
  @Before
  public void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // Ignore. This fails on android, in which case Conscrypt is already installed by default.
    }
    AeadConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.AesGcmSivKey", Aead.class))
        .isNotNull();
  }

  @Test
  public void testKeyCreationWorks() throws Exception {
    Parameters validParameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    assertThat(KeysetHandle.generateNew(validParameters).getAt(0).getKey().getParameters())
        .isEqualTo(validParameters);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder().setKeySizeBytes(16).setVariant(Variant.NO_PREFIX).build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext.length)
        .isEqualTo(12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */);
  }

  @Test
  public void testAes128GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.aes128GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(16)
                .setVariant(AesGcmSivParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes128GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.rawAes128GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(16)
                .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testAes256GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.aes256GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesGcmSivParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.rawAes256GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesGcmSivKeyManager.aes128GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.rawAes128GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.aes256GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.rawAes256GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {"AES128_GCM_SIV", "AES256_GCM_SIV", "AES256_GCM_SIV_RAW", "AES128_GCM_SIV_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Theory
  public void testCreateKeyFromRandomness(@FromDataPoints("templateNames") String templateName)
      throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    AesGcmSivParameters parameters =
        (AesGcmSivParameters) KeyTemplates.get(templateName).toParameters();
    AesGcmSivKey key =
        AesGcmSivKeyManager.createAesGcmSivKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    AesGcmSivKey key =
        AesGcmSivKeyManager.createAesGcmSivKeyFromRandomness(
            parameters,
            SlowInputStream.copyFrom(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testEncryptDecrypt_works() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    AesGcmSivKey aesGcmSivKey =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmSivKey).withRandomId().makePrimary())
            .build();
    Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // Encrypt an empty plaintext, and verify that it can be decrypted.
    byte[] ciphertext = aead.encrypt(new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
    byte[] decrypted = aead.decrypt(ciphertext, new byte[] {4, 5, 6});
    assertThat(decrypted).isEqualTo(new byte[] {1, 2, 3});
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[] {4, 5}));
  }

  @Test
  public void testEncryptAndDecryptFailBeforeAndroid30() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeNotNull(apiLevel);
    Assume.assumeTrue(apiLevel < 30);

    // Use an AES GCM test vector from AesGcmJceTest.testWithAesGcmKey_noPrefix_works
    byte[] keyBytes = Hex.decode("5b9604fe14eadba931b0ccf34843dab9");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .build();
    // Create an AEAD primitive for aesGcmSivKey.
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class));
  }

  // This test shows how ciphertexts created with older versions of Tink on older versions of
  // Android can still be decrypted with the current version of Tink.
  @Test
  public void testDecryptCiphertextCreatedOnOlderVersionOfAndroid() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    // A valid AES GCM SIV key.
    AesGcmSivKey aesGcmSivKey =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();

    // Valid ciphertext of an empty plaintext created with aesGcmSivKey.
    byte[] validCiphertext = Hex.decode("17871550708697c27881d04753337526f2bed57b7e2eac30ecde0202");

    // Ciphertext created with aesGcmSivKey on Android version 29 before
    // https://github.com/tink-crypto/tink-java/issues/18 was fixed.
    byte[] legacyCiphertext =
        Hex.decode("c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");

    // Create an Aead instance that can decrypt in both AES GCM and AES GCM SIV.
    AesGcmKey legacyKey =
        AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(aesGcmSivKey.getKeyBytes())
            .build();
    KeysetHandle backwardsCompatibleKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmSivKey).withRandomId().makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey).withRandomId())
            .build();
    Aead backwardsCompatibleAead =
        backwardsCompatibleKeysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // Check that backwardsCompatibleAead can decrypt both valid and legacy ciphertexts.
    assertThat(backwardsCompatibleAead.decrypt(validCiphertext, new byte[] {})).isEmpty();
    assertThat(backwardsCompatibleAead.decrypt(legacyCiphertext, new byte[] {})).isEmpty();
  }

  @Test
  public void getPrimitiveFromKeysetHandle() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder().setKeySizeBytes(16).setVariant(Variant.TINK).build();
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    Aead directAead = AesGcmSiv.create(key);

    assertThat(aead.decrypt(directAead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
    assertThat(directAead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
