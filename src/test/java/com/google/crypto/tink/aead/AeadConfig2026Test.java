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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link AeadConfig2026}. */
@RunWith(Theories.class)
public class AeadConfig2026Test {

  @BeforeClass
  public static void setUp() throws Exception {
    if (!Util.isAndroid() && Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }
  }

  private static boolean shouldSupportAesGcmSiv() {
    if (Util.isAndroid()) {
      return Util.getAndroidApiLevel() >= 30;
    }
    return Conscrypt.isAvailable();
  }

  /**
   * A list of Keys which behave common for this config. For these keys we can
   *
   * <ul>
   *   <li>create primitives
   *   <li>create new keys with the same parameters
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters.
   * </ul>
   */
  @DataPoints public static final Key[] keys = createKeys();

  private static Key[] createKeys() {
    try {
      return new Key[] {
        AesCtrHmacAeadKey.builder()
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
            .build(),
        AesCtrHmacAeadKey.builder()
            .setParameters(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                    .build())
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .build(),
        AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1234)
            .build(),
        AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(12)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build(),
        AesEaxKey.builder()
            .setParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1234)
            .build(),
        AesEaxKey.builder()
            .setParameters(
                AesEaxParameters.builder()
                    .setKeySizeBytes(16)
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build(),
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 1234),
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.NO_PREFIX, SecretBytes.randomBytes(32), null),
        XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.TINK, SecretBytes.randomBytes(32), 1234),
        XChaCha20Poly1305Key.create(
            XChaCha20Poly1305Parameters.Variant.NO_PREFIX, SecretBytes.randomBytes(32), null),
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.TINK, 12),
            SecretBytes.randomBytes(32),
            1234),
        XAesGcmKey.create(
            XAesGcmParameters.create(XAesGcmParameters.Variant.NO_PREFIX, 12),
            SecretBytes.randomBytes(32),
            null),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Theory
  public void createKey_works(Key key) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), AeadConfig2026.get());
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(key.getParameters());
  }

  @Theory
  public void serializeAndParseKey_works(Key key) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = AeadConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(Key key) throws Exception {
    Parameters parameters = key.getParameters();
    Configuration config = AeadConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_works(Key key) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Aead aead = keysetHandle.getPrimitive(AeadConfig2026.get(), Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void aesGcmSiv_createKey_works() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters, AeadConfig2026.get());
    assertThat(handle.getPrimary().getKey().getParameters()).isEqualTo(parameters);
  }

  @Test
  public void aesGcmSiv_serializeAndParseKey_works() throws Exception {
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1234)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1234).makePrimary())
            .build();
    Configuration config = AeadConfig2026.get();
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);
    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();
  }

  @Test
  public void aesGcmSiv_serializeAndParseParameters_works() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build();
    Configuration config = AeadConfig2026.get();
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);
    assertThat(parsed).isEqualTo(parameters);
  }

  @Test
  public void aesGcmSiv_getPrimitive_works() throws Exception {
    AesGcmSivKey key =
        AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(1234)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1234).makePrimary())
            .build();

    if (shouldSupportAesGcmSiv()) {
      Aead aead = keysetHandle.getPrimitive(AeadConfig2026.get(), Aead.class);
      byte[] plaintext = "plaintext".getBytes(UTF_8);
      byte[] associatedData = "associatedData".getBytes(UTF_8);
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      byte[] decrypted = aead.decrypt(ciphertext, associatedData);
      assertThat(decrypted).isEqualTo(plaintext);
    } else {
      Configuration config = AeadConfig2026.get();
      assertThrows(
          GeneralSecurityException.class,
          () -> keysetHandle.getPrimitive(config, Aead.class));
    }
  }

  @Test
  public void createKey_parametersWithIdRequirementButPassedNull_throws() throws Exception {
    AesGcmParameters parameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.TINK)
            .build();
    Configuration config = AeadConfig2026.get();
    assertThrows(GeneralSecurityException.class, () -> config.createKey(parameters, null));
  }
}
