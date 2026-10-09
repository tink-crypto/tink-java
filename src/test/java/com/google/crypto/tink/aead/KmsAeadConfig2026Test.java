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
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.aead.LegacyKmsEnvelopeAeadParameters.DekParsingStrategy;
import com.google.crypto.tink.testing.FakeKmsClient;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link KmsAeadConfig2026}. */
@RunWith(Theories.class)
public class KmsAeadConfig2026Test {
  private static final String KEK_URI =
      "fake-kms://CIqphp8HEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
          + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhBBqhLL7pdFk-FzEYi4lo5CGigSBAgDEBAaIFRMn3OEi"
          + "QQKUb85xOdhmuqMmvderls5oymgmtSLYKabGAEQARiKqYafByAB";
  private static final String GLOBAL_KEK_URI =
      "fake-kms://CPeFs9sGEo0BCoABCjh0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5B"
          + "ZXNDdHJIbWFjQWVhZEtleRJCEhYSAggQGhCE7VadpBOqUEib9Db55aI2GigSBAgDEBAaII0DdIzGe"
          + "3r2nXHnGoSRa9GZXGsjZsl719GfJrhtjjVGGAEQARj3hbPbBiAB";

  @BeforeClass
  public static void setUpClass() throws Exception {
    KmsClients.add(new FakeKmsClient(GLOBAL_KEK_URI));
  }

  /**
   * A list of Keys which behave commonly for this config. For these keys we can:
   *
   * <ul>
   *   <li>create primitives
   *   <li>create new keys with the same parameters
   *   <li>serialize and parse the keys
   *   <li>serialize and parse the parameters
   * </ul>
   */
  @DataPoints public static final Key[] keys = createKeys();

  private static Key[] createKeys() {
    try {
      return new Key[] {
        LegacyKmsAeadKey.create(
            LegacyKmsAeadParameters.create(KEK_URI, LegacyKmsAeadParameters.Variant.TINK), 1234),
        LegacyKmsAeadKey.create(
            LegacyKmsAeadParameters.create(KEK_URI, LegacyKmsAeadParameters.Variant.NO_PREFIX)),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_GCM)
                .setDekParametersForNewKeys(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build(),
            1234),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_GCM)
                .setDekParametersForNewKeys(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build()),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_EAX)
                .setDekParametersForNewKeys(
                    AesEaxParameters.builder()
                        .setIvSizeBytes(16)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                        .build())
                .build()),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_CTR_HMAC)
                .setDekParametersForNewKeys(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build()),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_CHACHA20POLY1305)
                .setDekParametersForNewKeys(
                    ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX))
                .build()),
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(KEK_URI)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
                .setDekParametersForNewKeys(
                    XChaCha20Poly1305Parameters.create(
                        XChaCha20Poly1305Parameters.Variant.NO_PREFIX))
                .build()),
      };
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Theory
  public void createKey_works(Key key) throws Exception {
    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(KEK_URI));
    KeysetHandle handle = KeysetHandle.generateNew(key.getParameters(), config);

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

    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(KEK_URI));
    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get(), config);
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get(), config);

    assertThat(parsed.equalsKeyset(keysetHandle)).isTrue();

    byte[] serializedWithoutSecret =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, config);
    KeysetHandle parsedWithoutSecret =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedWithoutSecret, config);

    assertThat(parsedWithoutSecret.equalsKeyset(keysetHandle)).isTrue();
  }

  @Theory
  public void serializeAndParseParameters_works(Key key) throws Exception {
    Parameters parameters = key.getParameters();
    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(KEK_URI));
    byte[] serialized = TinkProtoParametersFormat.serialize(parameters, config);
    Parameters parsed = TinkProtoParametersFormat.parse(serialized, config);

    assertThat(parsed).isEqualTo(parameters);
  }

  @Theory
  public void getPrimitive_getForKmsClients_works(Key key) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    if (key.getIdRequirementOrNull() == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(key.getIdRequirementOrNull());
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry).build();

    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(KEK_URI));
    Aead aead = keysetHandle.getPrimitive(config, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);

    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void getUsingGlobalKmsClients_kmsAead_works() throws Exception {
    LegacyKmsAeadParameters parameters =
        LegacyKmsAeadParameters.create(GLOBAL_KEK_URI, LegacyKmsAeadParameters.Variant.TINK);
    Configuration config = KmsAeadConfig2026.getUsingGlobalKmsClients();
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);

    Aead aead = handle.getPrimitive(config, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void getUsingGlobalKmsClients_kmsEnvelopeAead_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri(GLOBAL_KEK_URI)
            .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
            .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    Configuration config = KmsAeadConfig2026.getUsingGlobalKmsClients();
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);

    Aead aead = handle.getPrimitive(config, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void getUsingGlobalKmsClients_unregisteredUri_throws() throws Exception {
    String unregisteredUri = FakeKmsClient.createFakeKeyUri();
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create(unregisteredUri);
    Configuration config = KmsAeadConfig2026.getUsingGlobalKmsClients();
    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);

    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(config, Aead.class));
  }

  @Test
  public void getForKmsClients_multipleClients_works() throws Exception {
    String kekUri1 = FakeKmsClient.createFakeKeyUri();
    String kekUri2 = FakeKmsClient.createFakeKeyUri();
    KmsClient client1 = new FakeKmsClient(kekUri1);
    KmsClient client2 = new FakeKmsClient(kekUri2);
    Configuration config = KmsAeadConfig2026.getForKmsClients(client1, client2);

    Key key1 =
        LegacyKmsAeadKey.create(
            LegacyKmsAeadParameters.create(kekUri1, LegacyKmsAeadParameters.Variant.TINK), 1);
    Key key2 =
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(kekUri2)
                .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_GCM)
                .setDekParametersForNewKeys(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build(),
            2);

    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key1).withFixedId(1).makePrimary())
            .build();
    KeysetHandle handle2 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key1).withFixedId(1))
            .addEntry(KeysetHandle.importKey(key2).withFixedId(2).makePrimary())
            .build();

    Aead aead1 = handle1.getPrimitive(config, Aead.class);
    Aead aead2 = handle2.getPrimitive(config, Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);
    byte[] ciphertext2 = aead2.encrypt(plaintext, associatedData);

    assertThat(aead2.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
    assertThat(aead2.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void getForKmsClients_doesNotUseGlobalKmsClients() throws Exception {
    String otherUri = FakeKmsClient.createFakeKeyUri();
    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(otherUri));

    // GLOBAL_KEK_URI is registered in global KmsClients, but not in config's clients.
    KeysetHandle handle =
        KeysetHandle.generateNew(LegacyKmsAeadParameters.create(GLOBAL_KEK_URI), config);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(config, Aead.class));
  }

  @Test
  public void getForKmsClients_emptyClients_getPrimitiveThrows() throws Exception {
    Configuration config = KmsAeadConfig2026.getForKmsClients();
    KeysetHandle handle = KeysetHandle.generateNew(LegacyKmsAeadParameters.create(KEK_URI), config);

    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(config, Aead.class));
  }

  @Test
  public void getForKmsClients_defensiveCopyOfArray() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KmsClient[] clients = new KmsClient[] {new FakeKmsClient(kekUri)};
    Configuration config = KmsAeadConfig2026.getForKmsClients(clients);
    // Mutate the input array after creating the configuration.
    clients[0] = new FakeKmsClient(FakeKmsClient.createFakeKeyUri());

    KeysetHandle handle = KeysetHandle.generateNew(LegacyKmsAeadParameters.create(kekUri), config);
    Aead aead = handle.getPrimitive(config, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThat(aead.decrypt(aead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void aesGcmSivDek_serializeAndParse_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri(KEK_URI)
            .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
            .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_GCM_SIV)
            .setDekParametersForNewKeys(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    Configuration config = KmsAeadConfig2026.getForKmsClients(new FakeKmsClient(KEK_URI));

    byte[] serializedParams = TinkProtoParametersFormat.serialize(parameters, config);
    assertThat(TinkProtoParametersFormat.parse(serializedParams, config)).isEqualTo(parameters);

    KeysetHandle handle = KeysetHandle.generateNew(parameters, config);
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle, config);
    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, config);
    assertThat(parsedKeyset.equalsKeyset(handle)).isTrue();
  }
}
