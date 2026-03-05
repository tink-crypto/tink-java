// Copyright 2017 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetHandleInterface;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters.HashType;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters.Variant;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link WrappedAead}. */
@RunWith(Theories.class)
public class WrappedAeadTest {

  private static AesCtrHmacAeadKey tinkKey;
  private static AesCtrHmacAeadKey tinkFixedKey;
  private static AesCtrHmacAeadKey tinkFixedKeyDifferentId;
  private static AesCtrHmacAeadKey crunchyFixedKey;
  private static AesCtrHmacAeadKey rawKey0;
  private static AesCtrHmacAeadKey rawKey1;
  private static AesCtrHmacAeadKey rawFixedKey;

  @DataPoints("keys")
  public static com.google.crypto.tink.Key[] keys;

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
    AesCtrHmacAeadParameters tinkParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA512)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(Variant.TINK)
            .build();
    tinkKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(tinkParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(42)
            .build();
    tinkFixedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(tinkParameters)
            .setAesKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setIdRequirement(42)
            .build();
    tinkFixedKeyDifferentId =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(tinkParameters)
            .setAesKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setIdRequirement(43)
            .build();
    AesCtrHmacAeadParameters crunchyParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA512)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(Variant.CRUNCHY)
            .build();
    crunchyFixedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(crunchyParameters)
            .setAesKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setIdRequirement(42)
            .build();
    AesCtrHmacAeadParameters rawParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(HashType.SHA512)
            .setIvSizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(Variant.NO_PREFIX)
            .build();
    rawKey0 =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(rawParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .build();
    rawKey1 =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(rawParameters)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .build();
    rawFixedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(rawParameters)
            .setAesKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0011223344556677889910111213141516171819202122232425262728293031"),
                    InsecureSecretKeyAccess.get()))
            .build();

    keys = new com.google.crypto.tink.Key[] {tinkKey, crunchyFixedKey, rawKey0};
  }

  private static Aead primitiveFactory(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) entry.getKey();
    return EncryptThenAuthenticate.create((AesCtrHmacAeadKey) key);
  }

  @Test
  public void wrappedNonRawEncrypt_addsPrefixToRawCiphertext() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] outputPrefix = Hex.decode("000000002a");

    KeysetHandle rawKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawFixedKey).withFixedId(0x0000002a).makePrimary())
            .build();
    Aead rawAead = WrappedAead.create(rawKeysetHandle, WrappedAeadTest::primitiveFactory);
    KeysetHandle tinkKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(crunchyFixedKey).makePrimary())
            .build();
    Aead crunchyAead = WrappedAead.create(tinkKeysetHandle, WrappedAeadTest::primitiveFactory);

    byte[] ciphertext = crunchyAead.encrypt(plaintext, associatedData);
    byte[] ciphertextPrefix = Arrays.copyOf(ciphertext, 5);
    byte[] ciphertextWithoutPrefix = Arrays.copyOfRange(ciphertext, 5, ciphertext.length);

    assertThat(ciphertextPrefix).isEqualTo(outputPrefix);
    assertThat(rawAead.decrypt(ciphertextWithoutPrefix, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void disabedKey_doesNotDecrypt() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    // Create ciphertext with tinkFixedKey.
    KeysetHandle handleWithFixedKey =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkFixedKey).makePrimary())
            .build();
    Aead fixedKeyAead = WrappedAead.create(handleWithFixedKey, WrappedAeadTest::primitiveFactory);
    byte[] fixedKeyCiphertext = fixedKeyAead.encrypt(plaintext, associatedData);

    // Create keyset with disabled tinkFixedKey.
    KeysetHandle handleWithDisabledKey =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkFixedKey).setStatus(KeyStatus.DISABLED))
            .addEntry(KeysetHandle.importKey(rawKey0).withRandomId().makePrimary())
            .build();
    Aead aead = handleWithDisabledKey.getPrimitive(RegistryConfiguration.get(), Aead.class);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(fixedKeyCiphertext, associatedData));
  }

  @Test
  public void wrappedNonRawDecrypt_decryptsRawCiphertextWithPrefix() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] outputPrefix = Hex.decode("010000002a");
    byte[] invalid = "invalid".getBytes(UTF_8);

    KeysetHandle rawKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawFixedKey).withFixedId(0x0000002a).makePrimary())
            .build();
    Aead rawAead = WrappedAead.create(rawKeysetHandle, WrappedAeadTest::primitiveFactory);
    KeysetHandle tinkKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkFixedKey).makePrimary())
            .build();
    Aead tinkAead = WrappedAead.create(tinkKeysetHandle, WrappedAeadTest::primitiveFactory);

    byte[] rawCiphertext = rawAead.encrypt(plaintext, associatedData);
    byte[] rawCiphertextWithTinkPrefix = Bytes.concat(outputPrefix, rawCiphertext);

    assertThat(tinkAead.decrypt(rawCiphertextWithTinkPrefix, associatedData)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> tinkAead.decrypt(rawCiphertext, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> tinkAead.decrypt(rawCiphertextWithTinkPrefix, invalid));
    assertThrows(GeneralSecurityException.class, () -> tinkAead.decrypt(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> tinkAead.decrypt("".getBytes(UTF_8), associatedData));
  }

  @Theory
  public void encryptAndDecrypt_success(@FromDataPoints("keys") com.google.crypto.tink.Key key)
      throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();
    Aead aead = WrappedAead.create(keysetHandle, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void encryptAndDecrypt_incorrectInputsFail(
      @FromDataPoints("keys") com.google.crypto.tink.Key key) throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] invalid = "invalid".getBytes(UTF_8);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();
    Aead aead = WrappedAead.create(keysetHandle, WrappedAeadTest::primitiveFactory);
    KeysetHandle incorrectKeyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(42).makePrimary())
            .build();
    Aead incorrectKeyAead =
        WrappedAead.create(incorrectKeyKeysetHandle, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt("".getBytes(UTF_8), associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> incorrectKeyAead.decrypt(ciphertext, associatedData));
  }

  @Test
  public void decryptWorksIfCiphertextIsValidForAnyPrimitiveInThePrimitiveSet() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withRandomId().makePrimary())
            .build();
    Aead aead0 = keysetHandle0.getPrimitive(RegistryConfiguration.get(), Aead.class);
    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withRandomId().makePrimary())
            .build();
    Aead aead1 = WrappedAead.create(keysetHandle1, WrappedAeadTest::primitiveFactory);
    KeysetHandle keysetHandle01 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withRandomId().makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey1).withRandomId())
            .build();
    Aead aead01 = WrappedAead.create(keysetHandle01, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext0 = aead0.encrypt(plaintext, associatedData);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);

    assertThat(aead01.decrypt(ciphertext0, associatedData)).isEqualTo(plaintext);
    assertThat(aead01.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void encryptUsesPrimaryPrimitive() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    AeadConfig.register();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withRandomId().makePrimary())
            .build();
    Aead aead0 = WrappedAead.create(keysetHandle0, WrappedAeadTest::primitiveFactory);
    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withRandomId().makePrimary())
            .build();
    Aead aead1 = WrappedAead.create(keysetHandle1, WrappedAeadTest::primitiveFactory);
    KeysetHandle keysetHandle01 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withRandomId().makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey1).withRandomId())
            .build();
    Aead aead01 = WrappedAead.create(keysetHandle01, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext = aead01.encrypt(plaintext, associatedData);

    // rawKey0 is the primary key of aead01. Therefore, aead0 should be able to decrypt, and aead1
    // not.
    assertThat(aead0.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThrows(GeneralSecurityException.class, () -> aead1.decrypt(ciphertext, associatedData));
  }

  @Theory
  public void decryptFailsIfEncryptedWithOtherKeyEvenIfKeyIdsAreEqual(
      @FromDataPoints("keys") com.google.crypto.tink.Key key) throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(42).makePrimary())
            .build();
    Aead aead0 = WrappedAead.create(keysetHandle0, WrappedAeadTest::primitiveFactory);
    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(42).makePrimary())
            .build();
    Aead aead1 = WrappedAead.create(keysetHandle1, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext = aead0.encrypt(plaintext, associatedData);

    assertThrows(GeneralSecurityException.class, () -> aead1.decrypt(ciphertext, associatedData));
  }

  @Test
  public void nonRawKeysWithSameKeyMaterialButDifferentKeyIds_decryptFails() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle tinkKeysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkFixedKey).makePrimary())
            .build();
    Aead tinkAead0 = WrappedAead.create(tinkKeysetHandle0, WrappedAeadTest::primitiveFactory);
    KeysetHandle tinkKeysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkFixedKeyDifferentId).makePrimary())
            .build();
    Aead tinkAead1 = WrappedAead.create(tinkKeysetHandle1, WrappedAeadTest::primitiveFactory);

    byte[] ciphertext = tinkAead0.encrypt(plaintext, associatedData);

    assertThrows(
        GeneralSecurityException.class, () -> tinkAead1.decrypt(ciphertext, associatedData));
  }

  @Test
  public void rawKeysWithSameKeyMaterialButDifferentKeyIds_decryptWorks() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    AeadConfig.register();

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(123).makePrimary())
            .build();
    Aead aead0 = WrappedAead.create(keysetHandle0, WrappedAeadTest::primitiveFactory);
    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(42).makePrimary())
            .build();
    Aead aead1 = WrappedAead.create(keysetHandle1, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext = aead0.encrypt(plaintext, associatedData);

    assertThat(aead1.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void testAeadWithoutAnnotations_hasNoMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(tinkKey).makePrimary()).build();
    Aead aead = WrappedAead.create(keysetHandle, WrappedAeadTest::primitiveFactory);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertext, "invalid".getBytes(UTF_8)));

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] plaintext = Random.randBytes(20);
    byte[] plaintext2 = Random.randBytes(30);
    byte[] associatedData = Random.randBytes(40);

    // generate ciphertext2 using key2
    KeysetHandle singleKeyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(43).makePrimary())
            .build();
    Aead aead2 = WrappedAead.create(singleKeyKeysetHandle, WrappedAeadTest::primitiveFactory);
    byte[] ciphertext2 = aead2.encrypt(plaintext2, associatedData);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle twoKeysKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(43))
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    Aead aead = WrappedAead.create(twoKeysKeysetHandle, WrappedAeadTest::primitiveFactory);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData); // uses key1 to encrypt
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
    byte[] decrypted2 = aead.decrypt(ciphertext2, associatedData);
    assertThat(decrypted2).isEqualTo(plaintext2);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(3);
    FakeMonitoringClient.LogEntry encEntry = logEntries.get(0);
    assertThat(encEntry.getKeyId()).isEqualTo(42);
    assertThat(encEntry.getPrimitive()).isEqualTo("aead");
    assertThat(encEntry.getApi()).isEqualTo("encrypt");
    assertThat(encEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(encEntry.getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry decEntry = logEntries.get(1);
    assertThat(decEntry.getKeyId()).isEqualTo(42);
    assertThat(decEntry.getPrimitive()).isEqualTo("aead");
    assertThat(decEntry.getApi()).isEqualTo("decrypt");
    assertThat(decEntry.getNumBytesAsInput()).isEqualTo(ciphertext.length);
    assertThat(decEntry.getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry dec2Entry = logEntries.get(2);
    assertThat(dec2Entry.getKeyId()).isEqualTo(43);
    assertThat(dec2Entry.getPrimitive()).isEqualTo("aead");
    assertThat(dec2Entry.getApi()).isEqualTo("decrypt");
    // ciphertext2 was encrypted with key2, which has a RAW ouput prefix.
    assertThat(dec2Entry.getNumBytesAsInput()).isEqualTo(ciphertext2.length);
    assertThat(dec2Entry.getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(0);
    assertThat(decFailure.getPrimitive()).isEqualTo("aead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimary().getId()).isEqualTo(42);
    assertThat(decFailure.getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingAead implements Aead {
    AlwaysFailingAead() {}

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  private static Aead primitiveFactoryForAlwaysFailing(KeysetHandleInterface.Entry entry)
      throws GeneralSecurityException {
    return new AlwaysFailingAead();
  }

  @Test
  public void testFailingAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle aesCtrHmacAeadKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .addAnnotations(MonitoringAnnotations.class, annotations)
            .build();
    Aead aead =
        WrappedAead.create(
            aesCtrHmacAeadKeysetHandle, WrappedAeadTest::primitiveFactoryForAlwaysFailing);

    byte[] randomBytes = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(randomBytes, associatedData));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(randomBytes, associatedData));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(2);
    FakeMonitoringClient.LogFailureEntry encFailure = failures.get(0);
    assertThat(encFailure.getPrimitive()).isEqualTo("aead");
    assertThat(encFailure.getApi()).isEqualTo("encrypt");
    assertThat(encFailure.getKeysetInfo().getPrimary().getId()).isEqualTo(42);
    assertThat(encFailure.getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(1);
    assertThat(decFailure.getPrimitive()).isEqualTo("aead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimary().getId()).isEqualTo(42);
    assertThat(decFailure.getAnnotations()).isEqualTo(annotations);
  }
}
