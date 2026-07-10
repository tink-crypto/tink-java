// Copyright 2022 Google LLC
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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.daead.DeterministicAeadConfig2026;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacConfig2026;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkJsonProtoKeysetFormatTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
    DeterministicAeadConfig.register();
  }

  private void assertKeysetHandleAreEqual(KeysetHandle keysetHandle1, KeysetHandle keysetHandle2)
      throws Exception {
    assertThat(keysetHandle2.equalsKeyset(keysetHandle1)).isTrue();
  }

  private KeysetHandle generateKeyset() throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                .withRandomId()
                .makePrimary())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG_RAW")
                .withRandomId())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                .withRandomId()
                .setStatus(KeyStatus.DESTROYED))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG_RAW")
                .withRandomId()
                .setStatus(KeyStatus.DISABLED))
        .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
        .build();
  }

  private KeysetHandle generatePublicKeyset() throws GeneralSecurityException {
    return KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P256_RAW")
                .withRandomId()
                .setStatus(KeyStatus.DISABLED))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P256").withRandomId().makePrimary())
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("ECDSA_P521")
                .withRandomId()
                .setStatus(KeyStatus.DESTROYED))
        .build()
        .getPublicKeysetHandle();
  }

  private Aead generateAead() throws GeneralSecurityException {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_CTR_HMAC_SHA256")
                    .withRandomId()
                    .makePrimary())
            .build();
    return handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
  }

  @Test
  public void serializeAndParse_successWithSameKeyset() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, null));
  }

  @Test
  public void parseKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(generateKeyset(), InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, null));
  }

  @Test
  public void serializeAndParse_withConfiguration_success() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            keysetHandle, MacConfig2026.get(), InsecureSecretKeyAccess.get());
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            serializedKeyset, MacConfig2026.get(), InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);

    Configuration signatureConfiguration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeKeyset(
                keysetHandle, signatureConfiguration, InsecureSecretKeyAccess.get()));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeyset(
                serializedKeyset, signatureConfiguration, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeKeyset_withConfiguration_withoutInsecureSecretKeyAccess_fails()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    Configuration configuration = MacConfig2026.get();
    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, configuration, null));
  }

  @Test
  public void parseKeyset_withConfiguration_withoutInsecureSecretKeyAccess_fails()
      throws Exception {
    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            generateKeyset(), MacConfig2026.get(), InsecureSecretKeyAccess.get());

    Configuration configuration = MacConfig2026.get();
    assertThrows(
        NullPointerException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, configuration, null));
  }

  @Test
  public void parseKeyset_withConfiguration_fromTestVector_success() throws Exception {
    // The same key as in JsonKeysetReaderTest.
    String serializedKeyset =
        "{"
            + "\"primaryKeyId\": 547623039,"
            + "\"key\": [{"
            + "\"keyData\": {"
            + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
            + "\"keyMaterialType\": \"SYMMETRIC\","
            + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
            + "},"
            + "\"outputPrefixType\": \"TINK\","
            + "\"keyId\": 547623039,"
            + "\"status\": \"ENABLED\""
            + "}]}";
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            serializedKeyset, MacConfig2026.get(), InsecureSecretKeyAccess.get());
    Mac mac = handle.getPrimitive(MacConfig2026.get(), Mac.class);
    mac.verifyMac(Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7"), "data".getBytes(UTF_8));

    Configuration configuration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeyset(
                serializedKeyset, configuration, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parseInvalidSerializedKeyset_fails() throws Exception {
    String invalidSerializedKeyset = "invalid";
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeyset(
                invalidSerializedKeyset, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeEncryptedAndParseEncrypted_successWithSameKeyset() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncryptedKeysetWithInvalidKey_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    Aead invalidKeyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData));
  }

  @Test
  public void parseEncryptedKeysetWithInvalidAssociatedData_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, "associatedData".getBytes(UTF_8));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, "invalidAssociatedData".getBytes(UTF_8)));
  }

  @Test
  public void serializeAndParseWithoutSecret_successWithSameKeyset() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);
    KeysetHandle parsePublicKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(secretKeysetHandle));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    String serializedSecretKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            secretKeysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedSecretKeyset));
  }

  @Test
  public void parseWithoutSecretInvalidSerializedKeyset_fails() throws Exception {
    String invalidSerializedKeyset = "invalid";
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(invalidSerializedKeyset));
  }

  @Test
  public void serializeKeyset_worksWithCleartextKeysetHandleReadAndJsonKeysetReader()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parseKeysetHandle =
        CleartextKeysetHandle.read(JsonKeysetReader.withString(serializedKeyset));

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeyset_worksWithCleartextKeysetHandleWriteAndJsonKeysetWriter()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeysetWithoutSecret_worksWithKeysetHandleReadNoSecretAndJsonKeysetReader()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);

    KeysetHandle parsePublicKeysetHandle =
        KeysetHandle.readNoSecret(JsonKeysetReader.withString(serializedKeyset));

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void parseKeysetWithoutSecret_worksWithKeysetHandleWriteNoSecretAndJsonKeysetWriter()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    publicKeysetHandle.writeNoSecret(JsonKeysetWriter.withOutputStream(outputStream));
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parsePublicKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeEncrypted_worksWithKeysetHandleReadWithAssociatedDataAndJsonKeysetReader()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    KeysetHandle parseKeysetHandle =
        KeysetHandle.readWithAssociatedData(
            JsonKeysetReader.withString(serializedKeyset), keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncrypted_worksWithKeysetHandleWriteWithAssociatedDataAndJsonKeysetWriter()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    keysetHandle.writeWithAssociatedData(
        JsonKeysetWriter.withOutputStream(outputStream), keyEncryptionAead, associatedData);
    String serializedKeyset = new String(outputStream.toByteArray(), UTF_8);

    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeysetFromTestVector()
      throws Exception {
    // The same key as in JsonKeysetReaderTest.
    String serializedKeyset =
        "{"
            + "\"primaryKeyId\": 547623039,"
            + "\"key\": [{"
            + "\"keyData\": {"
            + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
            + "\"keyMaterialType\": \"SYMMETRIC\","
            + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
            + "},"
            + "\"outputPrefixType\": \"TINK\","
            + "\"keyId\": 547623039,"
            + "\"status\": \"ENABLED\""
            + "}]}";
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    Mac mac = handle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    mac.verifyMac(Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7"), "data".getBytes(UTF_8));
  }

  @Test
  public void parseEncryptedKeysetFromTestVector() throws Exception {
    // This is the same test vector as in KeysetHandleTest.
    // An AEAD key, with which we encrypted the mac keyset below.
    byte[] serializedKeysetEncryptionKeyset =
        Hex.decode(
            "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797"
                + "0746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cdd649e81e7952260689b2"
                + "e1971801100118b891f5a2042001");
    KeysetHandle keysetEncryptionHandle = TinkProtoKeysetFormat.parseKeyset(
        serializedKeysetEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead =
        keysetEncryptionHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // A keyset that contains one HMAC key, encrypted with the above, using associatedData
    String encryptedKeyset =
        "{\"encryptedKeyset\":"
            + "\"AURdSLhZcFEgMBptDyi4/D8hL3h+Iz7ICgLrdeVRH26Fi3uSeewFoFA5cV5wfNueme3/BBR60yJ4hGpQ"
            + "p+/248ZIgfuWyfmAGZ4dmYnYC1qd/IWkZZfVr3aOsx4j4kFZHkkvA+XIZUh/INbdPsMUNJy9cmu6s8osdH"
            + "zu0XzP2ltWUowbr0fLQJwy92eAvU6gv91k6Tc=\","
            + "\"keysetInfo\":{\"primaryKeyId\":547623039,\"keyInfo\":[{\"typeUrl\":"
            + "\"type.googleapis.com/google.crypto.tink.HmacKey\",\"status\":\"ENABLED\","
            + "\"keyId\":547623039,\"outputPrefixType\":\"TINK\"}]}}";
    byte[] associatedData = Hex.decode("abcdef330012");

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            encryptedKeyset, keysetEncryptionAead, associatedData);

    Mac mac = handle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    byte[] data = "data".getBytes(UTF_8);
    byte[] tag = Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7");
    mac.verifyMac(tag, data);
  }

  @Test
  public void serializeEncryptedAndParseEncrypted_withConfiguration_success() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead keyEncryptionAead = generateAead();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(101)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(101).makePrimary())
            .build();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData, DeterministicAeadConfig2026.get());
    KeysetHandle parseKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData, DeterministicAeadConfig2026.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);

    // The MacConfiguration doesn't allow to parse/serialize this keyset. Explicitly testing this
    // ensures that we don't mistakenly go to the RegistryConfiguration.
    Configuration macConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
                keysetHandle, keyEncryptionAead, associatedData, macConfiguration));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, associatedData, macConfiguration));
  }

  @Test
  public void parseEncryptedKeyset_withInvalidSerializedKeysetAndConfiguration_fails()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    String invalidSerializedKeyset = "invalid";
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                invalidSerializedKeyset, keyEncryptionAead, associatedData, configuration));
  }

  @Test
  public void parseEncryptedKeyset_withWrongAead_fails() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead keyEncryptionAead = generateAead();
    Aead invalidKeyEncryptionAead = generateAead();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(101)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(101).makePrimary())
            .build();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData, DeterministicAeadConfig2026.get());

    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData, configuration));
  }

  @Test
  public void parseEncryptedKeyset_withInvalidAssociatedDataAndConfiguration_fails()
      throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead keyEncryptionAead = generateAead();
    AesSivKey key =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(101)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(101).makePrimary())
            .build();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData, DeterministicAeadConfig2026.get());

    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset,
                keyEncryptionAead,
                "invalidAssociatedData".getBytes(UTF_8),
                configuration));
  }

  @Test
  public void parseEncryptedKeysetFromTestVector_withAeadAndDaeadKeys_success() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    // Test vectors are generated using this implementation here.
    byte[] associatedData = Hex.decode("000102030405");
    String encryptedKeyset =
        "{\"encryptedKeyset\":"
            + "\"Ab8hkWyJgNC7x2rOilETRYCq9eTiFE3FiGIHeDBFTS2pjpKb4fBZ7+LL4OGgJMPYs2UMfen2sokuHSTSoEQI"
            + "sJurEeP3zmf1QNrMvWLdEYMkmf/CCmuNt3GvjIVywqZDMAaed+fKhYP4MsVHERvBLi8ShzNSB11zmYUl57rl"
            + "eN+VeSu/aW3v5/VObzgDBMNzss8bpd6NTD69vgycEJRU/WGgDqSz8akLbKOe2hU+xuNcspU1i/d8OrXZz/Rb"
            + "Sq3gVp/L7kXuj6DoDOhbxA7t9uOjMgBfOabHiTFO2/jQHpXPJxJhpaVTBgB80itj5dwYnss2oeNGVPX7oY9M"
            + "yxiG5mxv7oyyOsn1\",\"keysetInfo\":{\"primaryKeyId\":102,\"keyInfo\":[{\"typeUrl\":"
            + "\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"status\":\"ENABLED\","
            + "\"keyId\":102,\"outputPrefixType\":\"TINK\"},{\"typeUrl\":"
            + "\"type.googleapis.com/google.crypto.tink.AesSivKey\",\"status\":\"ENABLED\","
            + "\"keyId\":103,\"outputPrefixType\":\"TINK\"}]}}";

    String expectedCleartextKeyset =
        "{\"primaryKeyId\":102,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/g"
            + "oogle.crypto.tink.AesGcmKey\",\"value\":\"GiDU/pJLzeVizJsi8FeUR5KmFryBHlE1NpsXrva"
            + "cgmdrqA==\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":"
            + "102,\"outputPrefixType\":\"TINK\"},{\"keyData\":{\"typeUrl\":\"type.googleapis.c"
            + "om/google.crypto.tink.AesSivKey\",\"value\":\"EkAMhf9mJljWPD0YnmQxC4z1kzrro66S1s"
            + "rPb5h5G1TiVV4U8N0jx7m2qTsxutS4/5b6Qp2fxk8iTeWx5UBBCeBQ\",\"keyMaterialType\":\"S"
            + "YMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":103,\"outputPrefixType\":\"TINK\"}]"
            + "}";

    String serializedEncryptionKeyset =
        "{\"primaryKeyId\":3206648172,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapi"
            + "s.com/google.crypto.tink.AesGcmKey\",\"value\":\"GhAqckOjrlqJ3DIaaERWSA1m\",\"ke"
            + "yMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":3206648172,\"out"
            + "putPrefixType\":\"TINK\"}]}";

    // Reconstruct AEAD from hardcoded key
    KeysetHandle keysetEncryptionHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            serializedEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead =
        keysetEncryptionHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // Reconstruct expected keyset from hardcoded cleartext
    KeysetHandle expectedKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            expectedCleartextKeyset, InsecureSecretKeyAccess.get());

    // Try to decrypt hardcoded
    KeysetHandle decryptedKeysetHandle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            encryptedKeyset, keysetEncryptionAead, associatedData, RegistryConfiguration.get());

    assertThat(decryptedKeysetHandle.equalsKeyset(expectedKeysetHandle)).isTrue();
  }

  @Test
  public void serializeAndParseWithoutSecret_withConfiguration_success() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
            publicKeysetHandle, SignatureConfig2026.get());
    KeysetHandle parsePublicKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(
            serializedKeyset, SignatureConfig2026.get());

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);

    // The MacConfiguration doesn't allow to parse/serialize this keyset. Explicitly testing this
    // ensures that we don't mistakenly go to the RegistryConfiguration.
    Configuration macConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
                publicKeysetHandle, macConfiguration));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, macConfiguration));
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeysAndConfiguration_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    Configuration configuration = SignatureConfig2026.get();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(
                secretKeysetHandle, configuration));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeysAndConfiguration_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    String serializedSecretKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(
            secretKeysetHandle, InsecureSecretKeyAccess.get());
    Configuration configuration = SignatureConfig2026.get();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(
                serializedSecretKeyset, configuration));
  }

  @Test
  public void parseWithoutSecret_withInvalidSerializedKeysetAndConfiguration_fails()
      throws Exception {
    String invalidSerializedKeyset = "invalid";
    Configuration configuration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(
                invalidSerializedKeyset, configuration));
  }

  @Test
  public void parseKeysetWithoutSecret_withConfiguration_fromTestVector_success() throws Exception {
    EcdsaParameters key0Params =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey key0 =
        EcdsaPublicKey.builder()
            .setParameters(key0Params)
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        "090f1f3c958f333ce7615cbe0ccfee9bdaa89596e6954a16a2ac1558b12bd98e", 16),
                    new BigInteger(
                        "6cb19e2cf35e68e528a336e2ba7816aca3b3729e9ce0a529143e0c0d03c0d799", 16)))
            .build();

    EcdsaParameters key1Params =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    EcdsaPublicKey key1 =
        EcdsaPublicKey.builder()
            .setParameters(key1Params)
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        "594fb5489202ed790f18cc3f79d77b5271a5225479166827e0d28b6aa2741c52", 16),
                    new BigInteger(
                        "00ba1d0fbbe9aaef905287b7bb72d8ba33ea7a220cc335049d8a9cae02471df114", 16)))
            .setIdRequirement(-1126826090)
            .build();

    EcdsaParameters key2Params =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    EcdsaPublicKey key2 =
        EcdsaPublicKey.builder()
            .setParameters(key2Params)
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        "1d78d36f4e3fcd64536489e204e678e0452eada95bdc4e3e6e9af9c7639025fc2d1c2a8c290793e4dcc9d526ed1b5e19a6fd5787c0efcd1e3736d6459212a233cd",
                        16),
                    new BigInteger(
                        "00825ef8e20dd2f819541a10d40774cc81fb8e63c872285d7ba2dda6c8d99d00e4a155a1060d191fd5fc2241142dec8c5b5371db1a2a630432ce100f4f6a665d72a7",
                        16)))
            .setIdRequirement(-1977361682)
            .build();

    KeysetHandle expectedHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(key0).withFixedId(1204988580).setStatus(KeyStatus.DISABLED))
            .addEntry(KeysetHandle.importKey(key1).withFixedId(-1126826090).makePrimary())
            .addEntry(
                KeysetHandle.importKey(key2)
                    .withFixedId(-1977361682)
                    .setStatus(KeyStatus.DESTROYED))
            .build();

    String jsonSerialized =
        "{\"primaryKeyId\":3168141206,\"key\":["
            + "{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
            + "\"value\":\"EgYIAxACGAEaIQAJDx88lY8zPOdhXL4Mz+6b2qiVluaVShairBVYsSvZjiIhAGyxnizzXmjl"
            + "KKM24rp4Fqyjs3KenOClKRQ+DA0DwNeZ\","
            + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},\"status\":\"DISABLED\","
            + "\"keyId\":1204988580,\"outputPrefixType\":\"RAW\"},"
            + "{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
            + "\"value\":\"EgYIAxACGAIaIQBZT7VIkgLteQ8YzD9513tScaUiVHkWaCfg0otqonQcUiIhALodD7vpqu+Q"
            + "Uoe3u3LYujPqeiIMwzUEnYqcrgJHHfEU\","
            + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},\"status\":\"ENABLED\","
            + "\"keyId\":3168141206,\"outputPrefixType\":\"TINK\"},"
            + "{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
            + "\"value\":\"EgYIBBAEGAIaQwAAHXjTb04/zWRTZIniBOZ44EUuralb3E4+bpr5x2OQJfwtHCqMKQeT5N"
            + "zJ1SbtG14Zpv1Xh8DvzR43NtZFkhKiM80iQwAAgl744g3S+BlUGhDUB3TMgfuOY8hyKF17ot2myNmdAOShV"
            + "aEGDRkf1fwiQRQt7IxbU3HbGipjBDLOEA9PamZdcqc=\","
            + "\"keyMaterialType\":\"ASYMMETRIC_PUBLIC\"},\"status\":\"DESTROYED\","
            + "\"keyId\":2317605614,\"outputPrefixType\":\"TINK\"}]}";

    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(
            jsonSerialized, SignatureConfig2026.get());

    assertThat(handle.equalsKeyset(expectedHandle)).isTrue();

    // Parse with MacConfig2026 which does not support ECDSA keys.
    Configuration configuration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(jsonSerialized, configuration));
  }
}
