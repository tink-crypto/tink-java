// Copyright 2023 Google LLC
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
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.DeterministicAeadConfig2026;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacConfig2026;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.KeysetInfo.KeyInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKeysetSerializationTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
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
  public void parseKeysetWithoutSecret_works() throws Exception {
    KeysetHandle keysetHandle = generatePublicKeyset();
    byte[] serializedKeyset = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle);

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseKeysetWithoutSecret(
            BinaryKeysetReader.withBytes(serializedKeyset));

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeysetWithoutSecret_throwsForKeysetWithPrivateKeys() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.parseKeysetWithoutSecret(
                BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void parseKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset), InsecureSecretKeyAccess.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeyset_throwsNullPointerExceptionWithNull() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () ->
            LegacyKeysetSerialization.parseKeyset(
                BinaryKeysetReader.withBytes(serializedKeyset), null));
  }

  @Test
  public void parseEncryptedKeyset_works() throws Exception {
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, aead, associatedData);

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseEncryptedKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset), aead, associatedData);

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseEncryptedKeyset_wrongAssociatedData_throws() throws Exception {
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, aead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.parseEncryptedKeyset(
                BinaryKeysetReader.withBytes(serializedKeyset), aead, new byte[] {4, 5, 6}));
  }

  @Test
  public void serializeKeysetWithoutSecret_works() throws Exception {
    KeysetHandle keysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeKeysetWithoutSecret(keysetHandle, writer);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeysetWithoutSecret_throwsForKeysetWithPrivateKeys() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKeysetSerialization.serializeKeysetWithoutSecret(keysetHandle, writer));
  }

  @Test
  public void serializeKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeKeyset(keysetHandle, writer, InsecureSecretKeyAccess.get());
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeyset_throwsWithoutSecretKeyAccess() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    assertThrows(
        NullPointerException.class,
        () -> LegacyKeysetSerialization.serializeKeyset(keysetHandle, writer, null));
  }

  @Test
  public void serializeEncryptedKeyset_works() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeEncryptedKeyset(keysetHandle, writer, aead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseEncryptedKeyset(serializedKeyset, aead, associatedData);
    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeEncryptedKeyset_throwsWithWrongAssociatedData() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();
    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeEncryptedKeyset(keysetHandle, writer, aead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, aead, new byte[] {4, 5, 6}));
  }

  @Test
  public void getKeysetInfo_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withFixedId(101))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG_RAW")
                    .withFixedId(301)
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                    .withFixedId(201)
                    .setStatus(KeyStatus.DESTROYED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG_RAW")
                    .withFixedId(-101)
                    .setStatus(KeyStatus.DISABLED))
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(-201))
            .build();

    assertThat(LegacyKeysetSerialization.getKeysetInfo(handle))
        .isEqualTo(
            KeysetInfo.newBuilder()
                .setPrimaryKeyId(301)
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .setKeyId(101)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .setKeyId(301)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.DESTROYED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .setKeyId(201)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.HmacKey")
                        .setStatus(KeyStatusType.DISABLED)
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .setKeyId(-101)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesCmacKey")
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .setKeyId(-201)
                        .build())
                .build());
  }

  @Test
  public void getKeysetInfo_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesSivKey tinkKey =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(101)
            .build();
    AesSivKey crunchyKey =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.CRUNCHY)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(301)
            .build();
    AesSivKey rawKey =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(null)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(tinkKey).withFixedId(101).setStatus(KeyStatus.DISABLED))
            .addEntry(KeysetHandle.importKey(crunchyKey).withFixedId(301).makePrimary())
            .addEntry(
                KeysetHandle.importKey(rawKey).withFixedId(201).setStatus(KeyStatus.DESTROYED))
            .build();

    KeysetInfo keysetInfo =
        LegacyKeysetSerialization.getKeysetInfo(handle, DeterministicAeadConfig2026.get());

    assertThat(keysetInfo)
        .isEqualTo(
            KeysetInfo.newBuilder()
                .setPrimaryKeyId(301)
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesSivKey")
                        .setStatus(KeyStatusType.DISABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .setKeyId(101)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesSivKey")
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.CRUNCHY)
                        .setKeyId(301)
                        .build())
                .addKeyInfo(
                    KeyInfo.newBuilder()
                        .setTypeUrl("type.googleapis.com/google.crypto.tink.AesSivKey")
                        .setStatus(KeyStatusType.DESTROYED)
                        .setOutputPrefixType(OutputPrefixType.RAW)
                        .setKeyId(201)
                        .build())
                .build());

    // We want to ensure that the prod code not mistakenly uses the RegistryConfiguration. So we
    // double check that this would fail.
    Configuration configuration = RegistryConfiguration.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKeysetSerialization.getKeysetInfo(handle, configuration));
  }

  @Test
  public void getKeysetInfo_wrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    AesSivKey key =
        AesSivKey.builder()
            .setParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(64)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(64))
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(101).makePrimary())
            .build();

    Configuration nonDeterministicAeadConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKeysetSerialization.getKeysetInfo(handle, nonDeterministicAeadConfiguration));
  }

  @Test
  public void parseKeysetWithoutSecret_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generatePublicKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, SignatureConfig2026.get());

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseKeysetWithoutSecret(
            BinaryKeysetReader.withBytes(serializedKeyset), SignatureConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeysetWithoutSecret_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generatePublicKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle, SignatureConfig2026.get());

    KeysetReader reader = BinaryKeysetReader.withBytes(serializedKeyset);
    Configuration configuration = MacConfig2026.get();
    // MacConfig2026 does not support ECDSA keys.
    assertThrows(
        GeneralSecurityException.class,
        () -> LegacyKeysetSerialization.parseKeysetWithoutSecret(reader, configuration));
  }

  @Test
  public void serializeKeysetWithoutSecret_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeKeysetWithoutSecret(
        keysetHandle, writer, SignatureConfig2026.get());
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, SignatureConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeysetWithoutSecret_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Configuration configuration = MacConfig2026.get();
    // MacConfig2026 does not support ECDSA keys.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.serializeKeysetWithoutSecret(
                keysetHandle, writer, configuration));
  }

  @Test
  public void parseKeysetWithoutSecret_withConfiguration_fromTestVector_success() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    // This contains public keys (ECDSA).
    byte[] serializedKeyset =
        Hex.decode(
            "0896ffd7e60b1296010a89010a35747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63"
                + "727970746f2e74696e6b2e45636473615075626c69634b6579124e12060803100218011a2100090f"
                + "1f3c958f333ce7615cbe0ccfee9bdaa89596e6954a16a2ac1558b12bd98e2221006cb19e2cf35e68"
                + "e528a336e2ba7816aca3b3729e9ce0a529143e0c0d03c0d7991803100218a4d5cabe042003129601"
                + "0a89010a35747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
                + "696e6b2e45636473615075626c69634b6579124e12060803100218021a2100594fb5489202ed790f"
                + "18cc3f79d77b5271a5225479166827e0d28b6aa2741c52222100ba1d0fbbe9aaef905287b7bb72d8"
                + "ba33ea7a220cc335049d8a9cae02471df114180310011896ffd7e60b200112db010ace010a357479"
                + "70652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74696e6b2e456364"
                + "73615075626c69634b657912920112060804100418021a4300001d78d36f4e3fcd64536489e204e6"
                + "78e0452eada95bdc4e3e6e9af9c7639025fc2d1c2a8c290793e4dcc9d526ed1b5e19a6fd5787c0ef"
                + "cd1e3736d6459212a233cd22430000825ef8e20dd2f819541a10d40774cc81fb8e63c872285d7ba2"
                + "dda6c8d99d00e4a155a1060d191fd5fc2241142dec8c5b5371db1a2a630432ce100f4f6a665d72a7"
                + "1803100318eeb58fd1082001");

    KeysetHandle handle =
        LegacyKeysetSerialization.parseKeysetWithoutSecret(
            BinaryKeysetReader.withBytes(serializedKeyset), SignatureConfig2026.get());

    assertThat(handle.size()).isEqualTo(3);

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

    assertThat(handle.equalsKeyset(expectedHandle)).isTrue();
  }

  @Test
  public void parseKeyset_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            keysetHandle, InsecureSecretKeyAccess.get(), MacConfig2026.get());

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset),
            InsecureSecretKeyAccess.get(),
            MacConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseKeyset_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            keysetHandle, InsecureSecretKeyAccess.get(), MacConfig2026.get());

    KeysetReader reader = BinaryKeysetReader.withBytes(serializedKeyset);
    Configuration configuration = SignatureConfig2026.get();
    // SignatureConfig2026 does not support HMAC/CMAC keys.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.parseKeyset(
                reader, InsecureSecretKeyAccess.get(), configuration));
  }

  @Test
  public void serializeKeyset_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeKeyset(
        keysetHandle, writer, InsecureSecretKeyAccess.get(), MacConfig2026.get());
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeyset, InsecureSecretKeyAccess.get(), MacConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeKeyset_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Configuration configuration = SignatureConfig2026.get();
    // SignatureConfig2026 does not support HMAC/CMAC keys.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.serializeKeyset(
                keysetHandle, writer, InsecureSecretKeyAccess.get(), configuration));
  }

  @Test
  public void parseKeyset_withConfiguration_fromTestVector_success() throws Exception {
    // This contains one HMAC key.
    byte[] serializedKeyset =
        Hex.decode(
            "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63"
                + "727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f5d01759ac1302f7d"
                + "883f2f4a40025532ee1b11f9e587120410100803180110011895e59bcc062001");

    // Parse with MacConfig2026 which supports HMAC keys.
    KeysetHandle handle =
        LegacyKeysetSerialization.parseKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset),
            InsecureSecretKeyAccess.get(),
            MacConfig2026.get());
    Mac mac = handle.getPrimitive(MacConfig2026.get(), Mac.class);
    mac.verifyMac(
        Hex.decode("016986f2956092d259136923c6f4323557714ec499"),
        "data".getBytes(StandardCharsets.UTF_8));

    // Parse with DeterministicAeadConfig2026 which does not support HMAC keys.
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.parseKeyset(
                BinaryKeysetReader.withBytes(serializedKeyset),
                InsecureSecretKeyAccess.get(),
                configuration));
  }

  @Test
  public void parseEncryptedKeyset_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, aead, associatedData, MacConfig2026.get());

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseEncryptedKeyset(
            BinaryKeysetReader.withBytes(serializedKeyset),
            aead,
            associatedData,
            MacConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeysetHandle));
  }

  @Test
  public void parseEncryptedKeyset_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, aead, associatedData, MacConfig2026.get());

    KeysetReader reader = BinaryKeysetReader.withBytes(serializedKeyset);
    Configuration configuration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.parseEncryptedKeyset(
                reader, aead, associatedData, configuration));
  }

  @Test
  public void serializeEncryptedKeyset_withConfiguration_works() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    LegacyKeysetSerialization.serializeEncryptedKeyset(
        keysetHandle, writer, aead, associatedData, MacConfig2026.get());
    byte[] serializedKeyset = outputStream.toByteArray();
    KeysetHandle parsedKeyset =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, aead, associatedData, MacConfig2026.get());

    assertTrue(keysetHandle.equalsKeyset(parsedKeyset));
  }

  @Test
  public void serializeEncryptedKeyset_withWrongConfiguration_throws() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

    Aead aead = generateAead();
    byte[] associatedData = new byte[] {1, 2, 3};

    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Configuration configuration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            LegacyKeysetSerialization.serializeEncryptedKeyset(
                keysetHandle, writer, aead, associatedData, configuration));
  }

  @Test
  public void parseEncryptedKeysetFromTestVector() throws Exception {
    // This is the same test vector as in KeysetHandleTest.
    // An AEAD key, with which we encrypted the mac keyset below.
    final byte[] serializedKeysetEncryptionKeyset =
        Hex.decode(
            "08cd9bdff30312540a480a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970"
                + "746f2e74696e6b2e41657347636d4b657912121a1082bbe6de4bf9a7655305615af46e594c180110"
                + "0118cd9bdff3032001");
    KeysetHandle keysetEncryptionHandle =
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeysetEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead =
        keysetEncryptionHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    // A keyset that contains one HMAC key, encrypted with the above, using associatedData
    final byte[] encryptedSerializedKeyset =
        Hex.decode(
            "129101013e77cdcd28f57ffb418afa7f25d48a74efe720246e9aa538f33a702888bb7c48bce0e5a016a0c8"
                + "e9085066d67c7c7fb40dceb176a3a10c7f7ab30c564dd8e2d918a2fc2d2e9a0245c537ff6d1fd756"
                + "ff9d6de5cf4eb7f229de215e6e892f32fd703d0c9c3d2168813ad5bbc6ce108fcbfed0d9e3b14faa"
                + "e3e3789a891346d983b1ecca082f0546163351339aa142f574");
    final byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeysetHandle parsedKeysetHandle =
        LegacyKeysetSerialization.parseEncryptedKeyset(
            BinaryKeysetReader.withBytes(encryptedSerializedKeyset),
            keysetEncryptionAead,
            associatedData,
            MacConfig2026.get());

    Mac mac = parsedKeysetHandle.getPrimitive(MacConfig2026.get(), Mac.class);
    final byte[] message = "data".getBytes(UTF_8);
    final byte[] tag = Hex.decode("018f2d72de5055e622591fcf0fb85a7b4158e96f68");
    mac.verifyMac(tag, message);
  }
}
