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
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.config.GlobalTinkFlags;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.DeterministicAeadConfig2026;
import com.google.crypto.tink.internal.testing.SetTinkFlag;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacConfig2026;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureConfig2026;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import javax.annotation.Nullable;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TinkProtoKeysetFormatTest {

  @Rule public SetTinkFlag setTinkFlag = new SetTinkFlag();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeAndParse_withConfiguration_success() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());

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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            keysetHandle, InsecureSecretKeyAccess.get(), DeterministicAeadConfig2026.get());
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeyset, InsecureSecretKeyAccess.get(), DeterministicAeadConfig2026.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);

    // The MacConfiguration doesn't allow to parse/serialize this keyset. Explicitly testing this
    // ensures that we don't mistakenly go to the RegistryConfiguration.
    Configuration macConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeyset(
                keysetHandle, InsecureSecretKeyAccess.get(), macConfiguration));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                serializedKeyset, InsecureSecretKeyAccess.get(), macConfiguration));
  }

  @Test
  public void parseKeyset_withInvalidSerializedKeysetAndConfiguration_fails() throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                invalidSerializedKeyset, InsecureSecretKeyAccess.get(), configuration));
  }

  @Test
  public void serializeKeyset_withUnserializableKeyAndConfiguration_throwsGeneralSecurityException()
      throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(new TestKey()).withFixedId(123).makePrimary())
            .build();
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeyset(
                handle, InsecureSecretKeyAccess.get(), configuration));
  }

  @Test
  public void serializeKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    assertThrows(
        NullPointerException.class,
        () -> TinkProtoKeysetFormat.serializeKeyset(keysetHandle, null));
  }

  @Test
  public void parseKeyset_withoutInsecureSecretKeyAccess_fails() throws Exception {
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(generateKeyset(), InsecureSecretKeyAccess.get());

    assertThrows(
        NullPointerException.class,
        () -> TinkProtoKeysetFormat.parseKeyset(serializedKeyset, null));
  }

  @Test
  public void parseInvalidSerializedKeyset_fails() throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                invalidSerializedKeyset, InsecureSecretKeyAccess.get()));
  }

  @Test
  public void parsingKeysetWithUnknownStatus_doesNotThrowButGetAtThrows() throws Exception {
    setTinkFlag.untilTheEndOfThisTest(GlobalTinkFlags.validateKeysetsOnParsing, false);
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(
                        KeyData.newBuilder()
                            .setValue(ByteString.copyFromUtf8("value"))
                            .setTypeUrl("unknown")
                            .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
                            .build())
                    .setStatus(KeyStatusType.UNKNOWN_STATUS)
                    .setKeyId(123)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .setPrimaryKeyId(123)
            .build();
    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    assertThrows(IllegalStateException.class, () -> handle.getAt(0));

    // re-parse the KeysetHandle, as suggested in documentation of getAt.
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.newBuilder(handle).build());
  }

  @Test
  public void parsingKeysetWithNonAsciiTypeUrl_doesNotThrowButGetAtThrows() throws Exception {
    setTinkFlag.untilTheEndOfThisTest(GlobalTinkFlags.validateKeysetsOnParsing, false);
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(
                        KeyData.newBuilder()
                            .setValue(ByteString.copyFromUtf8("value"))
                            .setTypeUrl("\t")
                            .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
                            .build())
                    .setStatus(KeyStatusType.ENABLED)
                    .setKeyId(123)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .setPrimaryKeyId(123)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get()));
  }

  @Test
  public void serializeEncryptedAndParseEncrypted_successWithSameKeyset() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle,
            keyEncryptionAead,
            associatedData,
            DeterministicAeadConfig2026.get());
    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset,
            keyEncryptionAead,
            associatedData,
            DeterministicAeadConfig2026.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);

    // The MacConfiguration doesn't allow to parse/serialize this keyset. Explicitly testing this
    // ensures that we don't mistakenly go to the RegistryConfiguration.
    Configuration macConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeEncryptedKeyset(
                keysetHandle, keyEncryptionAead, associatedData, macConfiguration));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, associatedData, macConfiguration));
  }

  @Test
  public void parseEncryptedKeyset_withInvalidSerializedKeysetAndConfiguration_fails()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                invalidSerializedKeyset, keyEncryptionAead, associatedData, configuration));
  }

  @Test
  public void parseEncryptedKeyset_withWrongAead_fails() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration configuration = DeterministicAeadConfig2026.get();

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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData, configuration);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData, configuration));
  }

  @Test
  public void parseEncryptedKeyset_withWrongAssociatedData_fails() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    Configuration configuration = DeterministicAeadConfig2026.get();

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

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData, configuration);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset,
                keyEncryptionAead,
                "invalidAssociatedData".getBytes(UTF_8),
                configuration));
  }

  @Test
  public void parseEncryptedKeysetWithInvalidKey_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    Aead invalidKeyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, invalidKeyEncryptionAead, associatedData));
  }

  @Test
  public void parseEncryptedKeysetWithInvalidAssociatedData_fails() throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, "associatedData".getBytes(UTF_8));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseEncryptedKeyset(
                serializedKeyset, keyEncryptionAead, "invalidAssociatedData".getBytes(UTF_8)));
  }

  @Test
  public void serializeAndParseWithoutSecret_successWithSameKeyset() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);
    KeysetHandle parsePublicKeysetHandle =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(secretKeysetHandle));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeys_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    byte[] serializedSecretKeyset =
        TinkProtoKeysetFormat.serializeKeyset(secretKeysetHandle, InsecureSecretKeyAccess.get());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedSecretKeyset));
  }

  @Test
  public void parseWithoutSecretInvalidSerializedKeyset_fails() throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(invalidSerializedKeyset));
  }

  @Test
  public void serializeAndParseWithoutSecret_withConfiguration_success() throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(
            publicKeysetHandle, SignatureConfig2026.get());
    KeysetHandle parsePublicKeysetHandle =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, SignatureConfig2026.get());

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);

    // The MacConfiguration doesn't allow to parse/serialize this keyset. Explicitly testing this
    // ensures that we don't mistakenly go to the RegistryConfiguration.
    Configuration macConfiguration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(
                publicKeysetHandle, macConfiguration));

    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, macConfiguration));
  }

  @Test
  public void serializeWithoutSecret_keysetWithSecretKeysAndConfiguration_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    Configuration configuration = SignatureConfig2026.get();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(secretKeysetHandle, configuration));
  }

  @Test
  public void parseWithoutSecret_keysetWithSecretKeysAndConfiguration_fails() throws Exception {
    KeysetHandle secretKeysetHandle = generateKeyset();
    byte[] serializedSecretKeyset =
        TinkProtoKeysetFormat.serializeKeyset(
            secretKeysetHandle, InsecureSecretKeyAccess.get(), MacConfig2026.get());
    Configuration configuration = SignatureConfig2026.get();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedSecretKeyset, configuration));
  }

  @Test
  public void parseWithoutSecret_withInvalidSerializedKeysetAndConfiguration_fails()
      throws Exception {
    byte[] invalidSerializedKeyset = "invalid".getBytes(UTF_8);
    Configuration configuration = SignatureConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeysetWithoutSecret(invalidSerializedKeyset, configuration));
  }

  @Test
  public void parseKeysetWithoutSecret_withConfiguration_fromTestVector_success() throws Exception {
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
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, SignatureConfig2026.get());

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

    // Parse with MacConfig2026 which does not support ECDSA keys.
    Configuration configuration = MacConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset, configuration));
  }

  @Test
  public void serializeKeyset_worksWithCleartextKeysetHandleReadAndBinaryKeysetReader()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    KeysetHandle parseKeysetHandle =
        CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(serializedKeyset));

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeyset_worksWithCleartextKeysetHandleWriteAndBinaryKeysetWriter()
      throws Exception {
    KeysetHandle keysetHandle = generateKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(keysetHandle, BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void serializeKeysetWithoutSecret_worksWithKeysetHandleReadNoSecretAndBinaryKeysetReader()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeysetHandle);

    KeysetHandle parsePublicKeysetHandle =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset));

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void parseKeysetWithoutSecret_worksWithKeysetHandleWriteNoSecretAndBinaryKeysetWriter()
      throws Exception {
    KeysetHandle publicKeysetHandle = generatePublicKeyset();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(outputStream));
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parsePublicKeysetHandle =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedKeyset);

    assertKeysetHandleAreEqual(publicKeysetHandle, parsePublicKeysetHandle);
  }

  @Test
  public void serializeEncrypted_worksWithKeysetHandleReadWithAssociatedDataAndBinaryKeysetReader()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, associatedData);

    KeysetHandle parseKeysetHandle =
        KeysetHandle.readWithAssociatedData(
            BinaryKeysetReader.withBytes(serializedKeyset), keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseEncrypted_worksWithKeysetHandleWriteWithAssociatedDataAndBinaryKeysetWriter()
      throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle keysetHandle = generateKeyset();
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    keysetHandle.writeWithAssociatedData(
        BinaryKeysetWriter.withOutputStream(outputStream), keyEncryptionAead, associatedData);
    byte[] serializedKeyset = outputStream.toByteArray();

    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            serializedKeyset, keyEncryptionAead, associatedData);

    assertKeysetHandleAreEqual(keysetHandle, parseKeysetHandle);
  }

  @Test
  public void parseKeysetFromTestVector()
      throws Exception {
    // This was generated in Python using the BinaryKeysetWriter. It contains one HMAC key.
    byte[] serializedKeyset =
        Hex.decode(
            "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63"
                + "727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f5d01759ac1302f7d"
                + "883f2f4a40025532ee1b11f9e587120410100803180110011895e59bcc062001");
    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    Mac mac = handle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    mac.verifyMac(Hex.decode("016986f2956092d259136923c6f4323557714ec499"), "data".getBytes(UTF_8));
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
        TinkProtoKeysetFormat.parseKeyset(
            serializedKeyset, InsecureSecretKeyAccess.get(), MacConfig2026.get());
    Mac mac = handle.getPrimitive(MacConfig2026.get(), Mac.class);
    mac.verifyMac(Hex.decode("016986f2956092d259136923c6f4323557714ec499"), "data".getBytes(UTF_8));

    // Parse with DeterministicAeadConfig2026 which does not support HMAC keys.
    Configuration configuration = DeterministicAeadConfig2026.get();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                serializedKeyset, InsecureSecretKeyAccess.get(), configuration));
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

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseEncryptedKeyset(
            encryptedSerializedKeyset, keysetEncryptionAead, associatedData);

    Mac mac = handle.getPrimitive(RegistryConfiguration.get(), Mac.class);
    final byte[] message = "data".getBytes(UTF_8);
    final byte[] tag = Hex.decode("018f2d72de5055e622591fcf0fb85a7b4158e96f68");
    mac.verifyMac(tag, message);
  }

  @Test
  public void serializationOverhead() throws Exception {
    int ivSize = 12;
    int keySize = 16;
    int tagSize = 16;
    AesGcmParameters aesGcm128Parameters =
        AesGcmParameters.builder()
            .setIvSizeBytes(ivSize)
            .setKeySizeBytes(keySize)
            .setTagSizeBytes(tagSize)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle keysetHandle = KeysetHandle.generateNew(aesGcm128Parameters);
    Aead keyEncryptionAead =
        KeysetHandle.generateNew(aesGcm128Parameters)
            .getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());

    byte[] rawEncryptedKeyset = keyEncryptionAead.encrypt(serializedKeyset, null);

    byte[] encryptedKeyset =
        TinkProtoKeysetFormat.serializeEncryptedKeyset(keysetHandle, keyEncryptionAead, null);
    // {@code encryptedKeyset} is a serialized protocol buffer that wraps the encrypted keyset bytes
    // as a protobuf bytes field. So, it should only be slightly larger than {@code
    // rawEncryptedKeyset}.
    assertThat(encryptedKeyset.length).isLessThan(rawEncryptedKeyset.length + 6);
  }

  private static final class TestKey extends Key {
    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException();
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      return null;
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  public void serializeKeyset_withUnserializableKey_throwsGeneralSecurityException()
      throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(new TestKey()).withFixedId(123).makePrimary())
            .build();
    SecretKeyAccess access = InsecureSecretKeyAccess.get();
    assertThrows(
        GeneralSecurityException.class, () -> TinkProtoKeysetFormat.serializeKeyset(handle, access));
  }

  @Test
  public void
      serializeEncryptedKeyset_withUnserializableKeyAndConfiguration_throwsGeneralSecurityException()
          throws Exception {
    Aead keyEncryptionAead = generateAead();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(new TestKey()).withFixedId(123).makePrimary())
            .build();
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.serializeEncryptedKeyset(
                handle,
                keyEncryptionAead,
                associatedData,
                DeterministicAeadConfig2026.get()));
  }
}
