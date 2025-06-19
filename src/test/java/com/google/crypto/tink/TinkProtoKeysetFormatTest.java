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
import com.google.crypto.tink.internal.testing.SetTinkFlag;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
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
}
