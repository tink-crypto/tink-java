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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import com.google.common.truth.Expect;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.internal.InternalConfiguration;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter;
import com.google.crypto.tink.internal.KeysetHandleInterface;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringAnnotations;
import com.google.crypto.tink.internal.MonitoringClient;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveWrapper;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.HmacPrfKey;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeysetHandle}. */
@RunWith(JUnit4.class)
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
public class KeysetHandleTest {

  @Rule public final Expect expect = Expect.create();

  private static interface EncryptOnly {
    byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException;
  }

  private static class AeadToEncryptOnlyWrapper implements PrimitiveWrapper<Aead, EncryptOnly> {

    private static final AeadToEncryptOnlyWrapper WRAPPER = new AeadToEncryptOnlyWrapper();

    private static class EncryptOnlyWithMonitoring implements EncryptOnly {

      private final MonitoringClient.Logger logger;
      private final KeysetHandleInterface keysetHandle;
      private final PrimitiveFactory<Aead> factory;

      EncryptOnlyWithMonitoring(
          KeysetHandleInterface keysetHandle,
          MonitoringAnnotations annotations,
          PrimitiveFactory<Aead> factory) {
        this.keysetHandle = keysetHandle;
        this.factory = factory;
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        logger = client.createLogger(keysetHandle, annotations, "encrypt_only", "encrypt");
      }

      @Override
      public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
        KeysetHandleInterface.Entry primary = keysetHandle.getPrimary();
        logger.log(primary.getId(), plaintext.length);
        return factory.create(primary).encrypt(plaintext, new byte[0]);
      }
    }

    @Override
    public EncryptOnly legacyWrap(
        KeysetHandleInterface keysetHandle,
        MonitoringAnnotations annotations,
        PrimitiveFactory<Aead> factory)
        throws GeneralSecurityException {
      return new EncryptOnlyWithMonitoring(keysetHandle, annotations, factory);
    }

    @Override
    public Class<EncryptOnly> getPrimitiveClass() {
      return EncryptOnly.class;
    }

    @Override
    public Class<Aead> getInputPrimitiveClass() {
      return Aead.class;
    }

    static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }

  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;

  private static HmacKey rawKey;

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    PrfConfig.register();
    SignatureConfig.register();
    AeadToEncryptOnlyWrapper.register();

    createTestKeys();
  }

  private static void createTestKeys() {
    try {
      rawKey =
          HmacKey.builder()
              .setParameters(
                  HmacParameters.builder()
                      .setKeySizeBytes(HMAC_KEY_SIZE)
                      .setTagSizeBytes(HMAC_TAG_SIZE)
                      .setVariant(HmacParameters.Variant.NO_PREFIX)
                      .setHashType(HmacParameters.HashType.SHA256)
                      .build())
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  @Test
  public void deprecated_getKeys() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES128_EAX").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_EAX")
                    .withRandomId()
                    .makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES128_EAX").withRandomId())
            .build();
    Keyset keyset = handle.getKeyset();

    List<KeyHandle> keysetKeys = handle.getKeys();

    expect.that(keysetKeys).hasSize(3);
    Map<Integer, KeyHandle> keysetKeysMap =
        keysetKeys.stream().collect(Collectors.toMap(KeyHandle::getId, key -> key));
    for (Keyset.Key key : keyset.getKeyList()) {
      expect.that(keysetKeysMap).containsKey(key.getKeyId());
      KeyHandle keysetKey = keysetKeysMap.get(key.getKeyId());
      expect
          .that(KeyStatusTypeProtoConverter.toProto(keysetKey.getStatus()))
          .isEqualTo(key.getStatus());
      KeyData keyData =
          ((ProtoKey) keysetKey.getKey(SecretKeyAccess.insecureSecretAccess())).getProtoKey();
      expect.that(keyData).isEqualTo(key.getKeyData());
    }
  }

  @Test
  public void generateNew_tink_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");

    KeysetHandle handle = KeysetHandle.generateNew(template);

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters()).isEqualTo(template.toParameters());
  }

  @Test
  public void testKeysetHandleGenerateNew_parameters_works() throws Exception {
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setVariant(Variant.CRUNCHY)
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .build();
    KeysetHandle h = KeysetHandle.generateNew(parameters);
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters()).isEqualTo(parameters);
  }

  @Test
  public void testKeysetHandleGenerateNew_parameters_fails() throws Exception {
    Parameters p =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };

    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(p));
  }


  @Test
  public void generateNew_raw_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX_RAW");

    KeysetHandle handle = KeysetHandle.generateNew(template);

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters()).isEqualTo(template.toParameters());
  }

  @Test
  public void generateNew_withProtoKeyTemplate_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    com.google.crypto.tink.proto.KeyTemplate protoTemplate = template.getProto();

    @SuppressWarnings("deprecation") // Need to test the deprecated function
    KeysetHandle handle = KeysetHandle.generateNew(protoTemplate);

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters()).isEqualTo(template.toParameters());
  }

  @Test
  public void generateNew_generatesDifferentKeys() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    Set<String> keys = new TreeSet<>();

    int numKeys = 2;
    for (int j = 0; j < numKeys; j++) {
      KeysetHandle handle = KeysetHandle.generateNew(template);
      AesEaxKey aesEaxKey =
          AesEaxKey.parseFrom(
              handle.getKeyset().getKey(0).getKeyData().getValue(),
              ExtensionRegistryLite.getEmptyRegistry());
      keys.add(aesEaxKey.getKeyValue().toStringUtf8());
    }

    assertThat(keys).hasSize(numKeys);
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_createFromKey_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    KeyHandle keyHandle = KeyHandle.generateNew(template);
    KeyAccess token = SecretKeyAccess.insecureSecretAccess();

    KeysetHandle handle = KeysetHandle.createFromKey(keyHandle, token);

    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters()).isEqualTo(template.toParameters());
  }

  @Test
  public void toString_containsNoKeyMaterial() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);

    String keysetInfo = handle.toString();

    expect.that(keysetInfo).doesNotContain(keyValue);
    expect.that(handle.getKeyset().toString()).contains(keyValue);
  }

  @Test
  public void writeThenRead_returnsSameKeyset() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.write(writer, masterKey);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 = KeysetHandle.read(reader, masterKey);

    assertThat(handle.getKeyset()).isEqualTo(handle2.getKeyset());
  }

  @Test
  public void writeThenReadWithAssociatedData_returnsSameKeyset() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.writeWithAssociatedData(writer, masterKey, new byte[] {0x01, 0x02});
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 =
        KeysetHandle.readWithAssociatedData(reader, masterKey, new byte[] {0x01, 0x02});

    assertThat(handle.getKeyset()).isEqualTo(handle2.getKeyset());
  }

  @Test
  public void writeThenReadWithDifferentAssociatedData_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.writeWithAssociatedData(writer, masterKey, new byte[] {0x01, 0x02});
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readWithAssociatedData(reader, masterKey, new byte[] {0x01, 0x03}));
  }

  /**
   * A test vector for readWithAssociatedData.It uses AES-GCM for the wrapping key, and a
   * HMAC-SHA256 for the MAC.
   */
  @Test
  public void readWithAssociatedDataTestVector() throws Exception {
    // An AEAD key, with which we encrypt the mac key below (using the encrypted keyset api).
    final byte[] serializedWrappingKeyset =
        Hex.decode(
            "08cd9bdff30312540a480a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970"
                + "746f2e74696e6b2e41657347636d4b657912121a1082bbe6de4bf9a7655305615af46e594c180110"
                + "0118cd9bdff3032001");
    final byte[] associatedData = "associatedData".getBytes(UTF_8);
    // A Mac key, encrypted with the above, using ASSOCIATED_DATA as aad.
    final byte[] encryptedSerializedKeyset =
        Hex.decode(
            "129101013e77cdcd28f57ffb418afa7f25d48a74efe720246e9aa538f33a702888bb7c48bce0e5a016a0c8"
                + "e9085066d67c7c7fb40dceb176a3a10c7f7ab30c564dd8e2d918a2fc2d2e9a0245c537ff6d1fd756"
                + "ff9d6de5cf4eb7f229de215e6e892f32fd703d0c9c3d2168813ad5bbc6ce108fcbfed0d9e3b14faa"
                + "e3e3789a891346d983b1ecca082f0546163351339aa142f574");
    // A message whose tag we computed with the wrapped key.
    final byte[] message = "data".getBytes(UTF_8);
    final byte[] tag = Hex.decode("018f2d72de5055e622591fcf0fb85a7b4158e96f68");

    KeysetReader wrappingReader = BinaryKeysetReader.withBytes(serializedWrappingKeyset);
    Aead wrapperAead =
        CleartextKeysetHandle.read(wrappingReader)
            .getPrimitive(RegistryConfiguration.get(), Aead.class);

    KeysetReader encryptedReader = BinaryKeysetReader.withBytes(encryptedSerializedKeyset);
    Mac mac =
        KeysetHandle.readWithAssociatedData(encryptedReader, wrapperAead, associatedData)
            .getPrimitive(RegistryConfiguration.get(), Mac.class);
    mac.verifyMac(tag, message);
  }

  @Test
  public void getPublicKeysetHandle_shouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    KeyData privateKeyData = privateHandle.getKeyset().getKey(0).getKeyData();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.parseFrom(
            privateKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    expect.that(publicHandle.getKeyset().getKeyCount()).isEqualTo(1);
    expect
        .that(privateHandle.getKeyset().getPrimaryKeyId())
        .isEqualTo(publicHandle.getKeyset().getPrimaryKeyId());
    KeyData publicKeyData = publicHandle.getKeyset().getKey(0).getKeyData();
    expect.that(publicKeyData.getTypeUrl()).isEqualTo(SignatureConfig.ECDSA_PUBLIC_KEY_TYPE_URL);
    expect
        .that(publicKeyData.getKeyMaterialType())
        .isEqualTo(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    expect
        .that(publicKeyData.getValue().toByteArray())
        .isEqualTo(privateKey.getPublicKey().toByteArray());
    PublicKeySign signer =
        privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        publicHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
    byte[] message = Random.randBytes(20);
    verifier.verify(signer.sign(message), message);
  }

  /** Tests that when encryption failed an exception is thrown. */
  @Test
  public void write_withFaultyAead_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    TestUtil.DummyAead faultyAead = new TestUtil.DummyAead();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    assertThrows(GeneralSecurityException.class, () -> handle.write(writer, faultyAead));
  }

  @Test
  public void read_withNoMasterKeyInput_shouldThrow() throws Exception {
    KeysetReader reader = BinaryKeysetReader.withBytes(new byte[0]);

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.read(reader, /* masterKey= */ null));
  }

  @Test
  public void getPrimitive_shouldWork() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX"));
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);

    Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    assertThat(aead.decrypt(aead.encrypt(message, aad), aad)).isEqualTo(message);
  }

  // Tests that getPrimitive does correct wrapping and not just return the primary. For this, we
  // simply add a raw, non-primary key and encrypt directly with it.
  @Test
  public void getPrimitive_wrappingDoneCorrectly() throws Exception {
    KeyData rawKeyData = Registry.newKeyData(KeyTemplates.get("AES128_EAX"));
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(KeyTemplates.get("AES128_EAX").getProto()),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(rawKeyData, 43, KeyStatusType.ENABLED, OutputPrefixType.RAW));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    Aead aeadToEncrypt = Registry.getPrimitive(rawKeyData, Aead.class);

    Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);

    assertThat(aead.decrypt(aeadToEncrypt.encrypt(message, aad), aad)).isEqualTo(message);
  }

  @Test
  public void getPrimitive_differentPrimitive_shouldWork() throws Exception {
    // We use RAW because the EncryptOnly wrapper wraps everything RAW.
    KeysetHandle handle = KeysetHandle.generateNew(AesEaxKeyManager.rawAes128EaxTemplate());
    byte[] message = Random.randBytes(20);

    EncryptOnly encryptOnly = handle.getPrimitive(RegistryConfiguration.get(), EncryptOnly.class);

    Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    assertThat(aead.decrypt(encryptOnly.encrypt(message), new byte[0])).isEqualTo(message);
  }

  @Test
  public void noBuilderSetMonitoringAnnotations_monitoringClientGetsAnnotationsWithKeysetInfo()
      throws Exception {
    MutableMonitoringRegistry.globalInstance().clear();
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesGcmKeyData(Hex.decode("000102030405060708090a0b0c0d0e0f")),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    byte[] message = Random.randBytes(123);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handleWithAnnotations = KeysetHandle.fromKeysetAndAnnotations(keyset, annotations);
    EncryptOnly encryptOnlyWithAnnotations =
        handleWithAnnotations.getPrimitive(RegistryConfiguration.get(), EncryptOnly.class);
    Object unused = encryptOnlyWithAnnotations.encrypt(message);
    List<FakeMonitoringClient.LogEntry> entries = fakeMonitoringClient.getLogEntries();
    assertThat(entries).hasSize(1);
    assertThat(entries.get(0).getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void builderSetMonitoringAnnotations_works() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle keysetHandleWithAnnotations =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder()
                            .setVariant(Variant.TINK)
                            .setKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .build())
                    .withFixedId(42)
                    .makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    Mac mac = keysetHandleWithAnnotations.getPrimitive(RegistryConfiguration.get(), Mac.class);

    // Work triggering various code paths.
    byte[] tag = mac.computeMac(plaintext);
    mac.verifyMac(tag, plaintext);
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag, new byte[0]));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(new byte[0], plaintext));

    // With annotations set, the events get logged.
    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    System.out.println(logEntries);
    assertThat(logEntries).hasSize(2);

    FakeMonitoringClient.LogEntry tinkComputeEntry = logEntries.get(0);
    assertThat(tinkComputeEntry.getKeyId()).isEqualTo(42);
    assertThat(tinkComputeEntry.getPrimitive()).isEqualTo("mac");
    assertThat(tinkComputeEntry.getApi()).isEqualTo("compute");
    assertThat(tinkComputeEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(tinkComputeEntry.getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry rawComputeEntry = logEntries.get(1);
    assertThat(rawComputeEntry.getKeyId()).isEqualTo(42);
    assertThat(rawComputeEntry.getPrimitive()).isEqualTo("mac");
    assertThat(rawComputeEntry.getApi()).isEqualTo("verify");
    assertThat(rawComputeEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(rawComputeEntry.getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void builderNotSetMonitoringAnnotations_setsEmptyAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    KeysetHandle keysetHandleWithAnnotations =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder()
                            .setVariant(Variant.TINK)
                            .setKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .build())
                    .withRandomId()
                    .makePrimary())
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    Mac mac = keysetHandleWithAnnotations.getPrimitive(RegistryConfiguration.get(), Mac.class);

    // Work triggering various code paths.
    byte[] tag = mac.computeMac(plaintext);
    mac.verifyMac(tag, plaintext);

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  @Test
  public void deprecated_readNoSecretWithBytesInput_sameAs_parseKeysetWithoutSecret()
      throws Exception {
    // Public keyset should have the same output
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    byte[] serializedPublicKeyset = privateHandle.getPublicKeysetHandle().getKeyset().toByteArray();

    KeysetHandle readNoSecretOutput = KeysetHandle.readNoSecret(serializedPublicKeyset);
    KeysetHandle parseKeysetWithoutSecretOutput =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedPublicKeyset);
    expect
        .that(readNoSecretOutput.getKeyset())
        .isEqualTo(parseKeysetWithoutSecretOutput.getKeyset());

    // Symmetric Keyset should fail
    byte[] serializedSymmetricKeyset =
        TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK))
            .toByteArray();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(serializedSymmetricKeyset));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedSymmetricKeyset));

    // Private Keyset should fail
    byte[] serializedPrivateKeyset = privateHandle.getKeyset().toByteArray();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(serializedPrivateKeyset));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedPrivateKeyset));

    // Empty Keyset should fail
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(new byte[0]));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(new byte[0]));

    // Invalid Keyset should fail
    byte[] proto = new byte[] {0x00, 0x01, 0x02};
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(proto));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(proto));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_shouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    Keyset keyset = privateHandle.getPublicKeysetHandle().getKeyset();
    byte[] serializedKeyset = keyset.toByteArray();

    Keyset readKeyset =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)).getKeyset();

    expect.that(readKeyset).isEqualTo(keyset);
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withTypeSymmetric_shouldThrow() throws Exception {
    String keyValue = "01234567890123456";
    byte[] serializedKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)).toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withTypeAsymmetricPrivate_shouldThrow()
      throws Exception {
    byte[] serializedKeyset =
        KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256")).getKeyset().toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withEmptyKeyset_shouldThrow() throws Exception {
    byte[] emptySerializedKeyset = new byte[0];
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(emptySerializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withInvalidKeyset_shouldThrow() throws Exception {
    byte[] invalidSerializedKeyset = new byte[] {0x00, 0x01, 0x02};
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(invalidSerializedKeyset)));
  }

  @Test
  public void writeNoSecretThenReadNoSecret_returnsSameKeyset() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Keyset keyset = publicHandle.getKeyset();

    publicHandle.writeNoSecret(writer);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    Keyset keyset2 = KeysetHandle.readNoSecret(reader).getKeyset();

    assertThat(keyset).isEqualTo(keyset2);
  }

  @Test
  public void writeNoSecret_withTypeSymmetric_shouldThrow() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);

    assertThrows(GeneralSecurityException.class, () -> handle.writeNoSecret(/* writer= */ null));
  }

  @Test
  public void writeNoSecret_withTypeAsymmetricPrivate_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));

    assertThrows(GeneralSecurityException.class, () -> handle.writeNoSecret(/* writer= */ null));
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_primaryKey_shouldWork() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("AES128_EAX").withFixedId(123))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                .withFixedId(234).makePrimary())
        .build();

    KeyHandle keyHandle = handle.primaryKey();
    assertThat(keyHandle.getId()).isEqualTo(234);
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_primaryKey_primaryNotPresent_shouldThrow() throws Exception {
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(77).build());

    assertThrows(GeneralSecurityException.class, handle::primaryKey);
  }

  @Test
  public void testGetAt_singleKeyWithRegisteredProtoSerialization_works() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(handle.size()).isEqualTo(1);
    KeysetHandle.Entry entry = handle.getAt(0);
    assertThat(entry.getId()).isEqualTo(42);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.isPrimary()).isTrue();
    assertThat(entry.getKey().getClass()).isEqualTo(HmacKey.class);
  }

  @Test
  public void getAt_invalidKeyWithRegisteredProtoSerialization_throwsIllegalStateException()
      throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    com.google.crypto.tink.proto.HmacKey invalidProtoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(999)
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(0))
            .build();
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createKeyData(
                    invalidProtoHmacKey,
                    "type.googleapis.com/google.crypto.tink.HmacKey",
                    KeyData.KeyMaterialType.SYMMETRIC),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(handle.size()).isEqualTo(1);
    assertThrows(IllegalStateException.class, () -> handle.getAt(0));
  }

  @Test
  public void testGetAt_singleKeyWithoutRegisteredProtoSerialization_wrapsToLegacyProtoKey()
      throws Exception {
    HmacPrfKey key =
        HmacPrfKey.newBuilder()
            .setParams(HmacPrfParams.newBuilder().setHash(HashType.SHA256).build())
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .build();
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createKeyData(
                    key, "i.am.an.unregistered.key.type", KeyData.KeyMaterialType.SYMMETRIC),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.RAW));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(handle.size()).isEqualTo(1);
    KeysetHandle.Entry entry = handle.getAt(0);
    assertThat(entry.getId()).isEqualTo(42);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.isPrimary()).isTrue();
    assertThat(entry.getKey().getClass()).isEqualTo(LegacyProtoKey.class);
  }

  @Test
  public void testGetAt_multipleKeys_works() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.DISABLED,
            OutputPrefixType.TINK);
    Keyset.Key key2 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("abcdefghijklmnopq".getBytes(UTF_8), 32),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.CRUNCHY);
    Keyset.Key key3 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("ABCDEFGHIJKLMNOPQ".getBytes(UTF_8), 32),
            46,
            KeyStatusType.DESTROYED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1, key2, key3);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(44).build());

    assertThat(handle.size()).isEqualTo(3);
    assertThat(handle.getAt(0).getId()).isEqualTo(42);
    assertThat(handle.getAt(0).getStatus()).isEqualTo(KeyStatus.DISABLED);
    assertThat(handle.getAt(0).isPrimary()).isFalse();

    assertThat(handle.getAt(1).getId()).isEqualTo(44);
    assertThat(handle.getAt(1).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(handle.getAt(1).isPrimary()).isTrue();

    assertThat(handle.getAt(2).getId()).isEqualTo(46);
    assertThat(handle.getAt(2).getStatus()).isEqualTo(KeyStatus.DESTROYED);
    assertThat(handle.getAt(2).isPrimary()).isFalse();
  }

  @Test
  public void testPrimary_multipleKeys_works() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset.Key key2 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("abcdefghijklmnopq".getBytes(UTF_8), 32),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.CRUNCHY);
    Keyset.Key key3 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("ABCDEFGHIJKLMNOPQ".getBytes(UTF_8), 32),
            46,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1, key2, key3);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(44).build());
    KeysetHandle.Entry primary = handle.getPrimary();
    assertThat(primary.getId()).isEqualTo(44);
    assertThat(primary.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(primary.isPrimary()).isTrue();
  }

  @Test
  public void testGetPrimary_noPrimary_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(77).build());

    assertThrows(IllegalStateException.class, handle::getPrimary);
  }

  @Test
  public void testGetPrimary_disabledPrimary_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.DISABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(16).build());

    assertThrows(IllegalStateException.class, handle::getPrimary);
  }

  @Test
  public void testGetAt_indexOutOfBounds_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(key1));

    assertThrows(IndexOutOfBoundsException.class, () -> handle.getAt(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> handle.getAt(1));
  }

  @Test
  public void testGetAt_wrongStatus_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.UNKNOWN_STATUS,
            OutputPrefixType.TINK);
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(key1));

    assertThrows(IllegalStateException.class, () -> handle.getAt(0));

    // re-parse the KeysetHandle, as suggested in documentation of getAt.
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.newBuilder(handle).build());
  }

  @Test
  public void keysetWithNonAsciiTypeUrl_fromKeysetDoesNotThrowButGetAtThrows() throws Exception {
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
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThrows(IllegalStateException.class, () -> handle.getAt(0));

    // re-parse the KeysetHandle, as suggested in documentation of getAt.
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.newBuilder(handle).build());
  }

  @Immutable
  private static final class TestKey extends Key {
    private final ByteString keymaterial;

    public TestKey(ByteString keymaterial) {
      this.keymaterial = keymaterial;
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }

    public ByteString getKeyMaterial() {
      return keymaterial;
    }
  }

  private static TestKey parseTestKey(
      ProtoKeySerialization serialization,
      @Nullable com.google.crypto.tink.SecretKeyAccess access) {
    return new TestKey(serialization.getValue());
  }

  /**
   * Tests that key parsing via the serialization registry works as expected.
   *
   * <p>NOTE: This adds a parser to the MutableSerializationRegistry, which no other test uses.
   */
  @Test
  public void testKeysAreParsed() throws Exception {
    ByteString value = ByteString.copyFromUtf8("some value");
    // NOTE: This adds a parser to the MutableSerializationRegistry, which no other test uses.
    MutableSerializationRegistry.globalInstance()
        .registerKeyParser(
            KeyParser.create(
                KeysetHandleTest::parseTestKey,
                Bytes.copyFrom("testKeyTypeUrl".getBytes(UTF_8)),
                ProtoKeySerialization.class));
    Keyset keyset =
        Keyset.newBuilder()
            .setPrimaryKeyId(1)
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setKeyData(KeyData.newBuilder().setTypeUrl("testKeyTypeUrl").setValue(value)))
            .build();
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(((TestKey) handle.getPrimary().getKey()).getKeyMaterial()).isEqualTo(value);
  }

  @Test
  public void testBuilder_basic() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    assertThat(keysetHandle.size()).isEqualTo(1);
    assertThat(keysetHandle.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(16).build());
  }

  @Test
  public void keysetRotationWithBuilder_works() throws Exception {
    KeysetHandle oldKeyset =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    // Add new key.
    KeysetHandle keysetWithNewKey =
        KeysetHandle.newBuilder(oldKeyset)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW").withRandomId())
            .build();

    // Make latest key primary.
    KeysetHandle.Builder builder = KeysetHandle.newBuilder(keysetWithNewKey);
    builder.getAt(builder.size() - 1).makePrimary();
    KeysetHandle keysetWithNewPrimary = builder.build();

    assertThat(oldKeyset.size()).isEqualTo(1);

    assertThat(keysetWithNewKey.size()).isEqualTo(2);
    assertThat(keysetWithNewKey.getAt(0).isPrimary()).isTrue();
    assertThat(keysetWithNewKey.getAt(1).isPrimary()).isFalse();

    assertThat(keysetWithNewPrimary.size()).isEqualTo(2);
    assertThat(keysetWithNewPrimary.getAt(0).isPrimary()).isFalse();
    assertThat(keysetWithNewPrimary.getAt(1).isPrimary()).isTrue();
  }

  @Test
  public void testBuilder_multipleKeys() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
                            .setVariant(Variant.CRUNCHY).build())
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13)
                            .setVariant(Variant.LEGACY).build())
                    .withRandomId())
            .build();
    assertThat(keysetHandle.size()).isEqualTo(3);
    KeysetHandle.Entry entry0 = keysetHandle.getAt(0);
    assertThat(entry0.getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(16).build());
    assertThat(entry0.isPrimary()).isFalse();
    assertThat(entry0.getStatus()).isEqualTo(KeyStatus.DISABLED);

    KeysetHandle.Entry entry1 = keysetHandle.getAt(1);
    assertThat(entry1.isPrimary()).isTrue();
    assertThat(entry1.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry1.getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
                .setVariant(Variant.CRUNCHY).build());

    KeysetHandle.Entry entry2 = keysetHandle.getAt(2);
    assertThat(entry2.isPrimary()).isFalse();
    assertThat(entry2.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(keysetHandle.getAt(2).getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13)
                .setVariant(Variant.LEGACY).build());
  }

  @Test
  public void testBuilder_isPrimary_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThat(builder.getAt(0).isPrimary()).isFalse();
    builder.getAt(0).makePrimary();
    assertThat(builder.getAt(0).isPrimary()).isTrue();
  }

  @Test
  public void testBuilder_setStatus_getStatus_works() throws Exception {
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId();
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    entry.setStatus(KeyStatus.DISABLED);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.DISABLED);
    entry.setStatus(KeyStatus.DESTROYED);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.DESTROYED);
  }

  @Test
  // Tests that withRandomId avoids collisions. We use 2^16 keys to make collision likely. The test
  // is about 4 seconds like this.
  public void testBuilder_withRandomId_doesNotHaveCollisions() throws Exception {
    // Test takes longer on Android; and a simple Java test suffices.
    assumeFalse(TestUtil.isAndroid());
    int numNonPrimaryKeys = 1 << 16;
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    for (int i = 0; i < numNonPrimaryKeys; i++) {
      builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    }
    KeysetHandle handle = builder.build();
    Set<Integer> idSet = new HashSet<>();
    for (int i = 0; i < handle.size(); ++i) {
      idSet.add(handle.getAt(i).getId());
    }
    assertThat(idSet).hasSize(numNonPrimaryKeys + 1);
  }

  @Test
  public void testBuilder_randomIdAfterFixedId_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);
    assertThat(handle.getAt(0).getId()).isEqualTo(777);
  }

  @Test
  public void testBuilder_fixedIdAfterRandomId_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777));
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_deprecated_removeAt_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
            .withRandomId()
            .setStatus(KeyStatus.DISABLED));
    builder.addEntry(
        KeysetHandle.generateEntryFromParameters(
                AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build())
            .withRandomId()
            .makePrimary()
            .setStatus(KeyStatus.ENABLED));
    KeysetHandle.Builder.Entry removedEntry = builder.removeAt(0);
    assertThat(removedEntry.getStatus()).isEqualTo(KeyStatus.DISABLED);
    KeysetHandle handle = builder.build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build());
  }

  @Test
  public void testBuilder_deprecated_removeAtInvalidIndex_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThrows(IndexOutOfBoundsException.class, () -> builder.removeAt(2));
  }

  @Test
  public void testBuilder_deleteAt_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build())
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);

    KeysetHandle handle2 = KeysetHandle.newBuilder(handle).deleteAt(0).build();

    assertThat(handle2.size()).isEqualTo(1);
    assertThat(handle2.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build());
  }

  @Test
  public void testBuilder_deleteAtInvalidIndex_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);

    assertThrows(
        IndexOutOfBoundsException.class, () -> KeysetHandle.newBuilder(handle).deleteAt(2));
  }

  @Test
  public void testBuilder_size_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    assertThat(builder.size()).isEqualTo(0);
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThat(builder.size()).isEqualTo(1);
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThat(builder.size()).isEqualTo(2);
  }

  @Test
  public void testBuilder_noPrimary_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_primaryNotEnabled_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
            .withRandomId()
            .setStatus(KeyStatus.DISABLED)
            .makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_removedPrimary_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.removeAt(0);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_deletedPrimary_throws() throws Exception {
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .deleteAt(0);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_addPrimary_clearsOtherPrimary() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThat(builder.getAt(0).isPrimary()).isFalse();
  }

  @Test
  public void testBuilder_setPrimary_clearsOtherPrimary() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.getAt(1).makePrimary();
    assertThat(builder.getAt(0).isPrimary()).isFalse();
  }

  @Test
  public void testBuilder_noIdSet_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_doubleId_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withFixedId(777));
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777));
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_createFromKeysetHandle_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withRandomId());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    KeysetHandle originalKeyset = builder.build();

    builder = KeysetHandle.newBuilder(originalKeyset);
    KeysetHandle secondKeyset = builder.build();

    assertThat(secondKeyset.size()).isEqualTo(2);
    assertThat(secondKeyset.getAt(0).getKey().equalsKey(originalKeyset.getAt(0).getKey())).isTrue();
    assertThat(secondKeyset.getAt(1).getKey().equalsKey(originalKeyset.getAt(1).getKey())).isTrue();
    assertThat(secondKeyset.getAt(0).getStatus()).isEqualTo(originalKeyset.getAt(0).getStatus());
    assertThat(secondKeyset.getAt(1).getStatus()).isEqualTo(originalKeyset.getAt(1).getStatus());
    assertThat(secondKeyset.getAt(0).isPrimary()).isTrue();
  }

  @Test
  public void testBuilder_copyKeyset_works() throws Exception {
    KeysetHandle original =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .makePrimary()
                    .withFixedId(778))
            .build();
    KeysetHandle copy = KeysetHandle.newBuilder(original).build();
    assertThat(copy.size()).isEqualTo(2);
    assertThat(copy.getAt(0).getId()).isEqualTo(777);
    assertThat(copy.getAt(0).getKey().equalsKey(original.getAt(0).getKey())).isTrue();
    assertThat(copy.getAt(0).getStatus()).isEqualTo(original.getAt(0).getStatus());
    assertThat(copy.getAt(1).getId()).isEqualTo(778);
    assertThat(copy.getAt(1).getKey().equalsKey(original.getAt(1).getKey())).isTrue();
    assertThat(copy.getAt(1).getStatus()).isEqualTo(original.getAt(1).getStatus());
  }

  @Test
  public void testBuilder_copyKeyset_originalHasInvalidKey_throws() throws Exception {
    Keyset keyset =
        Keyset.newBuilder()
            .setPrimaryKeyId(1)
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setKeyData(
                        KeyData.newBuilder()
                            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                            .setValue(ByteString.EMPTY)))
            .build();
    KeysetHandle.Builder builder = KeysetHandle.newBuilder(KeysetHandle.fromKeyset(keyset));
    GeneralSecurityException thrown = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(thrown)
        .hasCauseThat()
        .hasMessageThat()
        .contains("wrong status or key parsing failed");
  }

  @Test
  public void testBuilder_copyKeyset_originalHasNoPrimary_throws() throws Exception {
    KeysetHandle original =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .makePrimary()
                    .withFixedId(778))
            .build();
    Keyset keyset = original.getKeyset();
    Keyset keysetWithoutPrimary = keyset.toBuilder().setPrimaryKeyId(3843).build();

    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder(KeysetHandle.fromKeyset(keysetWithoutPrimary));
    GeneralSecurityException thrown = assertThrows(GeneralSecurityException.class, builder::build);
    assertThat(thrown).hasMessageThat().contains("No primary was set");
  }

  @Test
  public void testBuilder_buildTwice_fails() throws Exception {
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary());

    Object unused = builder.build();
    // We disallow calling build on the same builder twice. The reason is that build assigns IDs
    // which were marked with "withRandomId()". Doing this twice results in incompatible keysets,
    // which would be confusing.
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withFixedId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(102).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(102);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withoutIdRequirement_noIdAssigned_throws() throws Exception {
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withRandomId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_noId_works() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_randomId_throws() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToCorrectId_works() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(105).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToWrongId_throws() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(106).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testAddEntry_addTwice_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withRandomId();
    builder.addEntry(entry);
    assertThrows(IllegalStateException.class, () -> builder.addEntry(entry));
  }

  @Test
  public void testSetStatusNull_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
            .makePrimary()
            .withRandomId()
            .setStatus(null));
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testStatusNotSet_getPrimitive_throws() throws Exception {
    Keyset keyset =
        Keyset.newBuilder()
            .setPrimaryKeyId(1)
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .setKeyData(KeyData.newBuilder().setTypeUrl("unregisteredTypeUrl")))
            .build();
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> handle.getPrimitive(RegistryConfiguration.get(), Aead.class));
    assertThat(e).hasMessageThat().contains("registration_errors");
    assertThat(e).hasMessageThat().contains("unregisteredTypeUrl");
  }

  @Immutable
  private static final class TestPrimitiveA {
    public TestPrimitiveA() {}
  }

  @Immutable
  private static final class TestPrimitiveB {
    public TestPrimitiveB() {}
  }

  @Immutable
  private static final class TestWrapperA
      implements PrimitiveWrapper<TestPrimitiveA, TestPrimitiveB> {

    @Override
    public TestPrimitiveB legacyWrap(
        KeysetHandleInterface keysetHandle,
        MonitoringAnnotations annotations,
        PrimitiveFactory<TestPrimitiveA> factory) {
      return new TestPrimitiveB();
    }

    @Override
    public Class<TestPrimitiveB> getPrimitiveClass() {
      return TestPrimitiveB.class;
    }

    @Override
    public Class<TestPrimitiveA> getInputPrimitiveClass() {
      return TestPrimitiveA.class;
    }
  }

  private static TestPrimitiveA getPrimitiveAHmacKey(HmacKey key) {
    return new TestPrimitiveA();
  }

  @Test
  public void getPrimitive_usesProvidedConfigurationWhenProvided() throws Exception {
    PrimitiveRegistry registry =
        PrimitiveRegistry.builder()
            .registerPrimitiveConstructor(
                PrimitiveConstructor.create(
                    KeysetHandleTest::getPrimitiveAHmacKey,
                    HmacKey.class,
                    TestPrimitiveA.class))
            .registerPrimitiveWrapper(new TestWrapperA())
            .build();
    InternalConfiguration configuration =
        InternalConfiguration.createFromPrimitiveRegistry(registry);
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setKeySizeBytes(20)
                    .setTagSizeBytes(10)
                    .setVariant(HmacParameters.Variant.NO_PREFIX)
                    .setHashType(HmacParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(SecretBytes.randomBytes(20))
            .setIdRequirement(null)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(hmacKey).withRandomId().makePrimary())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(RegistryConfiguration.get(), TestPrimitiveB.class));
    assertThat(keysetHandle.getPrimitive(configuration, TestPrimitiveB.class)).isNotNull();
  }

  @Test
  public void getPrimitive_usesRegistryWhenNoConfigurationProvided() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
            .build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    ChunkedMac registryMac =
        MutablePrimitiveRegistry.globalInstance().getPrimitive(rawKey, ChunkedMac.class);
    ChunkedMacComputation registryMacComputation = registryMac.createComputation();
    registryMacComputation.update(ByteBuffer.wrap(plaintext));
    ChunkedMac keysetHandleMac =
        keysetHandle.getPrimitive(RegistryConfiguration.get(), ChunkedMac.class);
    ChunkedMacComputation keysetHandleMacComputation = keysetHandleMac.createComputation();
    keysetHandleMacComputation.update(ByteBuffer.wrap(plaintext));

    assertThat(keysetHandleMacComputation.computeMac())
        .isEqualTo(registryMacComputation.computeMac());
  }

  @Test
  public void getLegacyPrimitive_usesRegistryWhenNoConfigurationProvided() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
            .build();
    KeyData rawKeyData =
        KeyData.newBuilder()
            .setValue(
                com.google.crypto.tink.proto.HmacKey.newBuilder()
                    .setParams(
                        HmacParams.newBuilder()
                            .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                            .setTagSize(HMAC_TAG_SIZE)
                            .build())
                    .setKeyValue(
                        ByteString.copyFrom(
                            rawKey.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())))
                    .build()
                    .toByteString())
            .setTypeUrl(keysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl())
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();

    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Mac registryMac = Registry.getPrimitive(rawKeyData, Mac.class);
    Mac keysetHandleMac = keysetHandle.getPrimitive(RegistryConfiguration.get(), Mac.class);

    assertThat(keysetHandleMac.computeMac(plaintext)).isEqualTo(registryMac.computeMac(plaintext));
  }

  @Test
  public void keysetEquality_singleKeyEquals_returnsTrue() throws Exception {
    SecretBytes bytes = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(101)
                    .makePrimary())
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(101)
                    .makePrimary())
            .build();

    assertTrue(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_singleKeyDifferentKeys_returnsFalse() throws Exception {
    SecretBytes bytes = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        XChaCha20Poly1305Key.create(
                            XChaCha20Poly1305Parameters.Variant.TINK, bytes, 101))
                    .withFixedId(101)
                    .makePrimary())
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        XChaCha20Poly1305Key.create(
                            XChaCha20Poly1305Parameters.Variant.CRUNCHY, bytes, 101))
                    .withFixedId(101)
                    .makePrimary())
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_singleKeyDifferentId_returnsFalse() throws Exception {
    SecretBytes bytes = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(102)
                    .makePrimary())
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(103)
                    .makePrimary())
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_twoKeysEquals_returnsTrue() throws Exception {
    SecretBytes bytes1 = SecretBytes.randomBytes(32);
    SecretBytes bytes2 = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();

    assertTrue(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_twoKeysDifferentPrimaries_returnsFalse() throws Exception {
    SecretBytes bytes1 = SecretBytes.randomBytes(32);
    SecretBytes bytes2 = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1)).withFixedId(101))
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2))
                    .withFixedId(102)
                    .makePrimary())
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_twoKeysDifferentOrder_returnsFalse() throws Exception {
    SecretBytes bytes1 = SecretBytes.randomBytes(32);
    SecretBytes bytes2 = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_twoKeysDifferentStatuses_returnsFalse() throws Exception {
    SecretBytes bytes1 = SecretBytes.randomBytes(32);
    SecretBytes bytes2 = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2))
                    .withFixedId(102)
                    .setStatus(KeyStatus.DISABLED))
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_twoKeysDifferentSizes_returnsFalse() throws Exception {
    SecretBytes bytes1 = SecretBytes.randomBytes(32);
    SecretBytes bytes2 = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes2)).withFixedId(102))
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes1))
                    .withFixedId(101)
                    .makePrimary())
            .build();

    assertFalse(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void keysetEquality_unparseableStatus_returnsFalse() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.UNKNOWN_STATUS,
            OutputPrefixType.TINK);
    KeysetHandle badKeyset = KeysetHandle.fromKeyset(TestUtil.createKeyset(key1));
    assertFalse(badKeyset.equalsKeyset(badKeyset));
  }

  @Test
  public void keysetEquality_noPrimary_returnsFalse() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1);
    KeysetHandle badKeyset =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(77).build());
    assertFalse(badKeyset.equalsKeyset(badKeyset));
  }

  @Test
  public void keysetEquality_monitoringAnnotationIgnored_returnsTrue() throws Exception {
    SecretBytes bytes = SecretBytes.randomBytes(32);

    KeysetHandle keysetHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(101)
                    .makePrimary())
            .setMonitoringAnnotations(MonitoringAnnotations.newBuilder().add("k1", "v1").build())
            .build();
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(XChaCha20Poly1305Key.create(bytes))
                    .withFixedId(101)
                    .makePrimary())
            .setMonitoringAnnotations(MonitoringAnnotations.newBuilder().add("k2", "v2").build())
            .build();

    assertTrue(keysetHandle1.equalsKeyset(keysetHandle2));
  }

  @Test
  public void getPrimitive_wrongType_linksToDevsite() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX);
    GeneralSecurityException ex =
        assertThrows(
            GeneralSecurityException.class,
            () -> handle.getPrimitive(RegistryConfiguration.get(), Mac.class));
    assertThat(ex)
        .hasMessageThat()
        .contains("https://developers.google.com/tink/faq/registration_errors");
  }

  // This keyset contains a JwtEcdsaPrivateKey with an OutputPrefixType LEGACY. This
  // OutputPrefixType is not valid for JwtEcdsaPrivateKey.
  private static final String KEYSET_WITH_INVALID_JWT_KEY =
      "{  \"primaryKeyId\": 1742360595,  \"key\": [    {      \"keyData\": {        \"typeUrl\":"
          + " \"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey\",        \"value\":"
          + " \"GiBgVYdAPg3Fa2FVFymGDYrI1trHMzVjhVNEMpIxG7t0HRJGIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKE"
          + "I3WpPf8izEx1rRogbjQTXrTcw/1HKiiZm2Hqv41w7Vd44M9koyY/+VsP+SAQAQ==\",       "
          + " \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\"      },      \"status\": \"ENABLED\",    "
          + "  \"keyId\": 1742360595,      \"outputPrefixType\": \"LEGACY\"    }  ]}";

  @Test
  public void getPublicKeysetHandle_keysetWithInvalidKey() throws Exception {
    // JwtSignatureConfig is not yet registered.

    // Because there is no parser for JwtEcdsaPrivateKey, the entries of privateHandle
    // contain one key of type LegacyProtoKey.
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            KEYSET_WITH_INVALID_JWT_KEY, InsecureSecretKeyAccess.get());
    Key key = privateHandle.getAt(0).getKey();
    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    // getPublicKeysetHandle fails, because it requires a registered key manager.
    assertThrows(GeneralSecurityException.class, privateHandle::getPublicKeysetHandle);

    // JwtSignatureConfig registers parsers for JwtEcdsaPrivateKey and JwtEcdsaPublicKey,
    // and a key manager for JwtEcdsaPrivateKey that can implements getPublicKeyData
    JwtSignatureConfig.register();

    // getPublicKeysetHandle now works, because the key manager is now registered.
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    // But the public key can't be parsed, so getAt fails.
    assertThrows(IllegalStateException.class, () -> publicHandle.getAt(0));

    // parseKeyset now uses the parser for JwtEcdsaPrivateKey, but parsing fails.
    KeysetHandle privateHandle2 =
        TinkJsonProtoKeysetFormat.parseKeyset(
            KEYSET_WITH_INVALID_JWT_KEY, InsecureSecretKeyAccess.get());
    assertThrows(IllegalStateException.class, () -> privateHandle2.getAt(0));
    // getPublicKeysetHandle still work, because it uses the unparsed proto key.
    KeysetHandle publicHandle2 = privateHandle2.getPublicKeysetHandle();
    // But also parsing of the public key fails.
    assertThrows(IllegalStateException.class, () -> publicHandle2.getAt(0));
    // serializeKeysetWithoutSecret works, because it uses the unparsed proto keyset.
    String publicJsonKeyset2 = TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicHandle);
    assertThat(publicJsonKeyset2).contains("JwtEcdsaPublicKey");
  }

  @Test
  public void getPublicKeysetHandle_keysetWithUnknownStatus() throws Exception {
    EcdsaPrivateKey privateKeyProto =
        TestUtil.createEcdsaPrivKey(
            TestUtil.createEcdsaPubKey(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                EcdsaSignatureEncoding.DER,
                Hex.decode("d4ce489428982ef343186eb90e6a04adf41366359a508fe7ac66b283f06641ae"),
                Hex.decode("1ff5d6f8cd044273923012b9f726d94b0c0c50f1f5d4a32f7d925b30044319fc")),
            Hex.decode("00B8BB628605AF1045C13593F805BA7D93B35587BC66257F1EA4D93537CE26E58F"));
    KeyData keyData =
        TestUtil.createKeyData(
            privateKeyProto,
            SignatureConfig.ECDSA_PRIVATE_KEY_TYPE_URL,
            KeyMaterialType.ASYMMETRIC_PRIVATE);
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                keyData,
                123,
                KeyStatusType.UNKNOWN_STATUS,
                com.google.crypto.tink.proto.OutputPrefixType.RAW));
    KeysetHandle privateHandle =
        TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    assertThrows(IllegalStateException.class, () -> privateHandle.getAt(0));
    // getPublicKeysetHandle work, because it uses the unparsed proto key.
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    // But also parsing of the public key fails.
    assertThrows(IllegalStateException.class, () -> publicHandle.getAt(0));
    // serializeKeysetWithoutSecret works, because it uses the unparsed proto keyset.
    String publicJsonKeyset = TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicHandle);
    assertThat(publicJsonKeyset).contains("EcdsaPublicKey");
  }

  @Test
  public void getPublicKeysetHandle_keysetWithoutPrimaryKey() throws Exception {
    EcdsaPrivateKey privateKeyProto =
        TestUtil.createEcdsaPrivKey(
            TestUtil.createEcdsaPubKey(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                EcdsaSignatureEncoding.DER,
                Hex.decode("d4ce489428982ef343186eb90e6a04adf41366359a508fe7ac66b283f06641ae"),
                Hex.decode("1ff5d6f8cd044273923012b9f726d94b0c0c50f1f5d4a32f7d925b30044319fc")),
            Hex.decode("00B8BB628605AF1045C13593F805BA7D93B35587BC66257F1EA4D93537CE26E58F"));
    KeyData keyData =
        TestUtil.createKeyData(
            privateKeyProto,
            SignatureConfig.ECDSA_PRIVATE_KEY_TYPE_URL,
            KeyMaterialType.ASYMMETRIC_PRIVATE);
    Keyset validKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                keyData,
                123,
                KeyStatusType.ENABLED,
                com.google.crypto.tink.proto.OutputPrefixType.RAW));
    KeysetHandle privateHandleWithoutPrimaryKey =
        TinkProtoKeysetFormat.parseKeyset(
            validKeyset.toBuilder().clearPrimaryKeyId().build().toByteArray(),
            InsecureSecretKeyAccess.get());
    assertThrows(IllegalStateException.class, privateHandleWithoutPrimaryKey::getPrimary);
    KeysetHandle publicHandle = privateHandleWithoutPrimaryKey.getPublicKeysetHandle();
    assertThrows(IllegalStateException.class, publicHandle::getPrimary);
    String publicJsonKeyset = TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(publicHandle);
    assertThat(publicJsonKeyset).contains("EcdsaPublicKey");
  }
}
