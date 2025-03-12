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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrimitiveSet. */
@RunWith(JUnit4.class)
public class PrimitiveSetTest {

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    HmacKeyManager.register(true);
  }

  com.google.crypto.tink.Key getKeyFromProtoKey(Key key) throws GeneralSecurityException {
    @Nullable Integer idRequirement = key.getKeyId();
    if (key.getOutputPrefixType() == OutputPrefixType.RAW) {
      idRequirement = null;
    }
    return MutableSerializationRegistry.globalInstance()
        .parseKeyWithLegacyFallback(
            ProtoKeySerialization.create(
                key.getKeyData().getTypeUrl(),
                key.getKeyData().getValue(),
                key.getKeyData().getKeyMaterialType(),
                key.getOutputPrefixType(),
                idRequirement),
            InsecureSecretKeyAccess.get());
  }

  @Test
  public void primitiveSetWithOneEntry_works() throws Exception {
    byte[] keyMaterial = Hex.decode("000102030405060708090a0b0c0d0e0f");
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_GCM)
            .setKeyBytes(SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()))
            .setIdRequirement(42)
            .build();
    Keyset.Key protoKey =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(keyMaterial),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    PrimitiveSet<Aead> pset = PrimitiveSet.newBuilder(Aead.class).addPrimary(key, protoKey).build();
    assertThat(pset.getAll()).hasSize(1);
    List<PrimitiveSet.Entry<Aead>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(1);
    PrimitiveSet.Entry<Aead> entry = entries.get(0);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.getId()).isEqualTo(42);
    assertThat(entry.getKey()).isEqualTo(key);
  }

  @Test
  public void testBasicFunctionality() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(getKeyFromProtoKey(key1), key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getAll()).hasSize(3);

    List<PrimitiveSet.Entry<Mac>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(3);
    PrimitiveSet.Entry<Mac> entry = entries.get(0);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(1, entry.getId());
    assertThat(entry.isPrimary()).isFalse();
    assertEquals(Bytes.copyFrom(CryptoFormat.getOutputPrefix(key1)), entry.getOutputPrefix());
    entry = entries.get(1);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(2, entry.getId());
    assertThat(entry.isPrimary()).isTrue();
    assertEquals(Bytes.copyFrom(CryptoFormat.getOutputPrefix(key2)), entry.getOutputPrefix());

    entry = entries.get(2);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(3, entry.getId());
    assertThat(entry.isPrimary()).isFalse();
    assertEquals(Bytes.copyFrom(CryptoFormat.getOutputPrefix(key3)), entry.getOutputPrefix());

    entry = pset.getPrimary();
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(2, entry.getId());
    assertEquals(Bytes.copyFrom(CryptoFormat.getOutputPrefix(key2)), entry.getOutputPrefix());
  }

  @Test
  public void testGetKeysetHandle() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(getKeyFromProtoKey(key1), key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getKeysetHandle().size()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getPrimary().getId()).isEqualTo(2);
    assertThat(pset.getKeysetHandle().getAt(0).getId()).isEqualTo(1);
    assertThat(pset.getKeysetHandle().getAt(0).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(0).getKey().getIdRequirementOrNull()).isEqualTo(1);
    assertThat(pset.getKeysetHandle().getAt(0).isPrimary()).isFalse();
    assertThat(pset.getKeysetHandle().getAt(1).getId()).isEqualTo(2);
    assertThat(pset.getKeysetHandle().getAt(1).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(1).getKey().getIdRequirementOrNull()).isEqualTo(null);
    assertThat(pset.getKeysetHandle().getAt(1).isPrimary()).isTrue();
    assertThat(pset.getKeysetHandle().getAt(2).getId()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getAt(2).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(pset.getKeysetHandle().getAt(2).getKey().getIdRequirementOrNull()).isEqualTo(3);
    assertThat(pset.getKeysetHandle().getAt(2).isPrimary()).isFalse();
  }

  @Test
  public void testAddFullPrimitive_works() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(getKeyFromProtoKey(key1), key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getAll()).hasSize(3);
    assertThat(pset.getAllInKeysetOrder()).hasSize(3);
    PrimitiveSet.Entry<Mac> entry = pset.getPrimary();
    assertThat(entry).isNotNull();
  }

  @Test
  public void testAddFullPrimitive_keysHandledCorrectly() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(getKeyFromProtoKey(key1), key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .build();

    PrimitiveSet.Entry<Mac> entry = pset.getAllInKeysetOrder().get(0);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(1, entry.getId());

    entry = pset.getAllInKeysetOrder().get(1);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(2, entry.getId());

    entry = pset.getAllInKeysetOrder().get(2);
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(3, entry.getId());

    entry = pset.getPrimary();
    assertEquals(KeyStatus.ENABLED, entry.getStatus());
    assertEquals(2, entry.getId());
  }

  @Test
  public void testAddFullPrimitive_throwsOnDoublePrimaryAdd() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    assertThrows(
        IllegalStateException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addPrimary(getKeyFromProtoKey(key1), key1)
                .addPrimary(getKeyFromProtoKey(key2), key2)
                .build());
  }

  @Test
  public void testNoPrimary_getPrimaryReturnsNull() throws Exception {
    Key key =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class).add(getKeyFromProtoKey(key), key).build();
    assertThat(pset.getPrimary()).isNull();
  }

  @Test
  public void testEntryGetParametersToString() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();

    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class).addPrimary(getKeyFromProtoKey(key1), key1).build();
    assertThat(pset.getAllInKeysetOrder().get(0).getParameters().toString())
        .isEqualTo("(typeUrl=typeUrl1, outputPrefixType=TINK)");
  }

  @Test
  public void getKeyWithoutParser_givesLegacyProtoKey() throws Exception {
    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();
    builder.add(getKeyFromProtoKey(key1), key1);
    PrimitiveSet<Mac> pset = builder.build();
    com.google.crypto.tink.Key key = pset.getAllInKeysetOrder().get(0).getKey();

    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    LegacyProtoKey legacyProtoKey = (LegacyProtoKey) key;
    assertThat(legacyProtoKey.getSerialization(InsecureSecretKeyAccess.get()).getTypeUrl())
        .isEqualTo("typeUrl1");
  }

  @Test
  public void getKeyWithParser_works() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    builder.add(getKeyFromProtoKey(protoKey), protoKey);
    PrimitiveSet<Mac> pset = builder.build();

    com.google.crypto.tink.Key key = pset.getAllInKeysetOrder().get(0).getKey();
    assertThat(key).isInstanceOf(HmacKey.class);
    HmacKey hmacKey = (HmacKey) key;
    assertThat(hmacKey.getIdRequirementOrNull()).isEqualTo(42);
  }

  @Test
  public void addPrimitiveWithInvalidKeyThatHasAParser_throws() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    com.google.crypto.tink.proto.HmacKey invalidProtoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(999)
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(0))
            .build();
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createKeyData(
                invalidProtoHmacKey,
                "type.googleapis.com/google.crypto.tink.HmacKey",
                KeyData.KeyMaterialType.SYMMETRIC),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);

    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    assertThrows(
        GeneralSecurityException.class, () -> builder.add(getKeyFromProtoKey(protoKey), protoKey));
  }

  @Test
  public void testWithAnnotations() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("name", "value").build();
    PrimitiveSet<Mac> pset = PrimitiveSet.newBuilder(Mac.class).setAnnotations(annotations).build();

    HashMap<String, String> expected = new HashMap<>();
    expected.put("name", "value");
    assertThat(pset.getAnnotations().toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void testGetEmptyAnnotations() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newBuilder(Mac.class).build();
    assertThat(pset.getAnnotations()).isEqualTo(MonitoringAnnotations.EMPTY);
  }

  @Test
  public void testDuplicateKeys() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key4 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key5 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key6 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();

    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(null, key1)
            .addPrimary(getKeyFromProtoKey(key2), key2)
            .add(getKeyFromProtoKey(key3), key3)
            .add(getKeyFromProtoKey(key4), key4)
            .add(getKeyFromProtoKey(key5), key5)
            .add(getKeyFromProtoKey(key6), key6)
            .build();

    assertThat(pset.getAll()).hasSize(3); // 3 instead of 6 because of duplicated key ids

    List<PrimitiveSet.Entry<Mac>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(6);
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(0);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(1);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(2);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(2, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(3);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(2, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(4);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(3, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = entries.get(5);
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(3, entry.getId());
    }
    {
      PrimitiveSet.Entry<Mac> entry = pset.getPrimary();
      assertEquals(KeyStatus.ENABLED, entry.getStatus());
      assertEquals(1, entry.getId());
    }
  }

  @Test
  public void testAddFullPrimive_withUnknownPrefixType_shouldFail() throws Exception {
    Key key1 = Key.newBuilder().setKeyId(1).setStatus(KeyStatusType.ENABLED).build();

    assertThrows(
        GeneralSecurityException.class,
        () -> PrimitiveSet.newBuilder(Mac.class).add(getKeyFromProtoKey(key1), key1).build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class).addPrimary(getKeyFromProtoKey(key1), key1).build());
  }

  @Test
  public void testAddFullPrimive_withDisabledKey_shouldFail() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> PrimitiveSet.newBuilder(Mac.class).add(getKeyFromProtoKey(key1), key1).build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class).addPrimary(getKeyFromProtoKey(key1), key1).build());
  }

  @Test
  public void getAllInKeysetOrder_works() throws Exception {
    Key key0 =
        Key.newBuilder()
            .setKeyId(0xffffffff)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key1 =
        Key.newBuilder()
            .setKeyId(0xffffffdf)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(0xffffffef)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .add(getKeyFromProtoKey(key0), key0)
            .addPrimary(getKeyFromProtoKey(key1), key1)
            .add(getKeyFromProtoKey(key2), key2)
            .build();

    List<PrimitiveSet.Entry<Mac>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(3);
    assertThat(entries.get(0).getId()).isEqualTo(0xffffffff);
    assertThat(entries.get(1).getId()).isEqualTo(0xffffffdf);
    assertThat(entries.get(2).getId()).isEqualTo(0xffffffef);
  }

  @Test
  public void getPrimitiveCreator_works() throws Exception {
    byte[] empty = new byte[] {};
    XChaCha20Poly1305Key key1 = XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
    Aead key1Aead = XChaCha20Poly1305.create(key1);
    XChaCha20Poly1305Key key2 = XChaCha20Poly1305Key.create(SecretBytes.randomBytes(32));
    Aead key2Aead = XChaCha20Poly1305.create(key2);
    PrimitiveSet<Aead> pset =
        PrimitiveSet.newBuilder(Aead.class)
            .add(
                key1,
                Key.newBuilder()
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.RAW)
                    .build())
            .addPrimary(
                key2,
                Key.newBuilder()
                    .setKeyId(2)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.RAW)
                    .build())
            .addPrimitiveConstructor(key -> XChaCha20Poly1305.create((XChaCha20Poly1305Key) key))
            .build();

    List<PrimitiveSet.Entry<Aead>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(2);

    Aead key1AeadPset = pset.getPrimitiveForEntry(entries.get(0));
    Aead key2AeadPset = pset.getPrimitiveForEntry(entries.get(1));

    assertThat(key1AeadPset.decrypt(key1Aead.encrypt(empty, empty), empty)).isEmpty();
    assertThat(key2AeadPset.decrypt(key2Aead.encrypt(empty, empty), empty)).isEmpty();
  }
}
